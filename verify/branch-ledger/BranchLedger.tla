---------------------------- MODULE BranchLedger ----------------------------
(***************************************************************************)
(* hallpass promises that agents may update or delete only the branches    *)
(* they created. The broker enforces it with the branch ledger: it lets a  *)
(* push create any non-default, unprotected branch, records the branch    *)
(* after GitHub confirms the create, and lets later updates and deletes    *)
(* through only for branches in the ledger.                                *)
(*                                                                         *)
(* This model covers one repo. Each agent push carries one ref command.    *)
(* HTTPS and SSH pushes share the ledger and the check, so the model does  *)
(* not tell them apart. The user pushes with their own credentials, which  *)
(* the broker never sees.                                                  *)
(*                                                                         *)
(* Code for each action is named in its comment. Paths are relative to    *)
(* the repo root.                                                          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Names,           \* branch names in the repo
    Pushes,          \* agent pushes that can be in flight at once
    MaxCommit,       \* bound on new commits, which bounds the state space
    UserReusesNames  \* TRUE: the user may create a branch under a name
                     \* an agent created before. FALSE: never.

Zero == 0  \* zeroOID in internal/policy/git.go: an absent ref

Nobody == "nobody"
Agent  == "agent"
User   == "user"

VARIABLES
    gh,          \* gh[n].tip: the commit GitHub's ref n points at, or Zero.
                 \* gh[n].by: who created this life of the branch. by is
                 \* bookkeeping for the property; the broker can't see it.
    ledger,      \* Ledger.set in memory (internal/proxy/ledger.go)
    ledgerFile,  \* names written to branches.jsonl in the state dir
    push,        \* push[p]: one agent push and where the broker is in it
    nextCommit,  \* the next fresh commit
    agentMade,   \* bookkeeping: names whose create by an agent GitHub applied
    clobbered    \* bookkeeping: names where GitHub applied an agent's update
                 \* or delete to a branch the user created

vars == <<gh, ledger, ledgerFile, push, nextCommit, agentMade, clobbered>>

Commits == Zero..MaxCommit

(* pc values for a push:
   "idle"      no push in flight
   "received"  the broker has read the command section (policy.ReadPush)
   "forwarded" CheckPush allowed it and the broker sent it to GitHub
   "answered"  GitHub answered; ok says whether it applied the command
   "writing"   Ledger.Add put the name in memory and is writing the file
   "orphaned"  the broker restarted after forwarding; GitHub may still
               apply the push, but no broker is left to read the answer *)
PCs == {"idle", "received", "forwarded", "answered", "writing", "orphaned"}

IdlePush == [pc |-> "idle", name |-> CHOOSE n \in Names : TRUE,
             old |-> Zero, new |-> Zero, ok |-> FALSE]

IsCreate(c) == c.old = Zero   \* RefUpdate.Create
IsDelete(c) == c.new = Zero   \* RefUpdate.Delete

TypeOK ==
    /\ gh \in [Names -> [tip : Commits, by : {Nobody, Agent, User}]]
    /\ ledger \subseteq Names
    /\ ledgerFile \subseteq Names
    /\ push \in [Pushes -> [pc : PCs, name : Names, old : Commits,
                            new : Commits, ok : BOOLEAN]]
    /\ nextCommit \in 1..(MaxCommit + 1)
    /\ agentMade \subseteq Names
    /\ clobbered \subseteq Names

Init ==
    /\ gh = [n \in Names |-> [tip |-> Zero, by |-> Nobody]]
    /\ ledger = {}
    /\ ledgerFile = {}
    /\ push = [p \in Pushes |-> IdlePush]
    /\ nextCommit = 1
    /\ agentMade = {}
    /\ clobbered = {}

-----------------------------------------------------------------------------
(* Agent pushes, through the broker *)

(* git sends a ref command. old is what git read from GitHub's ref list,
   or Zero to create. The command can be stale by the time GitHub sees it,
   and an agent can send any old it likes; GitHub's compare-and-swap below
   makes a wrong old fail. new is a fresh commit, or Zero to delete.
   Old and new both Zero is refused as malformed before the ledger is
   consulted (checkUpdate), so the model never sends it.
   Code: policy.ReadPush in internal/policy/git.go, called from
   serveGit in internal/proxy/git.go and relayPush in
   internal/sshgate/gate.go. *)
AgentSendsPush(p) ==
    /\ push[p].pc = "idle"
    /\ \E n \in Names : \E old \in {Zero, gh[n].tip}, del \in BOOLEAN :
        /\ ~(old = Zero /\ del)
        /\ del \/ nextCommit <= MaxCommit
        /\ push' = [push EXCEPT ![p] =
                [pc |-> "received", name |-> n, old |-> old,
                 new |-> IF del THEN Zero ELSE nextCommit, ok |-> FALSE]]
        /\ nextCommit' = IF del THEN nextCommit ELSE nextCommit + 1
    /\ UNCHANGED <<gh, ledger, ledgerFile, agentMade, clobbered>>

(* The broker checks the command. A create passes. An update or delete
   passes only if Ledger.Has(repo, branch). The default-branch and
   protected-pattern rules don't depend on the ledger and are out of scope.
   Code: policy.CheckPush and checkUpdate in internal/policy/git.go,
   with Ours wired to s.Ledger.Has in internal/proxy/git.go and
   internal/sshgate/gate.go. Each Has call takes the ledger's mutex, so
   the read is one step. *)
BrokerChecksPush(p) ==
    /\ push[p].pc = "received"
    /\ LET c == push[p] IN
        IF IsCreate(c) \/ c.name \in ledger
        THEN push' = [push EXCEPT ![p].pc = "forwarded"]
        ELSE push' = [push EXCEPT ![p] = IdlePush]   \* policy.RefusePush
    /\ UNCHANGED <<gh, ledger, ledgerFile, nextCommit, agentMade, clobbered>>

(* GitHub runs receive-pack. It applies a command only if the ref still
   points at old, as one atomic compare-and-swap. A create whose ref
   exists fails. *)
ApplyAtGitHub(p, c) ==
    LET cur == gh[c.name]
        ok  == c.old = cur.tip
    IN
    /\ gh' = IF ~ok THEN gh
             ELSE [gh EXCEPT ![c.name] =
                     IF IsDelete(c) THEN [tip |-> Zero, by |-> Nobody]
                     ELSE [tip |-> c.new,
                           by  |-> IF IsCreate(c) THEN Agent ELSE cur.by]]
    /\ agentMade' = IF ok /\ IsCreate(c) THEN agentMade \union {c.name}
                    ELSE agentMade
    /\ clobbered' = IF ok /\ ~IsCreate(c) /\ cur.by = User
                    THEN clobbered \union {c.name} ELSE clobbered
    /\ ok

GitHubApplies(p) ==
    /\ push[p].pc \in {"forwarded", "orphaned"}
    /\ ApplyAtGitHub(p, push[p])
    /\ push' = [push EXCEPT ![p] =
           IF push[p].pc = "orphaned" THEN IdlePush
           ELSE [push[p] EXCEPT !.pc = "answered", !.ok = TRUE]]
    /\ UNCHANGED <<ledger, ledgerFile, nextCommit>>

GitHubRejects(p) ==
    /\ push[p].pc \in {"forwarded", "orphaned"}
    /\ push[p].old # gh[push[p].name].tip
    /\ push' = [push EXCEPT ![p] =
           IF push[p].pc = "orphaned" THEN IdlePush
           ELSE [push[p] EXCEPT !.pc = "answered", !.ok = FALSE]]
    /\ UNCHANGED <<gh, ledger, ledgerFile, nextCommit, agentMade, clobbered>>

(* The broker reads GitHub's report-status. For each ref reported "ok"
   that was a create, it calls Ledger.Add, which puts the name in memory
   first and returns early if it was there already.
   Code: policy.ReportStatus in internal/policy/git.go; the loop after
   flushCopy in serveGit (internal/proxy/git.go) and after the copy in
   relayPush (internal/sshgate/gate.go); Ledger.Add in
   internal/proxy/ledger.go up to os.OpenFile. *)
BrokerRecords(p) ==
    /\ push[p].pc = "answered"
    /\ LET c == push[p] IN
        IF c.ok /\ IsCreate(c) /\ c.name \notin ledger
        THEN /\ ledger' = ledger \union {c.name}
             /\ push' = [push EXCEPT ![p].pc = "writing"]
        ELSE /\ push' = [push EXCEPT ![p] = IdlePush]
             /\ UNCHANGED ledger
    /\ UNCHANGED <<gh, ledgerFile, nextCommit, agentMade, clobbered>>

(* Ledger.Add appends the entry to branches.jsonl and syncs it, or the
   write fails and the broker logs it. *)
LedgerWriteSucceeds(p) ==
    /\ push[p].pc = "writing"
    /\ ledgerFile' = ledgerFile \union {push[p].name}
    /\ push' = [push EXCEPT ![p] = IdlePush]
    /\ UNCHANGED <<gh, ledger, nextCommit, agentMade, clobbered>>

LedgerWriteFails(p) ==
    /\ push[p].pc = "writing"
    /\ push' = [push EXCEPT ![p] = IdlePush]
    /\ UNCHANGED <<gh, ledger, ledgerFile, nextCommit, agentMade, clobbered>>

(* The broker stops and starts again. OpenLedger rebuilds the memory set
   from branches.jsonl. A push already sent to GitHub may still land, but
   nobody records it.
   Code: OpenLedger in internal/proxy/ledger.go, called from
   cmd/hallpass/main.go. *)
BrokerRestarts ==
    /\ ledger' = ledgerFile
    /\ push' = [p \in Pushes |->
                  IF push[p].pc \in {"forwarded", "orphaned"}
                  THEN [push[p] EXCEPT !.pc = "orphaned"]
                  ELSE IdlePush]
    /\ UNCHANGED <<gh, ledgerFile, nextCommit, agentMade, clobbered>>

-----------------------------------------------------------------------------
(* The user, with their own credentials, around the broker *)

UserCreatesBranch(n) ==
    /\ gh[n].tip = Zero
    /\ nextCommit <= MaxCommit
    /\ UserReusesNames \/ n \notin agentMade
    /\ gh' = [gh EXCEPT ![n] = [tip |-> nextCommit, by |-> User]]
    /\ nextCommit' = nextCommit + 1
    /\ UNCHANGED <<ledger, ledgerFile, push, agentMade, clobbered>>

(* A user push to an existing branch keeps the branch's creator: an agent's
   branch with a commit from the user is still the agent's branch. *)
UserPushesBranch(n) ==
    /\ gh[n].tip # Zero
    /\ nextCommit <= MaxCommit
    /\ gh' = [gh EXCEPT ![n].tip = nextCommit]
    /\ nextCommit' = nextCommit + 1
    /\ UNCHANGED <<ledger, ledgerFile, push, agentMade, clobbered>>

UserDeletesBranch(n) ==
    /\ gh[n].tip # Zero
    /\ gh' = [gh EXCEPT ![n] = [tip |-> Zero, by |-> Nobody]]
    /\ UNCHANGED <<ledger, ledgerFile, push, nextCommit, agentMade, clobbered>>

(* Every commit is used and nothing is in flight. Without this step TLC
   would report the end of the bound as a deadlock. *)
OutOfCommits ==
    /\ nextCommit > MaxCommit
    /\ \A p \in Pushes : push[p].pc = "idle"
    /\ UNCHANGED vars

Next ==
    \/ \E p \in Pushes : AgentSendsPush(p)
    \/ \E p \in Pushes : BrokerChecksPush(p)
    \/ \E p \in Pushes : GitHubApplies(p)
    \/ \E p \in Pushes : GitHubRejects(p)
    \/ \E p \in Pushes : BrokerRecords(p)
    \/ \E p \in Pushes : LedgerWriteSucceeds(p)
    \/ \E p \in Pushes : LedgerWriteFails(p)
    \/ BrokerRestarts
    \/ \E n \in Names : UserCreatesBranch(n)
    \/ \E n \in Names : UserPushesBranch(n)
    \/ \E n \in Names : UserDeletesBranch(n)
    \/ OutOfCommits

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

(* The promise: GitHub never applies an agent's update or delete to a
   branch the user created. *)
NoClobber == clobbered = {}

(* The ledger, in memory and on disk, names only branches whose create by
   an agent GitHub applied. *)
LedgerOnlyAgentBranches == ledger \union ledgerFile \subseteq agentMade

(* Not a rule. Sanity.cfg checks this and expects it to break, which shows
   that an agent can update its own branch in the model, so the passes
   above aren't from a model that refuses everything. *)
AgentNeverUpdatesOwnBranch ==
    \A p \in Pushes :
        ~(push[p].pc = "answered" /\ push[p].ok /\ ~IsCreate(push[p]))

=============================================================================
