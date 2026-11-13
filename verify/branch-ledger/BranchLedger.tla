---------------------------- MODULE BranchLedger ----------------------------
(***************************************************************************)
(* hallpass promises that agents may update or delete only the branches    *)
(* they created. The broker enforces it with the branch ledger, which      *)
(* holds, for each branch, the commit an agent last pushed to it. A push   *)
(* may create any non-default, unprotected branch. An update or delete     *)
(* passes only if its old commit is the ledger's commit for the branch.    *)
(* GitHub applies a ref command only if the ref still has the old commit,  *)
(* so a branch the user changed no longer matches.                         *)
(*                                                                         *)
(* This model covers one repo. Agents push over SSH through relayPush in   *)
(* internal/sshgate/gate.go, the only push path. The user changes          *)
(* branches with their own credentials, which the broker never sees, and   *)
(* runs sudo hallpass ledger add.                                          *)
(*                                                                         *)
(* Code for each action is named in its comment. Paths are relative to    *)
(* the repo root.                                                          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Names,      \* branch names in the repo, none of them the default branch
    Pushes,     \* agent pushes that can be in flight at once
    MaxCommit,  \* bound on new commits, which bounds the state space
    MaxRefs,    \* most ref commands in one push
    Restarts    \* TRUE: the broker restarts, ledger writes fail, and the
                \* user runs ledger add (which takes a restart). FALSE
                \* leaves these out, to keep a larger config small.

Zero == 0  \* zeroOID in internal/policy/git.go: an absent ref, or no entry

VARIABLES
    gh,          \* gh[n]: the commit GitHub's ref n points at, or Zero
    ledger,      \* the broker's Ledger.tips in memory: n -> tip, Zero if none
    ledgerFile,  \* what OpenLedger would read from branches.jsonl
    push,        \* push[p]: one agent push and where the broker is in it
    nextCommit,  \* the next fresh commit
    placed,      \* bookkeeping: pairs <<n, c>> where GitHub set n to c
                 \* for an agent
    handed,      \* bookkeeping: pairs <<n, c>> the user handed over with
                 \* ledger add
    harmed,      \* bookkeeping: names where GitHub applied an agent's update
                 \* or delete to a state no agent or handover produced
    public       \* bookkeeping: commits the user can name: theirs, and
                 \* agents' once GitHub has them

vars == <<gh, ledger, ledgerFile, push, nextCommit, placed, handed, harmed, public>>

Commits == Zero..MaxCommit
Used == 1..(nextCommit - 1)  \* commits that exist somewhere

(* A ref command, as in policy.RefUpdate. *)
Cmds == [name : Names, old : Commits, new : Commits]
IsCreate(c) == c.old = Zero   \* RefUpdate.Create
IsDelete(c) == c.new = Zero   \* RefUpdate.Delete

(* pc values for a push:
   "idle"      no push in flight
   "received"  the broker has read the command section (policy.ReadPush)
   "forwarded" CheckPush allowed it and the broker sent it to GitHub
   "answered"  GitHub answered; ok holds the names it applied, not yet
               recorded
   "orphaned"  the broker restarted after forwarding; GitHub may still
               apply the push, but no broker is left to read the answer *)
PCs == {"idle", "received", "forwarded", "answered", "orphaned"}

IdlePush == [pc |-> "idle", cmds |-> {}, atomic |-> FALSE, fresh |-> FALSE,
             ok |-> {}]

TypeOK ==
    /\ gh \in [Names -> Commits]
    /\ ledger \in [Names -> Commits]
    /\ ledgerFile \in [Names -> Commits]
    /\ push \in [Pushes -> [pc : PCs, cmds : SUBSET Cmds, atomic : BOOLEAN,
                            fresh : BOOLEAN,
                            ok : SUBSET Names]]
    /\ nextCommit \in 1..(MaxCommit + 1)
    /\ placed \subseteq Names \X Commits
    /\ handed \subseteq Names \X Commits
    /\ harmed \subseteq Names
    /\ public \subseteq Commits

Init ==
    /\ gh = [n \in Names |-> Zero]
    /\ ledger = [n \in Names |-> Zero]
    /\ ledgerFile = [n \in Names |-> Zero]
    /\ push = [p \in Pushes |-> IdlePush]
    /\ nextCommit = 1
    /\ placed = {}
    /\ handed = {}
    /\ harmed = {}
    /\ public = {}

-----------------------------------------------------------------------------
(* Agent pushes, through the broker *)

(* git sends one to MaxRefs ref commands, each for a different branch.
   A push that names a ref twice is refused in CheckPush, so the model
   never sends one. old is Zero to create, or what git read: GitHub's
   tip, or a stale one such as the ledger's. An agent can send any old;
   one that matches neither the ledger nor GitHub fails both checks. new
   is Zero to delete, a fresh commit (one per push, as when git pushes
   HEAD to two branches), or an agent's commit GitHub doesn't have yet,
   such as one from a push GitHub rejected. Pushing it to another branch
   makes it public. Agents pushing public commits, the user's or their
   own, are left out to keep the state space small; the user can already
   put any public commit on any branch. Old and new both Zero is refused as malformed in
   checkUpdate, so the model never sends it. atomic is git's --atomic.
   relayPush reads GitHub's ref list before it reads the commands, and
   fresh says whether every command's old commit is where that list has
   its ref. The model reads the list in this step, the latest it can be
   read; the user may change a branch after it.
   Code: readAdvertisement and policy.ReadPush, called from relayPush in
   internal/sshgate/gate.go. *)
AgentSendsPush(p) ==
    /\ push[p].pc = "idle"
    /\ \E S \in SUBSET Names, atomic \in BOOLEAN :
        /\ S # {}
        /\ Cardinality(S) <= MaxRefs
        /\ LET fresh == nextCommit IN
           \E old \in [S -> Commits], new \in [S -> Commits] :
            /\ \A n \in S : old[n] \in {Zero, gh[n], ledger[n]}
            /\ \A n \in S : new[n] \in {Zero} \union (Used \ public) \union
                                       (IF fresh <= MaxCommit THEN {fresh} ELSE {})
            /\ \A n \in S : ~(old[n] = Zero /\ new[n] = Zero)
            /\ push' = [push EXCEPT ![p] =
                    [pc |-> "received", atomic |-> atomic, ok |-> {},
                     fresh |-> \A n \in S : old[n] = gh[n],
                     cmds |-> {[name |-> n, old |-> old[n], new |-> new[n]] : n \in S}]]
            /\ nextCommit' = IF \E n \in S : new[n] = fresh
                             THEN nextCommit + 1 ELSE nextCommit
    /\ UNCHANGED <<gh, ledger, ledgerFile, placed, handed, harmed, public>>

(* The broker checks every command. A create passes. An update or delete
   passes only if its old commit is Ledger.Tip for the branch. Every
   command must also start from where the ref list had its ref (fresh):
   the broker compares them itself, and doesn't count on GitHub alone to
   apply a command only while the ref still points at old. If any
   command fails, RefusePush refuses the whole push. The default-branch
   and protected-pattern rules don't depend on the ledger and are out of
   scope; Names holds no default or protected branch.
   Code: policy.CheckPush and checkUpdate in internal/policy/git.go, with
   Tip wired to s.Ledger.Tip in relayPush, and stale in
   internal/sshgate/gate.go. *)
Allowed(c) == IsCreate(c) \/ (c.old # Zero /\ c.old = ledger[c.name])

BrokerChecksPush(p) ==
    /\ push[p].pc = "received"
    /\ IF push[p].fresh /\ \A c \in push[p].cmds : Allowed(c)
       THEN push' = [push EXCEPT ![p].pc = "forwarded"]
       ELSE push' = [push EXCEPT ![p] = IdlePush]
    /\ UNCHANGED <<gh, ledger, ledgerFile, nextCommit, placed, handed, harmed, public>>

(* GitHub runs receive-pack. It applies a command only if the ref still
   points at old (a create needs the ref absent). Without --atomic it
   applies the commands that match; with it, all or none. It answers
   "ok" for each applied ref. *)
Matches(c) == c.old = gh[c.name]

GitHubAnswers(p) ==
    /\ push[p].pc \in {"forwarded", "orphaned"}
    /\ LET cmds    == push[p].cmds
           applied == IF push[p].atomic /\ \E c \in cmds : ~Matches(c)
                      THEN {}
                      ELSE {c \in cmds : Matches(c)}
           names   == {c.name : c \in applied}
       IN
       /\ gh' = [n \in Names |->
                   IF n \in names
                   THEN (CHOOSE c \in applied : c.name = n).new
                   ELSE gh[n]]
       /\ placed' = placed \union
                    {<<c.name, c.new>> : c \in {d \in applied : ~IsDelete(d)}}
       /\ public' = public \union ({c.new : c \in applied} \ {Zero})
       /\ harmed' = harmed \union
                    {c.name : c \in {d \in applied :
                        ~IsCreate(d) /\ <<d.name, gh[d.name]>> \notin placed \union handed}}
       /\ push' = [push EXCEPT ![p] =
                     IF push[p].pc = "orphaned" THEN IdlePush
                     ELSE [push[p] EXCEPT !.pc = "answered", !.ok = names]]
    /\ UNCHANGED <<ledger, ledgerFile, nextCommit, handed>>

(* For one ref GitHub reported "ok", the broker calls Ledger.Record with
   the command's new commit, or "" for a delete. Record holds the ledger
   mutex while it sets the tip in memory and appends the line to
   branches.jsonl, so other Records can't come between; the append can
   fail, which leaves memory changed and the file as it was. Record
   writes nothing when memory already has the tip.
   Code: policy.ReportStatus in internal/policy/git.go; the loop after
   the copy in relayPush; Ledger.Record in internal/sshgate/ledger.go. *)
BrokerRecords(p) ==
    /\ push[p].pc = "answered"
    /\ IF push[p].ok = {}
       THEN /\ push' = [push EXCEPT ![p] = IdlePush]
            /\ UNCHANGED <<ledger, ledgerFile>>
       ELSE \E n \in push[p].ok :
            LET tip == (CHOOSE c \in push[p].cmds : c.name = n).new IN
            /\ ledger' = [ledger EXCEPT ![n] = tip]
            /\ IF ledger[n] = tip
               THEN UNCHANGED ledgerFile
               ELSE \/ ledgerFile' = [ledgerFile EXCEPT ![n] = tip]
                    \/ Restarts /\ UNCHANGED ledgerFile
            /\ push' = [push EXCEPT ![p].ok = @ \ {n}]
    /\ UNCHANGED <<gh, nextCommit, placed, handed, harmed, public>>

(* The broker stops and starts again. OpenLedger rebuilds memory from
   branches.jsonl, where the last line for a branch wins. A push already
   sent to GitHub may still land, but nobody records it.
   Code: OpenLedger in internal/sshgate/ledger.go, called from serve in
   cmd/hallpass/main.go. *)
BrokerRestarts ==
    /\ Restarts
    /\ ledger' = ledgerFile
    /\ push' = [p \in Pushes |->
                  IF push[p].pc \in {"forwarded", "orphaned"}
                  THEN [push[p] EXCEPT !.pc = "orphaned"]
                  ELSE IdlePush]
    /\ UNCHANGED <<gh, ledgerFile, nextCommit, placed, handed, harmed, public>>

-----------------------------------------------------------------------------
(* The user, with their own credentials and sudo *)

(* The user creates n, pushes to it, force-pushes it, or restores it, at
   a fresh commit, one of theirs, or an agent's that GitHub has. *)
UserSetsBranch(n) ==
    /\ \E c \in public \union (IF nextCommit <= MaxCommit THEN {nextCommit} ELSE {}) :
        /\ c # gh[n]
        /\ gh' = [gh EXCEPT ![n] = c]
        /\ nextCommit' = IF c = nextCommit THEN nextCommit + 1 ELSE nextCommit
        /\ public' = public \union {c}
    /\ UNCHANGED <<ledger, ledgerFile, push, placed, handed, harmed>>

UserDeletesBranch(n) ==
    /\ gh[n] # Zero
    /\ gh' = [gh EXCEPT ![n] = Zero]
    /\ UNCHANGED <<ledger, ledgerFile, push, nextCommit, placed, handed, harmed, public>>

(* sudo hallpass ledger add OWNER/REPO n c. It is its own process: it
   reads branches.jsonl with OpenLedger, appends n with tip c through
   Ledger.Record, and restarts the broker, which is BrokerRestarts here.
   Until then the running broker's memory doesn't have the line. c is any
   commit the user names; the push refusal prints the one to use.
   Code: ledger in cmd/hallpass/ledger.go, Ledger.Record, system.Restart. *)
UserAddsLedgerEntry(n) ==
    /\ Restarts
    /\ \E c \in Used :
        /\ ledgerFile' = [ledgerFile EXCEPT ![n] = c]
        /\ handed' = handed \union {<<n, c>>}
    /\ UNCHANGED <<gh, ledger, push, nextCommit, placed, harmed, public>>

(* Every commit is used and nothing is in flight. Without this step TLC
   would report the end of the bound as a deadlock. *)
OutOfCommits ==
    /\ nextCommit > MaxCommit
    /\ \A p \in Pushes : push[p].pc = "idle"
    /\ UNCHANGED vars

Next ==
    \/ \E p \in Pushes : AgentSendsPush(p)
    \/ \E p \in Pushes : BrokerChecksPush(p)
    \/ \E p \in Pushes : GitHubAnswers(p)
    \/ \E p \in Pushes : BrokerRecords(p)
    \/ BrokerRestarts
    \/ \E n \in Names : UserSetsBranch(n)
    \/ \E n \in Names : UserDeletesBranch(n)
    \/ \E n \in Names : UserAddsLedgerEntry(n)
    \/ OutOfCommits

Spec == Init /\ [][Next]_vars

(* Branch names are interchangeable, and so are pushes, so TLC checks one
   state for each renaming of them. *)
Symmetry == Permutations(Names) \union Permutations(Pushes)

-----------------------------------------------------------------------------
(* Properties *)

(* The promise: GitHub applies an agent's update or delete to a branch
   only when the branch points at a commit an agent put on that branch,
   or one the user handed over with ledger add. So the user's own work on
   a branch, whether a branch they made, a name they reused, or commits
   they added to an agent's branch, is never overwritten or deleted. *)
NoOverwrite == harmed = {}

(* Every tip in the ledger, in memory and on disk, is one an agent put on
   that branch or one the user handed over. *)
LedgerSound ==
    \A n \in Names :
        /\ ledger[n] # Zero => <<n, ledger[n]>> \in placed \union handed
        /\ ledgerFile[n] # Zero => <<n, ledgerFile[n]>> \in placed \union handed

(* Not rules. SanityOwn.cfg and SanityHanded.cfg each check one and expect
   it to break. That shows an agent can go on updating its own branch,
   and can update a branch the user handed over, so the passes above
   aren't from a model that refuses everything. *)
Updated(p, pred(_)) ==
    /\ push[p].pc = "answered"
    /\ \E c \in push[p].cmds : c.name \in push[p].ok /\ ~IsCreate(c) /\ pred(c)

AgentNeverUpdatesOwnBranch ==
    \A p \in Pushes : ~Updated(p, LAMBDA c : <<c.name, c.old>> \in placed)

AgentNeverUpdatesHandedBranch ==
    \A p \in Pushes : ~Updated(p, LAMBDA c : <<c.name, c.old>> \in handed
                                            /\ <<c.name, c.old>> \notin placed)

=============================================================================
