"""Summarize a gh-matrix.sh capture: per command, each request the broker
refused, and the command's exit and last output line.

    python3 -I gh-matrix-report.py OUT.jsonl [--all]

--all also lists the requests the broker allowed.
"""
import json
import sys


def name(rec):
    head = rec["head"].split("\r\n")[0].rsplit(" ", 1)[0]
    body = rec.get("body") or ""
    if body.startswith("{") and '"query"' in body:
        q = json.loads(body).get("query", "")
        words = q.replace("{", " { ").split()
        op = next((w for w in words if w not in ("query", "mutation", "fragment", "{")), "")
        return f"{head} {op.split('(')[0]}"
    return head


def main():
    path = sys.argv[1]
    show_all = "--all" in sys.argv
    for line in open(path):
        rec = json.loads(line)
        if "mark" in rec:
            print(f"\n{rec['mark']}")
        elif "result" in rec:
            last = rec["result"].strip().splitlines()[-1:] or [""]
            print(f"    exit {rec['exit']}: {last[0][:160]}")
        elif rec.get("refusal"):
            print(f"  REFUSED {name(rec)}\n          {rec['refusal'][:220]}")
        elif show_all:
            print(f"  ok      {name(rec)} ({rec['status']})")


main()
