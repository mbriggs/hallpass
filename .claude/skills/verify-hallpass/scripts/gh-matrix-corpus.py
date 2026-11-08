"""Append a gh-matrix.sh capture to the policy corpus.

    python3 -I gh-matrix-corpus.py OUT.jsonl internal/policy/testdata/gh-VERSION-capture.jsonl

Keeps each request the broker allowed, and each it refused only because an
operation is off ("agents may not ..."), since those must still classify.
Skips refusals by design, which the escape tests cover, and requests the
corpus already has. The corpus tests then require every kept request to
classify.
"""
import json
import sys

src, corpus = sys.argv[1], sys.argv[2]
have = set()
for line in open(corpus):
    r = json.loads(line)
    have.add((r["head"].split("\r\n")[0], r.get("body", "")))

added = 0
with open(corpus, "a") as out:
    for line in open(src):
        r = json.loads(line)
        if "head" not in r:
            continue
        refusal = r.get("refusal", "")
        if refusal and "agents may not" not in refusal:
            continue
        key = (r["head"].split("\r\n")[0], r.get("body", ""))
        if key in have:
            continue
        have.add(key)
        out.write(json.dumps({"head": r["head"], "body": r.get("body", "")}) + "\n")
        added += 1
print(f"added {added} requests to {corpus}")
