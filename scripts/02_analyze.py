"""Agreement between the two coders plus the headline tabulation.
Usage: python3 scripts/02_analyze.py [final]
  default: compare coding_claude.jsonl with coding_codex.jsonl on the overlap
  final:   tabulate data/coding_final.jsonl (after adjudication)"""
import json, sys, pathlib, csv
from collections import Counter
ROOT = pathlib.Path(__file__).resolve().parents[1]
D = ROOT / "data"
def load(p): return {o["ghsa"]: o for o in map(json.loads, open(p)) if o}
meta = {r["ghsa"]: r for r in csv.DictReader(open(D / "candidates.csv"))}
inp = {o["ghsa"]: o for o in map(json.loads, open(D / "coding_input.jsonl"))}

def is_withdrawn(g):
    s = (inp[g]["summary"] + " " + inp[g]["details"][:200]).lower()
    return "duplicate advisory" in s or s.startswith("withdrawn") or "## withdrawn" in s

def kappa(a, b):
    n = len(a); cats = set(a) | set(b)
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[c] * cb[c] for c in cats) / n / n
    return po, (po - pe) / (1 - pe) if pe < 1 else 1.0

def fresh_bucket(o):
    # collapse to the question that matters: can a clean-state test see it?
    return {"Y": "fresh-visible", "N": "needs-prior-state", "DEPENDS": "cache-dependent"}[o["fresh_state_detects"]]

if len(sys.argv) > 1 and sys.argv[1] == "final":
    F = load(D / "coding_final.jsonl")
    rel = [o for g, o in F.items() if o["relevant"] == "Y" and not is_withdrawn(g)]
    print(f"relevant (dedup) {len(rel)} of {len(F)}")
    for field in ["carrier", "fresh_state_detects", "revocation_kind", "webapp"]:
        print(field, Counter(o[field] for o in rel).most_common())
    web = [o for o in rel if o["webapp"] == "Y"]
    print("\nweb apps only:", len(web))
    print(" fresh bucket", Counter(fresh_bucket(o) for o in web).most_common())
    print(" carrier x fresh", sorted(Counter((o["carrier"], o["fresh_state_detects"]) for o in web).items()))
    yrs = Counter(meta[o["ghsa"]]["published"][:4] for o in rel)
    print("\nby year", sorted(yrs.items()))
    sys.exit()

A, B = load(D / "coding_claude.jsonl"), load(D / "coding_codex.jsonl")
common = sorted(set(A) & set(B))
print(f"overlap {len(common)} (claude {len(A)}, codex {len(B)})")
po, k = kappa([A[g]["relevant"] for g in common], [B[g]["relevant"] for g in common])
print(f"relevant: agreement {po:.3f}, kappa {k:.3f}")
both = [g for g in common if A[g]["relevant"] == B[g]["relevant"] == "Y"]
for f in ["carrier", "fresh_state_detects", "revocation_kind", "webapp"]:
    po, k = kappa([A[g][f] for g in both], [B[g][f] for g in both])
    print(f"{f:20s} (n={len(both)}): agreement {po:.3f}, kappa {k:.3f}")
dis = [g for g in common if A[g]["relevant"] != B[g]["relevant"]
       or (g in both and (A[g]["carrier"], A[g]["fresh_state_detects"]) != (B[g]["carrier"], B[g]["fresh_state_detects"]))]
with open(D / "disagreements.jsonl", "w") as f:
    for g in dis:
        f.write(json.dumps({"ghsa": g, "summary": inp[g]["summary"], "claude": A[g], "codex": B[g]}) + "\n")
print(f"{len(dis)} disagreements -> data/disagreements.jsonl")
