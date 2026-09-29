"""Score Han's blind re-code against the adjudicated labels (and each LLM coder separately)."""
import csv, json, pathlib
from collections import Counter

R = pathlib.Path(__file__).resolve().parent
D = R.parent / "data"
FIELDS = ["relevant", "carrier", "fresh_state_detects", "revocation_kind", "webapp"]


def kappa(a, b):
    n = len(a)
    if n == 0:
        return float("nan"), float("nan")
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[c] * cb[c] for c in set(a) | set(b)) / n / n
    return po, (po - pe) / (1 - pe) if pe < 1 else 1.0


key = {k["item"]: k["ghsa"] for k in json.load(open(R / "_key_do_not_open.json"))}
human = {r["item"]: {f: (r[f].strip().upper() or None) for f in FIELDS} | {"note": r["note"]}
         for r in csv.DictReader(open(R / "answers.csv", encoding="utf-8-sig"))}
blank = [i for i, h in human.items() if not h["relevant"]]
if blank:
    print(f"{len(blank)} items not yet coded, e.g. {blank[:5]}; scoring only coded items.\n")
human = {i: h for i, h in human.items() if h["relevant"]}

refs = {name: {o["ghsa"]: o for o in map(json.loads, open(D / fn))}
        for name, fn in [("final", "coding_final.jsonl"), ("claude", "coding_claude.jsonl"), ("codex", "coding_codex.jsonl")]}

for name, ref in refs.items():
    items = sorted(human)
    po, k = kappa([human[i]["relevant"] for i in items], [ref[key[i]]["relevant"] for i in items])
    print(f"[human vs {name}] relevant (n={len(items)}): agreement {po:.3f}, kappa {k:.3f}")
    both = [i for i in items if human[i]["relevant"] == "Y" and ref[key[i]]["relevant"] == "Y"]
    for f in FIELDS[1:]:
        po, k = kappa([human[i][f] for i in both], [ref[key[i]][f] for i in both])
        print(f"    {f:20s} (n={len(both)}): agreement {po:.3f}, kappa {k:.3f}")

ref = refs["final"]
dis = []
for i in sorted(human):
    h, r = human[i], ref[key[i]]
    diff = [f for f in FIELDS if (h[f] or None) != (r[f] or None) and not (h["relevant"] == r["relevant"] == "N")]
    if diff:
        dis.append({"item": i, "ghsa": key[i], "fields": diff,
                    "human": {f: h[f] for f in FIELDS}, "final": {f: r[f] for f in FIELDS}, "human_note": h["note"]})
json.dump(dis, open(R / "disagreements_human.json", "w"), indent=1, ensure_ascii=False)
print(f"\n{len(dis)} items differ from the final labels -> recode/disagreements_human.json")
