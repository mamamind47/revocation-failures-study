"""Paper tables (LaTeX) and figures (PDF) from the final labels.
Run with the project venv: .venv/bin/python scripts/03_figures_tables.py"""
import json, pathlib
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[1]
D, T, FIG = ROOT / "data", ROOT / "paper" / "tables", ROOT / "paper" / "figs"
T.mkdir(parents=True, exist_ok=True)
FIG.mkdir(parents=True, exist_ok=True)

# validated categorical palette (dataviz reference, light mode)
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, SURFACE = "#0b0b0b", "#52514e", "#fcfcfb"

inp = {json.loads(l)["ghsa"]: json.loads(l) for l in open(D / "coding_input.jsonl")}
paths = {p.stem: p for p in (ROOT / "adb/advisories/github-reviewed").rglob("*.json")}


def withdrawn(g):
    s = (inp[g]["summary"] + inp[g]["details"][:200]).lower()
    return "duplicate advisory" in s or s.startswith("withdrawn") or "## withdrawn" in s


def load(fn):
    return [json.loads(l) for l in open(D / fn) if l.strip()]


primary = [o for o in load("coding_final.jsonl") if o["relevant"] == "Y" and not withdrawn(o["ghsa"])]
recovered = [o for f in ("recall_final.jsonl", "recall2_final.jsonl") for o in load(f) if o["relevant"] == "Y"]
rel = primary + recovered
web = [o for o in rel if o["webapp"] == "Y"]
year = {o["ghsa"]: json.loads(paths[o["ghsa"]].read_text())["published"][:4] for o in rel}

CARRIERS = ["TOKEN", "SESSION", "CHECK", "DATA", "CACHE", "CONNECTION", "ASYNC", "UNCLEAR"]
VIS = [("N", "needs prior state"), ("DEPENDS", "cache-dependent"), ("Y", "clean-state visible")]
cv = Counter((o["carrier"], o["fresh_state_detects"]) for o in web)

# ---- Table: carrier x clean-state visibility (web apps) ----
rows = []
for c in CARRIERS:
    n = [cv[(c, v)] for v, _ in VIS]
    rows.append(f"{c.title()} & {' & '.join(map(str, n))} & {sum(n)} \\\\")
tot = [sum(cv[(c, v)] for c in CARRIERS) for v, _ in VIS]
(T / "carrier_visibility.tex").write_text(
    "\\begin{tabular}{lrrrr}\n\\toprule\nCarrier & Needs prior state & Cache-dependent & Clean-state visible & Total \\\\\n\\midrule\n"
    + "\n".join(rows) + f"\n\\midrule\nTotal & {' & '.join(map(str, tot))} & {sum(tot)} \\\\\n\\bottomrule\n\\end{{tabular}}\n")

# ---- Table: revocation kind x carrier (all relevant) ----
KINDS = ["LOGOUT_PWCHANGE", "PERMISSION", "ACCOUNT", "CREDENTIAL", "MEMBERSHIP", "OTHER"]
kc = Counter((o["revocation_kind"], o["carrier"]) for o in rel)
lines = [f"{k.replace('_', '/').title()} & " + " & ".join(str(kc[(k, c)]) for c in CARRIERS)
         + f" & {sum(kc[(k, c)] for c in CARRIERS)} \\\\" for k in KINDS]
(T / "kind_by_carrier.tex").write_text(
    "\\begin{tabular}{l" + "r" * (len(CARRIERS) + 1) + "}\n\\toprule\nKind & " + " & ".join(c.title() for c in CARRIERS)
    + " & Total \\\\\n\\midrule\n" + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}\n")

# ---- Table: recall strata ----
s2 = json.load(open(D / "recall2_summary.json"))
strata = [("Seven CWEs, CWE-613", 97, 97, 35, "35"), ("Seven CWEs, other", 3386, 250, 0, "41")]
names = {"A": "CWE group A (287, 384, 281, ...)", "B": "CWE group B (200, 639, 522, ...)", "NONE": "No CWE", "C": "All other CWEs"}
for k in ["A", "B", "NONE", "C"]:
    pop, n, y = s2["pop"][k], s2["n"][k], s2["y"][k]
    ub = f"{3 / n * pop:.0f}" if y == 0 else "55"
    strata.append((names[k], pop, n, y, ub))
lines = [f"{a} & {b:,} & {c} & {d} & {d / c * b:.0f} & {e} \\\\" for a, b, c, d, e in strata]
(T / "recall.tex").write_text(
    "\\begin{tabular}{lrrrrr}\n\\toprule\nStratum & Population & Sampled & Relevant & Est.\\ missed & 95\\% UB \\\\\n\\midrule\n"
    + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}\n")

# ---- Figure 1: carrier x visibility, horizontal stacked bars (web apps) ----
plt.rcParams.update({"font.family": "sans-serif", "font.size": 8.5, "axes.edgecolor": INK2,
                     "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK})
fig, ax = plt.subplots(figsize=(6.2, 2.9), facecolor=SURFACE)
ax.set_facecolor(SURFACE)
order = sorted(CARRIERS, key=lambda c: sum(cv[(c, v)] for v, _ in VIS))
colors = {"N": BLUE, "DEPENDS": ORANGE, "Y": AQUA}
left = [0] * len(order)
for v, label in VIS:
    vals = [cv[(c, v)] for c in order]
    bars = ax.barh([c.title() for c in order], vals, left=left, color=colors[v], label=label,
                   height=0.62, edgecolor=SURFACE, linewidth=2)
    for b, val, l0 in zip(bars, vals, left):
        if val >= 4:  # direct labels give relief for the low-contrast slot
            ax.text(l0 + val / 2, b.get_y() + b.get_height() / 2, str(val), ha="center", va="center",
                    color="white", fontsize=7.5, fontweight="bold")
    left = [a + b for a, b in zip(left, vals)]
for i, total in enumerate(left):
    ax.text(total + 0.8, i, str(total), va="center", color=INK2, fontsize=7.5)
ax.set_xlabel("Web-application revocation failures")
ax.spines[["top", "right"]].set_visible(False)
ax.xaxis.grid(True, color="#e6e5e0", linewidth=0.6)
ax.set_axisbelow(True)
ax.legend(frameon=False, loc="lower right", fontsize=7.5)
fig.tight_layout()
fig.savefig(FIG / "carrier_visibility.pdf")
fig.savefig(FIG / "carrier_visibility.png", dpi=200)

# ---- Figure 2: relevant advisories by publication year ----
yc = Counter(year.values())
ys = [str(y) for y in range(int(min(yc)), int(max(yc)) + 1)]  # show empty years too
fig, ax = plt.subplots(figsize=(6.2, 2.2), facecolor=SURFACE)
ax.set_facecolor(SURFACE)
bars = ax.bar(ys, [yc[y] for y in ys], color=BLUE, width=0.62, edgecolor=SURFACE, linewidth=2)
for b, y in zip(bars, ys):
    ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, str(yc[y]), ha="center", color=INK2, fontsize=7.5)
ax.set_ylabel("Advisories")
ax.set_xlabel("Publication year of the GitHub advisory (2026 through September)")
ax.spines[["top", "right"]].set_visible(False)
ax.yaxis.grid(True, color="#e6e5e0", linewidth=0.6)
ax.set_axisbelow(True)
fig.tight_layout()
fig.savefig(FIG / "by_year.pdf")
fig.savefig(FIG / "by_year.png", dpi=200)

summary = {"relevant": len(rel), "web": len(web), "vis": dict(Counter(o["fresh_state_detects"] for o in web)),
           "carriers_web": dict(Counter(o["carrier"] for o in web)), "years": dict(yc)}
assert sum(cv.values()) == len(web), "a carrier value is missing from CARRIERS"
json.dump(summary, open(ROOT / "paper" / "numbers.json", "w"), indent=1)
print(json.dumps(summary))
