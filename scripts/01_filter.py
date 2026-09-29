"""Keyword filter over GitHub-reviewed advisories for access-revocation failures.
High recall on purpose; precision comes from manual/LLM coding in step 02."""
import json, re, pathlib, csv, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
ADB = ROOT / "adb/advisories/github-reviewed"
PATTERNS = {
    "revoke": r"\brevok\w*|\brevocation\b",
    "removed_member": r"(removed|removal) from (the |a |an )?(team|group|project|organi[sz]ation|workspace|channel|board|space|role|repository|site|tenant)",
    "after_removed": r"after (being |having been )?(removed|deleted|deactivated|disabled|demoted|downgraded|suspended|banned|blocked|kicked)",
    "deactivated_user": r"(deactivated|disabled|suspended|banned|blocked|deleted) (user|account|member)s?\b.{0,80}(still|continue|retain|access)",
    "retain_access": r"(retain|keep|still ha(ve|s)|continue to ha(ve|s)|maintain)\w* (their |its )?(access|permission|privilege|role|membership)",
    "session_not_invalidated": r"session\w*.{0,60}(not|never|fail\w*( to)?) (be )?(invalidat|terminat|revok|expire|destroy)\w*|(invalidat|terminat|revok)\w* .{0,30}sessions?\b.{0,40}(not|fail)",
    "stale": r"\bstale\b.{0,40}(permission|session|token|cache|role|authori[sz]ation|membership|privilege)",
    "cache_perm": r"cach\w*.{0,50}(permission|authori[sz]|role|acl|access (control|rights))|(permission|authori[sz]\w*|role|acl)s?.{0,40}cach\w*",
    "role_change": r"(role|permission|privilege)s? (is |are )?(changed|downgraded|reduced|lowered|removed)",
    "no_longer": r"no longer (ha(ve|s) (access|permission|the (right|role))|(a )?member|authori[sz]ed|permitted|allowed|belong)",
    "still_able": r"(still|remain\w*|continue\w*( to be)?) (able|allowed|permitted|authori[sz]ed) to",
    "even_after": r"even after (the |their |being |having )?\w*\s?(\w+ )?(revok|remov|delet|disabl|deactivat|logout|log out|logg|chang|expir|demot|downgrad)",
    "removed_access": r"removed from .{0,60}(still|continue|access|retain)",
    "token_after": r"token\w*.{0,60}(still (valid|work|usable)|remain\w* valid|after (the user|revocation|logout|deletion|password))",
}
RX = {k: re.compile(v, re.I | re.S) for k, v in PATTERNS.items()}
rows = []
for p in ADB.rglob("*.json"):
    a = json.loads(p.read_text())
    text = (a.get("summary") or "") + "\n" + (a.get("details") or "")
    hits = [k for k, rx in RX.items() if rx.search(text)]
    if not hits:
        continue
    aff = a.get("affected") or []
    rows.append({
        "ghsa": a["id"],
        "cve": ",".join(x for x in a.get("aliases", []) if x.startswith("CVE")),
        "published": (a.get("published") or "")[:10],
        "ecosystem": ",".join(sorted({x["package"]["ecosystem"] for x in aff if "package" in x})),
        "package": ",".join(sorted({x["package"]["name"] for x in aff if "package" in x}))[:120],
        "cwes": ",".join(a.get("database_specific", {}).get("cwe_ids", [])),
        "severity": a.get("database_specific", {}).get("severity", ""),
        "hits": ",".join(hits),
        "summary": (a.get("summary") or "").replace("\n", " ")[:200],
        "path": str(p.relative_to(ROOT)),
    })
rows.sort(key=lambda r: r["published"])
out = ROOT / "data/candidates.csv"
with out.open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
from collections import Counter
print(len(rows), "candidates ->", out)
print(Counter(h for r in rows for h in r["hits"].split(",")).most_common())
