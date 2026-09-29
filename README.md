# Revocation residual-state: desk study (2026-09-29)

Question: among known access-revocation vulnerabilities, how many would a test that starts
from a clean state after the revocation miss?

## Pipeline
1. `adb/`: sparse clone of github/advisory-database, github-reviewed only (35,979 advisories).
2. `scripts/01_filter.py`: high-recall keyword filter -> `data/candidates.csv` (542).
3. Two independent coders following `codebook.md`: Claude (`data/coding_claude.jsonl`) and
   Codex CLI 0.153.4 (`data/coding_codex.jsonl`). Disagreements adjudicated in
   `data/adjudication.tsv` (33 Claude, 15 Codex, 1 neither) -> `data/coding_final.jsonl`.
4. Recall check in two rounds covering all 35,437 non-candidates (see below):
   `data/recall_final.jsonl` and `data/recall2_final.jsonl`.
5. `python3 scripts/02_analyze.py final` prints the primary tables.

## Agreement (primary coding, n=542)
relevant kappa 0.877 (94.5%); on the 171 both-relevant: carrier 0.894, fresh_state 0.847.

## Recall of the keyword filter
Two rounds cover the whole database except the candidates themselves.

**Round 1: seven access-control CWEs** (613, 284, 285, 863, 862, 269, 672; 3,483 non-candidates).
We sampled all 97 CWE-613 items and 250 random others. Codex coded them, and Claude adjudicated every "relevant"
call (6 of 42 overturned, 1 duplicate removed). A blind check of 60 Codex "not relevant" calls
found 0 errors (`data/fn_check.md`; 95% upper bound on Codex's false-negative rate of 5%).
Result: 35 missed, all in the CWE-613 stratum.

**Round 2: everything else** (31,954 non-candidates), stratified by how many caught positives
each CWE holds (`data/recall2_*`). Codex coded 600 items before it hit its usage limit, and Claude coded the other 250.
Claude adjudicated all 17 Codex "relevant" calls and confirmed 11 of them.

| stratum | population | sampled | relevant | est. missed | 95% UB |
|---|---|---|---|---|---|
| 7 CWEs, CWE-613 | 97 | 97 | 35 | 35 | 35 |
| 7 CWEs, rest | 3,386 | 250 | 0 | 0 | 41 |
| A (287, 384, 281, ...) | 851 | 300 | 11 | 31 | 55 |
| B (200, 639, 522, ...) | 2,544 | 200 | 0 | 0 | 38 |
| no CWE | 1,546 | 150 | 0 | 0 | 31 |
| C (all other CWEs) | 27,013 | 200 | 0 | 0 | 405 |

- **Whole-database recall, point estimate: 184/(184+66) = 0.74.**
- The sampling-based lower bound is uninformative (0.23), because 0/200 in the 27,013-item stratum C
  cannot rule out much. Excluding C, the lower bound is 0.48.
- Model-based note (an assumption, not a sampling bound): stratum C holds only 6 of the 184 caught
  positives. If the filter's recall in C is similar to elsewhere (0.74 to 0.84), C hides about 1 to 2
  missed cases.
- Profile of the misses: round 1 = 35, all needs-prior-state or cache-dependent, 24 logout/password change.
  Round 2 = 11, of which 8 need prior state and 3 are clean-state visible (mostly disabled or deleted accounts).
  One notable miss is CVE-2025-1412 (Mattermost user-to-bot conversion leaves sessions active), because its
  text never says "revoke" or "removed from".

## Results (after human re-code; 183 caught + 46 recall-recovered = 229 relevant; 187 in web apps)
- Web apps: **144/187 (77%) strictly need state created before the revocation**; 154/187 (82%) with the
  10 cache-dependent or unclear cases. Only 33 are visible from a clean state.
- Carriers (web): TOKEN 62, SESSION 55, CHECK 26, DATA 22, CONNECTION 9, CACHE 8, ASYNC 2, UNCLEAR 3.
- 44 distinct CWEs; CWE-613 covers only 107/229 (47%); 8 CWEs are needed for 80% coverage.
- The pre-revocation-artifact class and the four incompleteness patterns: see `patch_taxonomy.md`.

## Human validation
Han blind re-coded 100 candidates (`recode/`). Against the labels as they stood before the re-code
(frozen in `data/coding_final_pre_human.json`): relevance kappa 0.960 (98%); carrier 0.847,
fresh_state 0.764, kind 0.947, webapp 0.850 (`recode/kappa_reported.txt`). Six labels were then revised in
the human coder's favour (`recode/adjudication_human.tsv`); three of them were LLM over-inference of the
carrier. The codebook is now v1.2.

## Limitations
Reported bugs only (selection bias). Recall is estimated with a single LLM coder screen on the
non-candidate side. 2026 is over-represented (reflects advisory-volume growth). Both primary coders
are LLMs; a human re-code of a subset is still owed. Advisory text truncated at 2,500 chars.
The pre-revocation-artifact cluster is concentrated in one project (Gitea) and partly one reporting
batch, so it is a lead, not an established cross-ecosystem trend.
