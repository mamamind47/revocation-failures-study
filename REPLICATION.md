# Replication package: "Revoked, But Not Gone"

Everything needed to reproduce the numbers, tables and figures in `paper/main.tex`.

## 0. Advisory snapshot
The GitHub Advisory Database is not redistributed. Clone the `github-reviewed` tree and check out
the commit nearest to **29 September 2026** (35,979 advisories):
```
git clone --filter=blob:none --sparse https://github.com/github/advisory-database.git adb
cd adb && git sparse-checkout set advisories/github-reviewed
```
Snapshot used: advisory-database commit `66975d745323ec6770fbbfe20a5687affb89b93f` (2026-09-28T15:52:38Z).

## 1. Candidate selection
`python3 scripts/01_filter.py` -> `data/candidates.csv` (542 candidates)

## 2. Coding and agreement
- Codebook: `codebook.md` (v1.1). Thai version for human coders: `recode/codebook_th.md`
- Coder input: `data/coding_input.jsonl`
- Coder 1 (Claude): `data/coding_claude.jsonl`; coder 2 (Codex CLI, gpt-5.6-sol): `data/coding_codex.jsonl`
  (run log: `data/codex_run.log`)
- Agreement and disagreements: `python3 scripts/02_analyze.py` -> `data/disagreements.jsonl`
- Adjudication with reasons: `data/adjudication.tsv` -> `data/coding_final.jsonl`
- Human re-code (blind, n=100): `recode/` (`items.md`, `answers.csv`, `score.py`). The key is in
  `recode/_key_do_not_open.json`.

## 3. Recall audit
- Round 1 (seven access-control CWEs): `data/recall_sample.jsonl`, `data/recall_codex.jsonl`, `data/recall_final.jsonl`
- Blind false-negative check of Codex: `data/fn_check.md`, `data/fn_check_ids.txt`
- Round 2 (all other advisories): `data/recall2_sample.jsonl`, `data/recall2_codex.jsonl`,
  `data/recall2_final.jsonl`, `data/recall2_strata.json`, `data/recall2_summary.json`

## 4. Tables and figures
`python3 -m venv .venv && .venv/bin/pip install matplotlib`
`.venv/bin/python scripts/03_figures_tables.py` -> `paper/tables/*.tex`, `paper/figs/*.pdf`, `paper/numbers.json`

## 5. Incomplete-fix analysis (RQ4)
- Object-carried cases and patch links: `data/artifact_class.json`; patch metadata: `data/patches/`
- Taxonomy and verbatim evidence: `patch_taxonomy.md`

## 6. Static probe
`static/revcov.py` (source-only). Run it on Gitea v1.26.2 and v1.27.0 (`git clone --depth 1 --branch <tag>`):
`python3 static/revcov.py static/gitea-v1.26.2 out.json`. Results: `static/RESULTS.md`

## 7. Paper
`cd paper && tectonic -X compile main.tex`
