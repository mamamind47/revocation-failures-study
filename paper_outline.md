# Paper outline (draft 0, 2026-09-29)

**Working title:** Revoked, But Not Gone: An Empirical Study of Access-Revocation Failures in Open-Source Web Software

**Type / venue:** empirical study. First choice is JSS or IST (Han's earlier targets); the alternatives are EMSE or the
MSR/ESEM technical track. No tool is needed.

## RQs
- **RQ1 (Where does residual authority live?)** Carrier taxonomy over 230 revocation failures:
  TOKEN, SESSION, CHECK, DATA-artifact, CACHE, CONNECTION, ASYNC.
- **RQ2 (Can clean-state testing see them?)** Share of failures that need state created before the
  revocation: 77% of 188 web-app cases, versus 36 that are visible from a clean state.
- **RQ3 (What is withdrawn?)** Revocation kinds: logout/password change, permission, account,
  credential, membership, visibility. Logout/password change is the biggest kind, which is consistent with
  LoginPlus and is not claimed as new.
- **RQ4 (Why do fixes stay incomplete?)** Pre-revocation artifacts: two fix strategies
  (clean-up-on-revoke vs re-check-on-read) and four incompleteness patterns (revocation path,
  artifact type, read path, field).

## Method (mostly done)
1. Data: GitHub-reviewed advisories (35,979), keyword filter -> 542 candidates.
2. Coding: codebook v1.1, two independent coders (Claude, Codex), kappa 0.877 on relevance,
   49 disagreements adjudicated.
3. Recall: two stratified rounds over all non-candidates. Point estimate 0.74; 46 cases
   recovered; bounds reported honestly (C stratum uninformative).
4. Patch analysis: 15 artifact-class advisories, 24 patch references.

## Contributions
1. The first cross-project dataset and taxonomy of access-revocation failures (release data + codebook).
2. A clean-state-visibility measure showing why fresh-environment testing (e.g., ACtests-style) is
   structurally blind to most revocation failures.
3. Evidence that cache, often named as the culprit, is a minority carrier (9/188).
4. The coverage framing (N revocation paths x K artifact types, or M read paths x fields), which
   explains recurring incomplete fixes and gives testers concrete guidance.

## Threats to validity (write these carefully)
- Reported-bug selection bias. We describe reported failures, not how prevalent they are in the wild.
- Both primary coders are LLMs. **A human re-code of a random subset is still owed** (Han, and
  ideally a second person; report kappa).
- 2026 is over-represented (95/184), and one Gitea reporting batch dominates the artifact class.
- Recall bounds: point estimate 0.74; the lower bound is uninformative for the largest stratum.
- Competing work: an "incomplete-patch measurement study" by another group already reports Gitea siblings
  (see patch_taxonomy.md). Monitor arXiv and cite it once it appears.

## Remaining work before a full draft
1. Human re-code of about 100 items (for kappa against the adjudicated labels).
2. Extend the artifact/incomplete-fix analysis beyond Gitea, or state its concentration openly.
3. Write RQ1 to RQ4 results with tables and figures from `scripts/02_analyze.py`.
4. Release package: codebook, labels, scripts (not the advisory DB itself; cite a snapshot date).
