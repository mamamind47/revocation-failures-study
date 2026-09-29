# Related work scan for the revocation empirical study (2026-09-29)

Search angle: is there an empirical study of access-revocation failures in software
advisories, and of pre-revocation artifacts in particular? None was found. Closest work:

| Work | What it covers | Gap relative to us |
|---|---|---|
| ACtests, arXiv 2505.12770 | Tests config changes (deny<->allow) in a fresh test environment; drops cache service | Fresh state; no pre-revocation state |
| AuthStateBench (2026) | Design-only benchmark; names "stale-session reuse" as a class | No data, no measurement |
| EvoMaster access-policy oracles, arXiv 2604.00702 | Fuzzing oracles for access policy | Not revocation-sequenced |
| Zhu & Wang, arXiv 2609.21284 | Revocation for long-running AI agents, 17 tests | Agents, not web apps |
| Shen et al., arXiv 2609.08258 | Revocation enforcement in agent-memory systems | Agent memory, not web apps |
| LoginPlus, "Login, Logout, Reset" (Springer 2025/26) | Large-scale measurement of logout and token invalidation on top-1M sites | **Already covers our largest class (logout/password change)**, so we should not claim it as new |
| BOLA taxonomy, arXiv 2605.25865 (ISCC) | 100+ bug-bounty BOLA disclosures | Authorization, but not revocation |
| Multi-patch studies, arXiv 2609.07224, 2607.13206 | Multiple security patches per CVE; incomplete fixes in general | Not authorization-specific; can supply our incomplete-fix taxonomy |
| Incomplete fixes in the Linux kernel, arXiv 2511.17799 | Root causes of incomplete security fixes | Kernel only |
| Consent revocation, arXiv 2411.15414 | Cookie-consent revocation by third parties | Different domain |
| ACGreGate, arXiv 1801.07005 | Access control over weakly consistent DBs | Design, not measurement |
| Industry: Wing Security offboarding (2024) | 43% of firms have ex-staff with repo access | Survey, not code-level |

Positioning: the first empirical study of access-revocation failures in OSS advisories, with
(a) a carrier taxonomy, (b) the clean-state visibility measure, and (c) the pre-revocation
artifact class with its incomplete-fix pattern. Logout/password change is reported but framed as
consistent with LoginPlus rather than as new.
