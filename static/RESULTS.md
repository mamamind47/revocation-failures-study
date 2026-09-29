# revcov prototype: feasibility result (2026-09-29)

Static, source-only probe (`revcov.py`, ~150 lines of Python regex plus a crude call graph). It was run on
Gitea v1.26.2 (before the July 2026 fixes) and v1.27.0 (after them). Nothing was built or executed.

## Ground truth: revocation-artifact bugs present in v1.26.2 and fixed by v1.27.0
| Advisory | Bug | Result |
|---|---|---|
| GHSA-q423 | REST visibility change (`updateRepository`) skips `ClearRepoWatches` | **Detected** by the CL matrix (1 flag, the only CL flag); gone in v1.27.0 |
| GHSA-j2w3 / qf2f | `/user/starred`, `/user/subscriptions` list repos after access is revoked | **Detected** by the RC check (4 handler flags); all 4 gone in v1.27.0 |
| GHSA-44qc | notification `subject` field still leaks (field-level) | Missed: field-level exposure is not modeled |
| GHSA-66m4 | removed collaborator's webhooks keep firing | Missed: `Webhook` has no creator field, so it is not discovered as an artifact |
| GHSA-wrf9 | fork sync continues after parent goes private | Missed: the fork link is repo-to-repo, not user-to-object |

**Recall on known bugs: 2 of 5.** Both found bugs disappear in the fixed version, and no known-bug flag remains.

## Noise
- CL matrix: 1 flag in v1.26.2, and it is the true positive; 0 flags in v1.27.0.
- RC check, all read handlers: 28 flags (v1.26.2) vs 24 (v1.27.0). Most sit under repo-scoped
  routes whose group-level middleware already checks current repo permission, which the probe
  cannot see.
- RC check, user-scoped routes only (the surface where this bug class lives): 9 flags in v1.26.2,
  of which 5 correspond to the known bug, and 4 in v1.27.0. The remaining flags were **not triaged** and are
  deliberately not listed in this release; they may be false positives or undisclosed issues.

## What it took to get here (a lesson about the method)
Four fixes were needed before the RC check found the known bug. Each is a generic Go/ORM idiom,
not a Gitea-specific hack: (1) ORM queries that name tables as strings (`"star.uid"`); (2) query
conditions built by `Options.ToConds()` via interface dispatch; (3) same-named methods on different
receivers merging in a name-based call graph; (4) "calls a permission check" is not the same as "uses
the check to drop items". Point 4 is the bug class itself: `getStarredRepos` computed the permission and then ignored it.

## Verdict
The idea **works partially**. The CL half (compare cleanups across revocation paths of the same kind)
is precise and cheap. The RC half finds the read-path leak but needs route-scope awareness to be
usable. The three misses point to model extensions: field-level exposure, artifacts without a creator
field, and object-to-object links. A regex prototype cannot answer precision honestly; a real version
needs go/ast or CodeQL, plus evaluation on a second application.
