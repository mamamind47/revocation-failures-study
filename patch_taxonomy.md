# Fix strategies and incompleteness in the pre-revocation-artifact class (2026-09-29)

Scope: 15 web-app advisories where residual authority lives in an object the subject created
before losing access (carrier DATA/ASYNC, fresh_state = N). Patch metadata was fetched from GitHub
(`data/patches/`); only diffs, commit messages and advisory text were read, and nothing was executed.

## Two fix strategies
| Strategy | What the patch does | Examples |
|---|---|---|
| **Re-check on read/use (RC)** | Re-authorize the caller when the artifact is read or acted on | Gitea notification convert (#36339, #38108), starred/subscriptions query gate (#38321), MantisBT bugnote revisions (71df1f6), Lemmy multi-community read (6471), Mattermost post edit (#35558), Open WebUI scheduler re-gate (#26047), Gitea fork sync (#38103) |
| **Clean up on revocation (CL)** | Delete or disable the artifacts when access is withdrawn | Gitea ClearRepoWatches on make-private (#36319); collaboration removal cleanup (#36340) |
| Both | CL plus RC at send/read | Gitea #36319 (clear watches + permission check at release-mail send), #36340 (stopwatch read check + cleanup on collaboration removal) |

Each strategy has a coverage obligation that grows with the application:
- CL must cover **every revocation path x every artifact type** (N paths x K types).
- RC must cover **every read path and every field** that renders the artifact (M endpoints x fields).

## Four incompleteness patterns observed (all in Gitea, from advisory text + patches)
1. **Revocation-path incompleteness (CL):** ClearRepoWatches was wired into `MakeRepoPrivate`
   (web UI) but not `updateRepository` (REST `PATCH /repos`) -> GHSA-q423 after GHSA-8fwc.
2. **Artifact-type incompleteness (CL):** the API path cleared stars but not watches (GHSA-q423);
   `DeleteCollaboration` removed the collaboration, watches and assignments but not webhooks the collaborator had created
   (GHSA-66m4).
3. **Read-path incompleteness (RC):** the CVE-2026-20800 fix re-checked access on the
   notification endpoint only; sibling endpoints `/user/starred` and `/user/times` still leaked
   (GHSA-qf2f).
4. **Field-level incompleteness (RC):** after the notification fix, `repository` was nulled
   but `subject` still exposed private titles and live comment activity (GHSA-44qc).

Interpretation: the fixes treat revocation as an event on one object, but the authority has already been
copied into derived objects that are reachable through many paths. This is the same
"coherence, not latency" framing as arXiv 2603.09875, applied to web-app data models.

## Competing work (important)
GHSA-qf2f's credit line reads: "Reported as part of an incomplete-patch measurement study
(responsible disclosure)", runtime-confirmed on gitea 1.25.4. **Another group is already measuring
incomplete patches and finding these Gitea siblings.** Its publication would overlap our
artifact/incomplete-fix angle. Our differentiators must be the cross-project revocation dataset
(230 cases), the carrier taxonomy and clean-state visibility measure, and the CL/RC coverage framing,
not the Gitea findings themselves.

## Cross-project evidence: the coverage framing is not Gitea-specific (added 2026-09-29)

Revocation failures recur within the same project: 18 of 125 projects have 3 or more advisories
(Keycloak 12, Gitea 12, OpenClaw 10, Open WebUI 9, Mattermost 8, Rancher 6, Keystone 6,
Airflow 6). Only 6 of 230 advisories say explicitly that an earlier fix was incomplete (3 of them Gitea). But the
advisory text of six other projects describes the same coverage gap without using that word
(quotes are verbatim):

| Pattern | Project, advisory | Evidence |
|---|---|---|
| Revocation-path | NocoDB, GHSA-r989 | "`passwordChange` and `passwordReset` deleted the user's refresh tokens, but `passwordForgot` only rotated `token_version`..." |
| Revocation-path | Open WebUI, GHSA-wjwr | "Only the admin user-management endpoints invalidated sessions, so a demotion driven by the identity provider left the old privileges live on the socket." |
| Revocation-path | Airflow, GHSA-vr7m | "logout flow for `FabAuthManager` and `KeycloakAuthManager` did not actually reach the underlying `revoke_token()` call" (a follow-up to an earlier logout-JWT advisory) |
| Revocation-path | OpenClaw, 3 advisories | device removal, `device.token.rotate`, and shared-token rotation were each reported separately as not terminating live WebSocket sessions |
| Credential-type | NocoDB, GHSA-g72g | "`revokeAllOAuthTokensByUser` ... was an empty stub being called from `passwordChange`, `passwordForgot`, and `passwordReset`." |
| Credential-type | Mattermost, GHSA-mc2f | deactivation "fails to properly invalidate personal access tokens" |
| Entry/read-path | Vikunja, GHSA-94xm | "User status ... is checked in only two places", namely local login and JWT refresh, not API tokens, CalDAV or OIDC |
| Entry/read-path | Open WebUI, GHSA-855v | Redis revocation is enforced on HTTP but "The realtime authentication surfaces do not perform this check" |

**Revised RQ4 framing.** Revocation is enforced per path. Every revocation trigger has to reach every
carrier (sessions, each credential type, sockets, artifacts), and every entry or read path has to consult
the current state. The recurring failures are missing cells in that trigger × carrier and
entry-path × check matrix. The pre-revocation-artifact class is one instance, not the whole
story. This is also why the static CL-matrix probe worked: it compares rows of that matrix.
