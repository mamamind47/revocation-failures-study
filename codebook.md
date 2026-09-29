# Codebook: access-revocation failures (v1, 2026-09-29)

Code each advisory on the fields below from its summary and details ONLY. Do not guess
beyond the text. When the text is insufficient, use UNCLEAR.

## relevant (Y / N)
Y only if ALL hold:
1. Some authority a subject legitimately HAD was withdrawn: a permission or role was removed or
   lowered, a membership was removed, an account was disabled, deleted or locked, a token, API key,
   share link or invitation was revoked or deleted, or a logout or password change happened.
2. After that withdrawal the subject can STILL exercise some of the withdrawn authority.
N examples: TLS/X.509 certificate revocation checking (CRL/OCSP); a user who NEVER had the right
(ordinary IDOR or missing check); a revoke API that is itself unauthorised (e.g. anyone can revoke others'
tokens); a revocation feature that crashes; a bug where a revoked item is just displayed; library docs.

## carrier (only if relevant=Y). Where does the residual authority live?
- SESSION: an existing login session or cookie established BEFORE revocation keeps old authority
  (server-side session object, cached user/roles in session).
- TOKEN: a self-contained or long-lived credential issued BEFORE revocation stays valid (JWT,
  OAuth access/refresh token, API key, signed URL, remember-me token).
- CACHE: a server-side cache of permissions, membership or auth decisions (in-memory, Redis,
  per-node) that is not invalidated.
- CONNECTION: a long-lived connection opened before revocation (WebSocket, SSE, streaming,
  subscription) keeps delivering or accepting.
- DATA: residual persistent grant or record in the data model (e.g. child grants, ACL
  entries, group links not removed). A FRESH login after revocation would still get access.
- CHECK: the code simply never checks the revoked state (e.g. disabled flag ignored on some endpoint);
  a fresh login or fresh request after revocation would still succeed.
- ASYNC: work queued or scheduled before revocation still runs later (jobs, webhooks, cron).
- UNCLEAR

## fresh_state_detects (only if relevant=Y)
Would a test that starts from a clean state AFTER the revocation (new login or new credential,
cold caches) expose the bug?
- Y: DATA and CHECK usually.
- N: SESSION, TOKEN, CONNECTION, ASYNC usually (the needed state predates revocation).
- DEPENDS: CACHE (depends on whether the cache is per-session or shared), or when the text is ambiguous.
Override the default mapping when the text says otherwise.

## revocation_kind (only if relevant=Y)
PERMISSION (role or permission lowered) | MEMBERSHIP (removed from team, group, project, org) |
ACCOUNT (disabled, deleted, locked, banned) | CREDENTIAL (token, key or share link revoked or deleted) |
LOGOUT_PWCHANGE | OTHER

## webapp (Y/N): is the affected software a web application or web API server (as opposed to a
library, CLI, OS component, or protocol lib)? Libraries that implement web auth (e.g. a session or JWT
library) count as N.

## v1.1 clarifications (2026-09-29, from adjudicating coder disagreements)
- R1. Reading data the subject can no longer see counts as exercising withdrawn authority, even
  when the leak is "only" titles or metadata shown through an old notification, star or watch. The v1 N-example
  "a revoked item is just displayed" meant listing a revoked token in a UI, not leaking protected data.
- R2. `fresh_state_detects` = N whenever the bug needs an object the subject created BEFORE the
  revocation (notification, stopwatch, watch, fork, historical record, share link), even if
  the carrier is DATA. A clean-state test starts after the revocation and has no such object.
- Out of scope: revocation checking in cryptographic libraries and protocols (X.509 CRL/OCSP, SSH CA keys,
  PGP, verifiable credentials, mesh certificate blocklists), and single-use tokens that are not consumed.

## v1.2 clarifications (2026-09-29, from the human re-code)
- Webhooks and scheduled automations are ASYNC (configured work), not DATA; the R2 example list no longer names webhooks.
- If the text states that access persists but not *where* it persists, code carrier = UNCLEAR and fresh_state = DEPENDS. Do not infer a mechanism.
- A missing revocation *trigger* (e.g. token-theft detection that never revokes) is not relevant; relevance requires a withdrawal that happened.
