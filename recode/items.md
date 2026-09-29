# รายการสำหรับจัดประเภท (100 รายการ)

อ่าน codebook_th.md ก่อนเริ่ม กรอกคำตอบลง answers.csv โดยใช้เลข item

---

## R001

**Package:** typo3/cms

**Summary:** Typo3 Security Misconfiguration in User Session Handling

When users change their password existing sessions for that particular user account are not revoked. A valid backend or frontend user account is required in order to make use of this vulnerability.

---

## R002

**Package:** ci4-cms-erp/ci4ms

**Summary:** CI4MS has a Deactivated User Session Bypass (active=0)

### Summary
The auth filter has the deactivated/banned user check commented out. 

### Details
CodeIgniter Shield's `loggedIn()` re-checks the `status` field (catching `status='banned'`), but does **not** re-check the `active` field for existing sessions. When an admin deactivates a user (`active=0`) after they have already logged in:
- Their session cookie remains valid
- `auth()->loggedIn()` still returns `true`
- The commented-out code is the only mechanism that would have checked `!$user->active`

### Evidence
<img width="981" height="654" alt="image" src="https://github.com/user-attachments/assets/6f75d144-5bcf-4a3f-bc35-bb0715c3ed05" />


### Impact
- User deactivation does NOT immediately revoke backend access
- Deactivated user retains full access until session expires (default: 7200s)

### Additional note
The commented-out block appears to be a deferred placeholder — it was written but disabled from the very first commit that introduced the filter, and has never been active. The later addition of SessionTracker (v0.31.4.0) suggests the dev was aware of the session revocation gap, but account-level deactivation (users.active = 0) remains unenforced. Could you verify if this is intentionally pending or simply forgotten and not documented?.

---

## R003

**Package:** github.com/QuantumNous/new-api

**Summary:** New API: Redis user quota cache overwrite via PUT /api/user/self allows quota bypass

### Summary
Authenticated users can repeatedly call PUT /api/user/self with language or sidebar_modules while relay requests are consuming quota. The settings path reads a full User snapshot and writes it back through User.Update(), which refreshes Redis with RedisHSetObj and overwrites the Quota field. This can erase concurrent HINCRBY quota deductions and keep cached balance artificially high, allowing calls far beyond the paid quota.

### Impact
A low-privileged authenticated user may bypass quota enforcement and cause financial loss to operators. Authentication and pre-consumption use cached quota, while DB/log usage can continue increasing.

### Affected Components
- controller/user.go: UpdateSelf language/sidebar_modules branches
- model/user.go: User.Update / UpdateWithTx full snapshot update
- model/user_cache.go: updateUserCache RedisHSetObj full hash write
- model/user.go: GetUserQuota reads Redis cache first

### Root Cause
Normal billing uses Redis HINCRBY on user:<id>.Quota, while settings updates use a stale full user snapshot to HSET the entire cache hash, including Quota. These two writers race on the same Redis field.

### Patches
This issue is fixed in v1.0.0-rc.16. The fix makes user setting updates field-scoped, prevents stale user snapshots from overwriting accounting fields, and keeps generic user cache refreshes from modifying Quota. Quota cache updates are reserved for atomic quota delta paths or explicit quota synchronization paths.

### Workarounds
If upgrading immediately is not possible, operators should temporarily restrict or rate-limit PUT /api/user/self and avoid allowing frequent user setting updates while Redis-backed quota cache is enabled. This is only a mitigation; upgrading is recommended.

### Remediation
Upgrade to v1.0.0-rc.16 or later. Deployments with Redis enabled should restart application instances after upgrading so stale in-process code paths are removed.

---

## R004

**Package:** openclaw

**Summary:** OpenClaw: Discord voice ingress authorization can be bypassed via channel, name, and stale-role validation gaps

## Summary
Discord voice ingress authorization can be bypassed via channel, name, and stale-role validation gaps

## Current Maintainer Triage
- Status: narrow
- Assessment: Real in shipped v2026.3.28 Discord voice ingress, but impact is channel/member allowlist bypass rather than a broader critical auth break and mainline fix is unreleased.

## Affected Packages / Versions
- Package: `openclaw` (npm)
- Latest published npm version: `2026.3.31`
- Vulnerable version range: `<=2026.3.28`
- Patched versions: `>= 2026.3.31`
- First stable tag containing the fix: `v2026.3.31`

## Fix Commit(s)
- `dba96e7507e0900f120e5e28e57755d69bf78759` — 2026-03-31T21:29:13+09:00

OpenClaw thanks @cyjhhh for reporting.

---

## R005

**Package:** graphql-shield

**Summary:** Authorization Bypass in graphql-shield

Versions of `graphql-shield` prior to 6.0.6 are vulnerable to an Authorization Bypass. The rule caching option `no_cache` relies on keys generated by cryptographically insecure functions, which may cause rules to be incorrectly cached. This allows attackers to access information they should not have access to in case of a key collision.


## Recommendation

Upgrade to version 6.0.6 or later.

---

## R006

**Package:** io.quarkus:quarkus-cache

**Summary:** Quarkus Cache Runtime exposes sensitive information to an unauthorized actor

A flaw was found in the Quarkus Cache Runtime. When request processing utilizes a Uni cached using @CacheResult and the cached Uni reuses the initial "completion" context, the processing switches to the cached Uni instead of the request context. This is a problem if the cached Uni context contains sensitive information, and could allow a malicious user to benefit from a POST request returning the response that is meant for another user, gaining access to sensitive data.

---

## R007

**Package:** code.gitea.io/gitea

**Summary:** Gitea: Repository Visibility Manipulation via Git Push Options

### Repository Visibility Manipulation via Git Push Options

| Field | Value |
|-------|-------|
| **Affected File** | `routers/private/hook_post_receive.go` |
| **Affected Function** | `HookPostReceive()` |
| **Affected Lines** | 173–225 |
| **Prerequisite** | Attacker must have owner-level or admin collaborator access to the target repository |

---

#### Description

Gitea's post-receive git hook handler processes git push options — key-value pairs transmitted by a client during `git push` using the `-o` flag. Two undocumented push options, `repo.private` and `repo.template`, allow any user with repository owner or admin-collaborator access to toggle the visibility (`private/public`) and template status of a repository as a side effect of a normal git push.

This capability was originally intended solely for the "push-to-create" feature (automatically creating a repo on first push). However, the options are processed without restriction on already-existing repositories, and — critically — the visibility change bypasses every control that a proper settings change would trigger:

- No entry written to the repository's audit/activity log
- No webhook event fired (`repository` event with `visibility_changed` action)
- No org-level notification to owners
- No team permission re-calculation
- No email alert to watchers
- The database update uses `UpdateRepositoryColsNoAutoTime`, which also suppresses the `updated_at` timestamp change


---

#### Vulnerable Code

**`routers/private/hook_post_receive.go:173–225`**

```go
isPrivate  := opts.GitPushOptions.Bool(private.GitPushOptionRepoPrivate)  // "repo.private"
isTemplate := opts.GitPushOptions.Bool(private.GitPushOptionRepoTemplate) // "repo.template"

if isPrivate.Has() || isTemplate.Has() {
    // ... loads repo and verifies pusher is owner or admin ...
    if !perm.IsOwner() && !perm.IsAdmin() {
        ctx.JSON(http.StatusNotFound, ...)
        return
    }

    // FIXME: these options are not quite right, for example: changing visibility
    //        should do more works than just setting the is_private flag
    // These options should only be used for "push-to-create"
    if isPrivate.Has() && repo.IsPrivate != isPrivate.Value() {
        // TODO: it needs to do more work
        repo.IsPrivate = isPrivate.Value()
        repo_model.UpdateRepositoryColsNoAutoTime(ctx, repo, "is_private")
        //         ^^^ bypasses updated_at timestamp, audit trail suppressed
    }
    if isTemplate.Has() && repo.Is [...truncated]

---

## R008

**Package:** github.com/openfga/openfga

**Summary:** OpenFGA has an Authorization Bypass through cached keys

### Description
In OpenFGA, under specific conditions, models using conditions with caching enabled can result in two different check requests producing the same cache key. This can result in OpenFGA reusing an earlier cached result for a different request.

### Am I Affected?
Users are affected if the following preconditions are met:
1. The model has relations which rely on condition evaluation.
1. Caching is enabled.

### Fix
Upgrade to OpenFGA v1.13.1.

### Acknowledgement
OpenFGA would like to thank @Amemoyoi for the discovery and responsible disclosure.

---

## R009

**Package:** github.com/rancher/rancher

**Summary:** Rancher Project Members Have Continued Access to Namespaces After Being Removed From Them

In Rancher 2.0.0 through 2.1.5, project members have continued access to create, update, read, and delete namespaces in a project after they have been removed from it.

---

## R010

**Package:** github.com/cloudflare/gokey

**Summary:** gokey allows secret recovery from a seed file without the master password

In gokey versions `<0.2.0`, a flaw in the seed decryption logic resulted in passwords incorrectly being derived solely from the initial vector and the AES-GCM authentication tag of the key seed.

This issue has been fixed in gokey version `0.2.0`. This is a breaking change. The fix has invalidated any passwords/secrets that were derived from the seed file (using the `-s` option). Even if the input seed file stays the same, version `0.2.0` gokey will generate different secrets.

### Impact

This vulnerability impacts generated keys/secrets using a seed file as an entropy input (using the `-s` option). Keys/secrets generated just from the master password (without the `-s` option) are not impacted. The confidentiality of the seed itself is also not impacted (it is not required to regenerate the seed itself). Specific impact includes:

* keys/secrets generated from a seed file may have lower entropy: it was expected that the whole seed would be used to generate keys (240 bytes of entropy input), where in vulnerable versions only 28 bytes was used  
* a malicious entity could have recovered all passwords, generated from a particular seed, having only the seed file in possession without the knowledge of the seed master password

### Patches

The code logic bug has been fixed in gokey version `0.2.0` and above. Due to the deterministic nature of gokey, fixed versions will produce different passwords/secrets using seed files, as all seed entropy will be used now.

### System secret rotation guidance

It is advised for users to regenerate passwords/secrets using the patched version of gokey (`0.2.0` and above), and provision/rotate these secrets into respective systems in place of the old secret. A specific rotation procedure is system-dependent, but most common patterns are described below.

#### Systems that do not require the old password/secret for rotation

Such systems usually have a "Forgot password" facility or a similar facility allowing users to rotate their password/secrets by sending a unique "magic" link to the user's email or phone. In such cases users are advised to use this facility and input the newly generated password secret, when prompted by the system.

#### Systems that require the old password/secret for rotation

Such systems usually have a modal password rotation window usually in the user settings section requiring the user to input the old and the new password sometimes with a confirmation. To generate/recover the old password in such cas [...truncated]

---

## R011

**Package:** github.com/mattermost/mattermost-server

**Summary:** Mattermost doesn't properly validate channel membership at the time of data retrieval

Mattermost versions 10.11.x <= 10.11.9 fail to properly validate channel membership at the time of data retrieval which allows a deactivated user to learn team names they should not have access to via a race condition in the /common_teams API endpoint.. Mattermost Advisory ID: MMSA-2025-00549

---

## R012

**Package:** github.com/filebrowser/filebrowser,github.com/filebrowser/filebrowser/v2

**Summary:** File Browser’s insecure JWT handling can lead to session replay attacks after logout

### Summary

File Browser’s authentication system issues long-lived JWT tokens that remain valid even after the user logs out. Please refer to the CWE's listed in this report for further reference and system standards. In summary, the main issue is:

- Tokens remain valid after logout (session replay attacks)

In this report, I used docker as the documentation instruct:

```
docker run \
    -v filebrowser_data:/srv \
    -v filebrowser_database:/database \
    -v filebrowser_config:/config \
    -p 8080:80 \
    filebrowser/filebrowser
```

### Details

**Issue: Tokens remain valid after logout (session replay attacks)**

After logging in and receiving a JWT token, the user can explicitly "log out." However, this action does not invalidate the issued JWT. Any captured token can be replayed post-logout until it expires naturally. The backend does not track active sessions or invalidate existing tokens on logout. Login request:

```
POST /api/login HTTP/1.1
Host: machine.local:8090
Content-Length: 69

{"username":"admin","password":"password-here","recaptcha":""}
```

The check found in the code `https://github.com/filebrowser/filebrowser/blob/master/http/auth.go` is not enough. There is no server-side blacklist or token invalidation on logout. Token renewal and validity only depends on expiry and user store timestamps:

```
expired := !tk.VerifyExpiresAt(time.Now().Add(time.Hour), true)
updated := tk.IssuedAt != nil && tk.IssuedAt.Unix() < d.store.Users.LastUpdate(tk.User.ID)
```

### PoC

**Issue: Tokens remain valid after logout (session replay attacks)**

- Login and capture the generate JWT. Eg. the http request:

```
POST /api/login HTTP/1.1
Host: machine.local:8090
Content-Length: 69

{"username":"admin","password":"password-here","recaptcha":""}
```

- Logout in the dashboard. And then try to use the old generated JWT to access any authenticated endpoint eg:

```
GET /api/resources HTTP/1.1
Host: machine.local:8090
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
X-Auth: Old-JWT-token-here
Content-Length: 173
Accept: */*
Referer: http://machine.local:8090/files/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Content-Length: 26

Connection: keep-alive
```

### Impact

- A valid JWT remains active after user logout.
- If stolen, tokens persist access indefinitely until expiry.
- Violates OWASP Top 10 A2:2021 - Broken Authentication.

### Recommendation [...truncated]

---

## R013

**Package:** solidinvoice/solidinvoice

**Summary:** SolidInvoice: IDOR in LiveComponent allows same-company cross-user access to API tokens and notification transport settings

## Summary

Four authorization bypass vulnerabilities in Symfony LiveComponent actions allow any authenticated user within a company to access, modify, or delete other users' API tokens and notification transport settings. The root cause is that LiveComponent actions accept entity IDs without verifying ownership, while the listing methods correctly filter by user.

## Findings

### 1. Cross-User API Token Revocation (MEDIUM)

**File:** `src/UserBundle/Twig/Components/ApiTokens.php`, lines 50-55

The `revoke()` LiveAction accepts any `ApiToken` via `#[LiveArg]` without checking ownership. The `apiTokens()` method correctly filters by user (`getApiTokensForUser($this->security->getUser())`).

```php
#[LiveAction]
public function revoke(#[LiveArg] ApiToken $token): void
{
    $this->apiTokenRepository->revoke($token); // No ownership check
}
```

### 2. Cross-User API Token History Disclosure (MEDIUM)

**File:** `src/UserBundle/Twig/Components/ApiTokenHistory.php`, lines 30-55

The writable `$token` LiveProp performs `$this->apiTokenRepository->find($this->token)` without user verification. Exposes IP addresses, request methods, paths, and user agents from other users' API token usage.

### 3. Cross-User Notification Transport Settings Disclosure (HIGH)

**File:** `src/NotificationBundle/Twig/Components/NotificationIntegrations.php`, lines 48-55

The `integration()` method performs `$this->repository->find($this->setting)` using a writable LiveProp without user check. The `enabledIntegrations()` method correctly filters: `$this->repository->findBy(['user' => $this->getUser()])`.

The `TransportSetting` entity stores notification credentials in a JSON `settings` column, potentially exposing API keys for Slack, Discord, Telegram, or SMS services.

### 4. Cross-User Notification Transport Setting Takeover (HIGH)

**File:** `src/NotificationBundle/Twig/Components/NotificationTransportConfiguration.php`, lines 39-40, 84-101

The writable `$setting` LiveProp accepts any `TransportSetting` entity. The `save()` action overwrites the user field with the current user via `$setting->setUser($user)`, effectively stealing the transport configuration and its stored credentials.

## Root Cause

The application relies on Doctrine's `CompanyFilter` for tenant isolation but has no user-level access controls within a company. LiveComponent actions that resolve entities from client-provided IDs don't verify ownership.

## Suggested Fix

Add user ownership verification in each Li [...truncated]

---

## R014

**Package:** mint

**Summary:** mint has potential CRLF injection in its HTTP request line via unvalidated `method`/`target`

### Summary

Mint's HTTP/1 request encoder splices the caller-supplied `method` and `target` directly into the request line without character validation. An application that forwards attacker-controlled input as the HTTP method or the target to `Mint.HTTP.request/5` is exposed to request-line CRLF injection, allowing the attacker to terminate the request line early, inject arbitrary headers, and pipeline a fully attacker-chosen second request onto the same TCP connection.

### Details

`encode_request_line/2` in `lib/mint/http1/request.ex` writes `method` and `target` to the wire verbatim. `encode_headers/1` validates header names and values, but there is no equivalent `validate_method!/1`.

Mint 1.7.0 added `validate_request_target/2`, which rejects CRLF and other control characters in `target` by default and closes the path/query vector. The `method` field remains unvalidated, so a CRLF-bearing method such as `"GET / HTTP/1.1\r\nX-Smuggled: 1\r\nGET /admin"` is accepted and written to the socket as-is. Bytes after the first `\r\n` are interpreted by the peer as an injected header, or, with a second `\r\n`, as an additional pipelined request.

### PoC

1. Stand up a Mint-using gateway/proxy that calls `Mint.HTTP.request(conn, method, "/", [], nil)` with `method` taken from caller input.
2. Send a request whose forwarded method is `"GET / HTTP/1.1\r\nX-Smuggled-Header: pwned\r\nGET /admin/delete-everything"`.
3. Observe the bytes received by the upstream server: the smuggled header line and the second request line appear verbatim in the outbound stream.

### Impact

CRLF injection / HTTP request smuggling in the HTTP/1 client encoder, exploitable under default configuration whenever an application passes caller-influenced input as the HTTP method. An attacker who controls the method can inject arbitrary outbound headers (forged `Host`, `Authorization`, cache-poisoning headers) and smuggle additional, fully attacker-chosen requests to the upstream server over the same connection, potentially reaching endpoints the legitimate caller never intended to invoke.

## Resources

* Introduction commit: https://github.com/elixir-mint/mint/commit/8db1acff30b6a9433762c18b1e1f891b8c1f74f7
* Patch commit: https://github.com/elixir-mint/mint/commit/fad091454cbb7449b19edb8e1fee12ca7cf28c3a

---

## R015

**Package:** github.com/siyuan-note/siyuan/kernel

**Summary:** SiYuan: The session-cookie signing key (Conf.CookieKey) is returned to anonymous readers by /api/system/getConf

**CVE:** This vulnerability corresponds to [CVE-2026-72794](https://nvd.nist.gov/vuln/detail/CVE-2026-72794).

### Summary

`/api/system/getConf` returns `Conf.CookieKey`, the key used to sign the server's session cookies in its response body. The endpoint is registered with `CheckAuth` only, so the field reaches the publish `RoleReader` token and the anonymous account when `Publish.Auth.Enable` is `false`.

The configuration-export endpoint in the same file strips this exact field before returning config, so the project already treats it as secret. The reader-facing masking path does not.

### Details

| Item | Detail |
|---|---|
| Route | `kernel/api/router.go:70` `POST /api/system/getConf` → `model.CheckAuth` → `getConf` |
| Middleware | `CheckAuth` only — no `CheckReadonly`, no `CheckAdminRole` |
| Leaked field | `AppConf.CookieKey`, serialized as `cookieKey` |
| Purpose of the field | Signing key for the `siyuan` session cookie |

**The field survives every stage of the masking chain.** `getConf` masks through `GetMaskedConf()` → `HideConfSecret()` (non-administrators) → `FilterConfByPublishIgnore()` (readers) → the browser-side System-path strip. `CookieKey` is removed by none of them:

- `GetMaskedConf` masks `UserData`, `MCPOAuth` and `AccessAuthCode` only.
- `HideConfSecret` nulls `AI`, `Api`, `Flashcard`, `ServerAddrs`, `Publish`, `Repo`, `Sync`, `Secrets`, `Variables` and the System paths. It contains no reference to `CookieKey`.
- `FilterConfByPublishIgnore` touches `UILayout` only.
- The browser-side strip removes System paths only.

**The key is live, not vestigial.** It is passed straight into the session store at startup:

```
cli/cmd/serve.go:67   go server.Serve(false, model.Conf.CookieKey)
kernel/server/serve.go:152   sessionStore = cookie.NewStore([]byte(cookieKey))
kernel/server/serve.go:159   ginServer.Use(sessions.Sessions("siyuan", sessionStore))
```

`gin-contrib/sessions/cookie.NewStore` constructed with a single key uses that key as the `gorilla/securecookie` HMAC key. The `siyuan` session cookie is therefore signed with the value the endpoint hands out. An attacker holding it can mint and modify session cookies that the server accepts as authentic.

**Guarded sibling, in the same file.** `exportConf` (`kernel/api/system.go:299`) clones the configuration before returning it and explicitly clears both secrets:

```
kernel/api/system.go:360   clonedConf.CookieKey = ""
                           clonedConf.NotebookCrypto = nil
```

 [...truncated]

---

## R016

**Package:** github.com/go-gitea/gitea

**Summary:** Gitea improperly exposes issue titles and repository names through previously started stopwatches

Gitea's stopwatch API does not re-validate repository access permissions. After a user's access to a private repository is revoked, they may still view issue titles and repository names through previously started stopwatches.

---

## R017

**Package:** katalyst-koi

**Summary:** katalyst-koi: Session cookies can be replayed after user logout

### Impact

Admin session cookies were not invalidated when an admin user logged out. An attacker with access to a valid admin session cookie could continue to access admin functionality after logout, until the cookie expired or session secrets were rotated.

This affects applications using Koi admin authentication where an admin session cookie may have been exposed, cached, intercepted, or otherwise retained after logout.

### Patches

The issue has been patched by recording admin logout time and rejecting any admin session cookie created before the user’s most recent logout.

Users should upgrade to the patched Koi releases once available.

### Workarounds

Katalyst Koi recommends upgrading to the latest available version, or back porting the changes released in 5.6.0/4.20.0

### Resources

This is an application of https://guides.rubyonrails.org/v5.2.0/security.html#replay-attacks-for-cookiestore-sessions

---

## R018

**Package:** github.com/zitadel/zitadel

**Summary:** ZITADEL's truncated opaque tokens are still valid

### Summary

Opaque OIDC access tokens in v2 format, truncated to 80 characters are still considered valid. 

ZITADEL uses a symmetric AES encryption for opaque tokens. The cleartext payload is a concatenation of a couple of identifiers, such as a token ID and user ID. Internally Zitadel has 2 different versions of token payloads. v1 tokens are no longer created, but are still verified as to not invalidate existing session after upgrade.

The cleartext payload has a format of `<token_id>:<user_id>`. v2 tokens distinguished further where the `token_id` is of the format `v2_<oidc_session_id>-at_<access_token_id>`. This is an example of such a cleartext: `V2_354201447279099906-at_354201447279165442:354201364702363650`

### Impact

V1 token authZ/N session data is retrieved from the database using the (simple) `token_id` value and `user_id` value. The `user_id` (called `subject` in some parts of our code) was used as being the trusted user ID.

V2 token authZ/N session data is retrieved from the database using the `oidc_session_id` and `access_token_id` and in this case the `user_id` from the token is ignored and taken from the session data in the database.

By truncating the token to 80 chars, the user_id is now missing from the cleartext of the v2 token: `V2_354201447279099906-at_354201447279165442:`  The back-end still accepts this for above reasons.

This issue is not considered exploitable, but may look awkward when reproduced.

### Affected Versions

All versions within the following ranges, including release candidates (RCs), are affected:
- **v4.x**: `4.0.0` through `4.10.1`
- **3.x**: `3.0.0` through `3.4.6`
- **2.x**: `2.31.0` through `2.71.19`

### Patches

The vulnerability has been addressed in the latest releases. The patch resolves the issue by verifying the `user_id` from the token against the session data from the database

4.x: Upgrade to >=[4.11.0](https://github.com/zitadel/zitadel/releases/tag/v4.11.0)
3.x: Update to >=[3.4.7](https://github.com/zitadel/zitadel/releases/tag/v3.4.7)
2.x: Update to >=[3.4.7](https://github.com/zitadel/zitadel/releases/tag/v3.4.7)

### Workarounds

The recommended solution is to update ZITADEL to a patched version.

### Questions

If there any questions or comments about this advisory, please send an email to [security@zitadel.com](mailto:security@zitadel.com)

### Credits

ZITADEL thanks Olivier Becker and Lucas Dodgson for reporting this vulnerability.

---

## R019

**Package:** github.com/zitadel/zitadel/v2

**Summary:** ZITADEL's Service Users Deactivation not Working 

### Impact
ZITADEL's user account deactivation mechanism did not work correctly with service accounts. Deactivated service accounts retained the ability to request tokens, which could lead to unauthorized access to applications and resources.

### Patches

2.x versions are fixed on >= [2.62.1](https://github.com/zitadel/zitadel/releases/tag/v2.62.1)
2.61.x versions are fixed on >= [2.61.1](https://github.com/zitadel/zitadel/releases/tag/v2.61.1)
2.60.x versions are fixed on >= [2.60.2](https://github.com/zitadel/zitadel/releases/tag/v2.60.2)
2.59.x versions are fixed on >= [2.59.3](https://github.com/zitadel/zitadel/releases/tag/v2.59.3)
2.58.x versions are fixed on >= [2.58.5](https://github.com/zitadel/zitadel/releases/tag/v2.58.5)
2.57.x versions are fixed on >= [2.57.5](https://github.com/zitadel/zitadel/releases/tag/v2.57.5)
2.56.x versions are fixed on >= [2.56.6](https://github.com/zitadel/zitadel/releases/tag/v2.56.6)
2.55.x versions are fixed on >= [2.55.8](https://github.com/zitadel/zitadel/releases/tag/v2.55.8)
2.54.x versions are fixed on >= [2.54.10](https://github.com/zitadel/zitadel/releases/tag/v2.54.10)

### Workarounds
Instead of deactivating the service account, consider creating new credentials and replacing the old ones wherever they are used. This effectively prevents the deactivated service account from being utilized.

- Revoke all existing authentication keys associated with the service account
- Rotate the service account's password

### Questions
If you have any questions or comments about this advisory, please email us at 

[security@zitadel.com](mailto:security@zitadel.com)

---

## R020

**Package:** open-webui

**Summary:** Open WebUI: Users denied by the OAuth role policy can still sign in via token exchange

## Summary
Open WebUI's OAuth token exchange endpoint issues a session for a provider access token without running the OAuth role management that the normal OAuth login callback runs. A user whose provider roles the login callback would refuse, or would demote, could still obtain a working session at their existing role through this endpoint.

## Preconditions
- `ENABLE_OAUTH_TOKEN_EXCHANGE=True`. It is disabled by default, so a default deployment is not affected.
- `ENABLE_OAUTH_ROLE_MANAGEMENT=True` together with `OAUTH_ALLOWED_ROLES` or `OAUTH_ADMIN_ROLES`. Role management is off by default, and deployments not using it are not affected.
- A valid, unexpired access token on the configured provider.
- An Open WebUI account already linked to that provider subject, or an account with a matching email when `OAUTH_MERGE_ACCOUNTS_BY_EMAIL` is enabled. This endpoint never creates accounts, so a token for a subject with no existing account is rejected.

## Impact
An admin who relies on OAuth role management expects a user to lose access, or lose admin, as soon as the identity provider stops reporting the required role. The login callback does enforce this on the next sign-in. Token exchange kept issuing sessions and never re-evaluated the role, so the user retained working access as their existing account at its existing role, including an admin role the provider had already revoked. The endpoint cannot create an account and cannot raise anyone's role, so this grants continued access rather than new or elevated access.

## Fix
d799e81ed, released in 0.11.1, runs the same role evaluation on the provider's response that the login callback runs. The exchange is denied with 403 when the reported roles match no allowed or admin role, and the account's role is updated to match the provider otherwise. Upgrading restores the check with no further action.

## Root cause
The affected component is the OAuth token exchange endpoint in `backend/open_webui/routers/auths.py`, present in builds from 0.8.0 onward.

The endpoint was added as a second entry point into the same session-issuing path the OAuth login callback uses, but it re-implemented only the identity lookup and not the policy checks surrounding it. Role evaluation lived inside the callback's own body rather than in shared code, so the second caller inherited none of it.

## Credits
@Classic298

---

## R021

**Package:** pimcore/admin-ui-classic-bundle

**Summary:** Pimcore's Admin Classic Bundle is Missing Function Level Authorization on "Predefined Properties" Listing

### Summary
The API endpoint for listing Predefined Properties in the Pimcore platform lacks adequate server-side authorization checks. Predefined Properties are configurable metadata definitions (e.g., name, key, type, default value) used across documents, assets, and objects to standardize custom attributes and improve editorial workflows, as documented in Pimcore's official properties guide. Testing confirmed that an authenticated backend user without explicit permissions for property management could successfully call the endpoint and retrieve the complete list of these configurations. This exemplifies Broken Access Control (OWASP Top 10 A01:2021), enabling unauthorized access to administrative features and potentially violating role-based access controls inherent to Pimcore's multi-user environment.

### Details
The backend user without permission was still able to list "Predefined Properties" item

### Step to Reproduce the issue 
login as Admin (full permission) and clicked "Predefined Properties"
<img width="1493" height="862" alt="Screenshot 2025-12-10 at 10 11 31 PM" src="https://github.com/user-attachments/assets/005d2704-347c-4aa1-b415-d52ab3794c99" />

Then, captured and saved the request:
- List API
<img width="922" height="797" alt="Screenshot 2025-12-10 at 10 39 53 PM" src="https://github.com/user-attachments/assets/2ee3e0e1-06da-442f-b2c7-0dfa8360c04a" />


Next, login a backend user with no permission
<img width="1219" height="744" alt="Screenshot 2025-12-10 at 9 06 12 PM" src="https://github.com/user-attachments/assets/1dada4c4-d907-4477-9773-70dea3ef5816" />

The copy the "Cookie" and "X-Pimcore-Csrf-Token"
<img width="1902" height="971" alt="Screenshot 2025-12-10 at 9 10 47 PM" src="https://github.com/user-attachments/assets/63221682-fa14-429b-8665-fc9dd8bed890" />

After that, pasted the copied "Cookie" and "X-Pimcore-Csrf-Token" to captured request

-List API
![Uploading Screenshot 2025-12-10 at 10.55.23 PM.png…]()


### Impact
Exploitation allows low-privileged users to enumerate all Predefined Properties, exposing internal metadata schemas, default values, and configuration details that may reveal business logic, data classification strategies, or sensitive defaults (e.g., proprietary keys or select options). In a PIM system like Pimcore, this could facilitate reconnaissance for further attacks, such as targeted data manipulation or privilege escalation, leading to unauthorized alterations of asset/object properties. For organizati [...truncated]

---

## R022

**Package:** code.gitea.io/gitea

**Summary:** Gitea Remember-Me Token Theft Not Invalidating Attacker Session

The vulnerability is in the Remember-Me (gitea_incredible) token validation logic, specifically when handling a compromised token (hash mismatch).

The vulnerable function is this one:

https://github.com/go-gitea/gitea/blob/689ace1ce28fd74244b8aa335d9928cdbf6b22f9/services/auth/auth_token.go#L33-L64

### Affected Endpoint
POST `/user/login` (and any endpoint triggering `autoSignIn` via the Remember-Me cookie).

### Description
Gitea implements Remember-Me cookies using a split token design (ID:Hash), [citing the Paragonie secure remember-me guide](https://github.com/go-gitea/gitea/blob/689ace1ce28fd74244b8aa335d9928cdbf6b22f9/services/auth/auth_token.go#L21). When a token is used, its Hash is rotated, but the ID remains the same.

If an attacker steals a user's Remember-Me token and uses it to authenticate, the attacker is issued a new rotated token (same ID, new Hash). When the legitimate user later attempts to use their original token, Gitea correctly detects a hash mismatch for the given ID.

According to the referenced Paragonie specification, this indicates a compromised token, and ALL active remember-me sessions for that user MUST be invalidated. However, Gitea's `CheckAuthToken` function simply returns `ErrAuthTokenInvalidHash`. The calling code (`autoSignIn`) catches this error and deletes the victim's local cookie via `ctx.DeleteSiteCookie`, but fails to delete the compromised token from the database.

As a result, the attacker's active session is never invalidated, and the attacker maintains persistent, indefinite access to the victim's account, entirely defeating the purpose of the split-token security design.

---

## R023

**Package:** ci4-cms-erp/ci4ms

**Summary:** CI4MS: Account Deactivation Module Grants Full Persistent Unauthorized Access for All‑Roles via Improper Session Invalidation (Logic Flaw)

## Summary
### Vulnerability: Improper Session Invalidation on Account Deactivation (Broken Access Control / Logic Flaw)
- This vulnerability is caused by a backend logic flaw that maintains a false trust assumption that already-authenticated users remain trustworthy, even after their accounts are explicitly deactivated. As a result, administrative security actions do not behave as intended, allowing persistent unauthorized access.

### Description
The application fails to immediately revoke active user sessions when an account is deactivated. Due to a logic flaw in the backend design, account state changes are enforced only during authentication (login), not for already-established sessions.

The system implicitly assumes that authenticated users remain trusted for the lifetime of their session. There is no session expiration or account expiration mechanism in place, causing deactivated accounts to retain indefinite access until the user manually logs out. This behavior breaks the intended access control policy and results in persistent unauthorized access, representing a critical security flaw.

### Affected Functionality
- User session management and authentication logic
- Account deactivation mechanism
- All authenticated endpoints, including administrative and content interfaces

### Attack Scenario
- A user logs into the application.
- An administrator deactivates the user account.
- The user remains fully logged in and can continue performing all actions allowed by their role indefinitely, as there is no session expiration.
- The user can continue invoking backend methods, triggering application actions, accessing sensitive interfaces (including user management if permitted), and interacting with the system as if the account were still active.
- Access is only lost if the user manually logs out, which may never occur.

### Impact
- Unauthorized Continued Access: Deactivated users retain full access indefinitely, violating intended access control and expected security behavior.
- Bypass of Administrative Controls: Administrative actions (deactivation) fail to immediately restrict active sessions.
- Logic Flaw Resulting in Broken Behavior: Backend authorization logic relies on a flawed trust assumption that authenticated users remain valid, enforcing account state only at login.
- Full Functional Access Retained: Deactivated users can continue invoking application methods, executing actions, interacting with protected endpoints, and using the system e [...truncated]

---

## R024

**Package:** easybuild-framework

**Summary:** GitHub personal access token leaking into temporary EasyBuild (debug) logs

### Impact

The GitHub Personal Access Token (PAT) used by EasyBuild for the GitHub integration features (like `--new-pr`, `--from-pr`, etc.) is shown in plain text in EasyBuild debug log files.

Scope:

* the log message only appears in the top-level log file, *not* in the individual software installation logs (see https://easybuild.readthedocs.io/en/latest/Logfiles.html);
    - as a consequence, tokens are *not* included in the partial log files that are uploaded into a gist when using `--upload-test-report` in combination with `--from-pr`, nor in the installation logs that are copied to the software installation directories;
* the message is only logged when using `--debug`, so it will not appear when using the default EasyBuild configuration (only info messages are logged by default);
* the log message is triggered via `--from-pr`, but also via various other GitHub integration options like `--new-pr`, `--merge-pr`, `--close-pr`, etc., but usually only appears in the temporary log file that is cleaned up automatically as soon as eb completes successfully;
* you may have several debug log files that include your GitHub token in `/tmp` (or a different location if you've set the `--tmpdir` EasyBuild configuration option) on the systems where you use EasyBuild, but they are located in a subdirectory that is only accessible to your account (permissions set to 700);
* the only way that a log file that may include your token could have been made public is *if you shared it yourself*, for example by copying the contents of the log file into a gist manually, or by sending a log file to someone;
* for log files uploaded to GitHub, your token would be revoked automatically when GitHub notices it;

### Patches

The issue is fixed with the changes in https://github.com/easybuilders/easybuild-framework/pull/3248.

This fix is included in EasyBuild v4.1.2 (released on Mon Mar 16th 2020), and in the `master`+  `develop` branches of the `easybuild-framework` repository since Mon Mar 16th 2020 (see https://github.com/easybuilders/easybuild-framework/pull/3248 and https://github.com/easybuilders/easybuild-framework/pull/3249 resp.).

**Make sure you revoke the existing GitHub tokens you're using with EasyBuild** (via https://github.com/settings/tokens), and install new ones using "`eb --install-github-token --force`" (see also https://easybuild.readthedocs.io/en/latest/Integration_with_GitHub.html#installing-a-github-token-install-github-token).

### Workarounds

* avoid  [...truncated]

---

## R025

**Package:** @better-auth/oauth-provider,better-auth

**Summary:** Better Auth: OAuth refresh-token rotation forks the token family on concurrent redemption

### Am I affected?

Users are affected if all of the following are true:

- Their project depends on `@better-auth/oauth-provider` at a version `>= 1.6.0, < 1.6.11`, or uses the embedded plugin in `better-auth >= 1.4.8-beta.7, < 1.6.0`.
- At least one OAuth client served by their application's authorization server requests the `offline_access` scope, so refresh tokens are minted.
- Concurrent redemption of the same refresh token is reachable: an SPA shares one refresh token across browser tabs without a mutex, a mobile client retries after a transient failure, an attacker who has stolen a refresh token times two requests, or a service worker queues offline requests.

If developer applications do not request `offline_access` for any client, no refresh tokens are minted and they are not exposed.

Fix:

1. Upgrade to `@better-auth/oauth-provider@1.6.11` or later.
2. If developers cannot upgrade, see workarounds below.

### Summary

The OAuth provider's `POST /oauth2/token` endpoint, on the `refresh_token` grant, performs a non-atomic read / validate / revoke / mint sequence on the `oauthRefreshToken` row. Two concurrent requests presenting the same parent refresh token both pass the revocation check before either revoke completes, so each mints a fresh refresh token. The replay-detection branch only fires when `revoked` is already truthy at read time, which is exactly the state concurrent attackers race past. The result is a forked refresh-token family from a single parent token.

### Details

The `adapter.update` predicate on the parent row is keyed on `id` only; it does not include `revoked IS NULL`, so two concurrent updates both succeed (last-write-wins, no error path). The schema does not declare `unique` on `oauthRefreshToken.token`, so concurrent creates do not collide on a unique-key violation either.

RFC 9700 §4.14 (OAuth Security Best Current Practice) prescribes refresh-token family invalidation on detected reuse; this implementation tries to enforce that contract through the `revoked` check, but the check is not atomic with the consumption step. Token rotation issues a new refresh token with each call, so a single stolen refresh token grants indefinite access until the row is revoked or its `refreshTokenExpiresAt` (default 7 days) passes. Rotation refreshes that window each call.

The fix lands an atomic compare-and-swap on the parent row inside the rotation primitive (`UPDATE ... WHERE id = ? AND revoked IS NULL` with a rowcount check), so the l [...truncated]

---

## R026

**Package:** keystone

**Summary:** OpenStack Identity (Keystone) Multiple vulnerabilities in revocation events

The MySQL token driver in OpenStack Identity (Keystone) 2014.1.x before 2014.1.2.1 and Juno before Juno-3 stores timestamps with the incorrect precision, which causes the expiration comparison for tokens to fail and allows remote authenticated users to retain access via an expired token.

---

## R027

**Package:** fastmcp

**Summary:** FastMCP Auth Integration Allows for Confused Deputy Account Takeover

### Summary

FastMCP documentation [covers the scenario](https://gofastmcp.com/integrations/azure) where it is possible to use Entra ID or other providers for authentication. In this context, because Entra ID does not support Dynamic Client Registration (DCR), the FastMCP-hosted MCP server is acting as the authorization provider, as declared in the Protected Resource Metadata (PRM) document hosted on the server.

For example, on a local MCP server, it may be hosted here:

```http
http://localhost:8000/.well-known/oauth-protected-resource
```

And the JSON representation of the PRM document:

```json
{
  "resource": "http://localhost:8000/mcp",
  "authorization_servers": [
    "http://localhost:8000/"
  ],
  "scopes_supported": [
    "User.Read",
    "email",
    "openid",
    "profile"
  ],
  "bearer_methods_supported": [
    "header"
  ]
}
```

Notice that the `authorization_servers` field contains the MCP server itself - it acts as an **OAuth Client** to the downstream authorization server (e.g., Entra ID) and as a **Authorization Server** (AS) to the MCP client.

The FastMCP server also hosts the AS metadata:

```bash
http://localhost:8000/.well-known/oauth-authorization-server
```

With the following content:

```json
{
  "issuer": "http://localhost:8000/",
  "authorization_endpoint": "http://localhost:8000/authorize",
  "token_endpoint": "http://localhost:8000/token",
  "registration_endpoint": "http://localhost:8000/register",
  "scopes_supported": [
    "User.Read",
    "email",
    "openid",
    "profile"
  ],
  "response_types_supported": [
    "code"
  ],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_post"
  ],
  "code_challenge_methods_supported": [
    "S256"
  ]
}
```

All of this confirms that the FastMCP server is, in fact, handling the client-to-server authorization and then delegating the downstream effects (i.e., authorization with Entra ID) to its own redirect logic, with a call like this (as seen through MCP Inspector):

```http
http://localhost:8000/authorize?response_type=code&client_id=fdec0bb8-3423-40d0-aa2a-73de26bf6f93&code_challenge=2a9ZxAEr5NEsKPwFWuEFA1W-kFMXc-02u6qc8aLf_g4&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A6274%2Foauth%2Fcallback%2Fdebug&state=9f23fd47e2b8786b502f116bdbfd6ae3d7d2801167e24fea82f608bb52312bbd&scope=User.Read+email+openid+profile&resource=http%3A%2F%2Flocalhost%3A8000%2Fmcp
```

When us [...truncated]

---

## R028

**Package:** ash_authentication_phoenix

**Summary:** ash_authentication_phoenix has Insufficient Session Expiration

### Impact

Session tokens remain valid on the server after user logout, creating a security gap where:

- Compromised tokens (via XSS, network interception, or device theft) continue to work even after the user logs out
  - The sessions stored in the database still expire, limiting the duration during which this could be exploited
- Users cannot fully invalidate their sessions when logging out from shared or potentially compromised devices 
  - by default, changing one's password *does* invalidate all other sessions, so changing your password as a security measure would have been effective
- May cause compliance issues with security frameworks requiring complete session 
### Patches
Upgrade to version 2.10.0. After upgrading, users must update their AuthController implementation to use the new `clear_session/2` function with their OTP app name. You will be prompted to do so with a compile-time error.

If you do not have the setting `require_token_presence_for_authentication?` set to `true` in the `tokens` section, you will see a separate error:

```
** (Spark.Error.DslError) authentication -> session_identifier:
Must set `authentication.session_identifier` to either `:jti` or `:unsafe`.

...
```

In order to revoke sessions on log out when not storing tokens directly in the session, we must have some unique identifier with which to do so. You should prefer to enable `require_token_presence_for_authentication?` if possible, instead of setting this to `:jti`. Note that whatever you do here, if you did not previously have `require_token_presence_for_authentication?` set to `true`, setting it to `true` *or* setting `authentication.session_identifier` to `:jti` will log out all of your currently authenticated users.

### Workarounds
You can manually revoke tokens in your `logout/2` handler in your auth controller.

---

## R029

**Package:** org.keycloak:keycloak-server

**Summary:** Keycloak has a Time-of-check Time-of-use (TOCTOU) Race Condition

A flaw was found in Keycloak. An authenticated administrator with the `manage-clients` role can exploit a Time-of-check to time-of-use (TOCTOU) vulnerability in the name-based admin role checks. This allows the attacker to escalate their privileges to `realm-admin` for all users within the realm, granting them extensive control over the system. The composite role relationship persists even after the attacker's own permissions are revoked and across system reboots.

---

## R030

**Package:** github.com/openshift-pipelines/pipelines-as-code

**Summary:** Tekton Pipelines-as-Code: Unscoped GitHub App installation token allows unauthorized access to private repositories via remote task resolution

### Impact
When Pipelines-as-Code is configured with a GitHub App installed across multiple repositories, the installation token issued during webhook processing is not scoped to the triggering repository by default. The token retains access to all repositories in the GitHub App installation.

This allows a user with push access to any repository in the installation to craft a PipelineRun with a remote task annotation pointing at a private repository in the same installation:
```
pipelinesascode.tekton.dev/task: "https://github.com/org/private-repo/blob/main/.tekton/secret-task.yaml"
```
Pipelines-as-Code resolves and inlines the remote task using the unscoped token, exposing the contents of the private repository's Tekton definitions. This is a read-only confidentiality breach, no write access is exposed.

### Patches
The fix extracts the repository ID from the webhook payload during initial parsing so that it is available for later use. It then adds a fallback in the client setup path so that when no explicit scoping configuration is present and `ScopeTokenToListOfRepos` returns empty, the token is re-issued scoped to the triggering repository's ID rather than retaining access to the entire installation. The initial token remains unscoped so that the extra-repos lookup can still discover and resolve additional repositories when configured.

The fix is available in v0.48.0. Supported backport releases will be added here after release tags are published.

### Workarounds
Limit the GitHub App installation to only the repositories that require Pipelines-as-Code. Avoid org-wide installations or mixed-trust installations where repositories with different access requirements share the same GitHub App. This restricts the blast radius of the unscoped token to only the repositories that are explicitly selected during App installation.

### Credits
Reported and fixed by the Pipelines-as-Code maintainers.

---

## R031

**Package:** n8n

**Summary:** n8n: Per-Resource OAuth Consent Bypass via Unbound Refresh Token Resource Substitution

## Impact

The OAuth token endpoint bound an authorization code's first access token to the consented resource, but not its refresh token. Refreshing only checked that the requested resource was registered, not that it matched the original grant. An OAuth client approved for one workflow could refresh with a different workflow's URL and get a valid, unapproved token for it. The patch binds refresh tokens to the granted resource and rejects mismatches.

Exploitation requires the attacker to register an OAuth client, convince an authenticated user to approve that client for one known protected resource, and know the URL of a second protected resource that the consenting user is permitted to execute.

## Patches

The issue has been fixed in n8n versions 2.38.1 and 2.37.7. Users should upgrade to this version or later to remediate the vulnerability.

## Workarounds

If upgrading is not immediately possible, administrators should consider the following temporary mitigations:
- Restrict n8n instance access to fully trusted users only.
- Deactivate MCP Trigger, form, and webhook workflows that are protected by the n8n OAuth server if they are not required.
- Audit connected OAuth clients and revoke any that are not recognized or no longer needed.
- Require re-authorization for all existing OAuth clients after upgrading, as previously issued refresh tokens did not store the original resource binding.

These workarounds do not fully remediate the risk and should only be used as short-term mitigation measures.

---

## R032

**Package:** kimai/kimai

**Summary:** Improper Authorization in Kimai Timesheet Restart and Duplicate Allows New Timesheets After Project Access Revocation

### Summary

Kimai 2.56.0 contains an authenticated authorization bypass in the timesheet `restart` and `duplicate` workflows. After a user loses access to a project, the user can still derive a new timesheet from one of their historical entries and create a new record under that now-unauthorized project and activity combination.

This is a permission revocation bypass with persistent write impact. The issue affects both `restart` and `duplicate`, which trust ownership of an old timesheet more than the user's current access to the underlying project, activity, and customer.

### Details

The issue affects the following operations:

- `PATCH /api/timesheets/{id}/restart`
- `PATCH /api/timesheets/{id}/duplicate`

The root cause is that authorization gives too much weight to the fact that the original timesheet belongs to the current user. In `src/Voter/TimesheetVoter.php`, the `*_own_timesheet` branch is evaluated before team-based access checks.

The restart/duplicate capability check also verifies only object visibility, not whether the current user still has team-based access to the referenced objects. 

In `src/API/TimesheetController.php`, the restart flow copies the historical `project` and `activity` into a new candidate timesheet.

The duplicate flow similarly clones the historical record and saves it.

In `src/Timesheet/TimesheetService.php`, creation of a new running entry still relies on `isGranted('start', $timesheet)`.

For historical entries that belong to the current user, this logic can still succeed through the `*_own_timesheet` branch even after project access has been revoked. As a result, normal creation pages correctly stop offering the revoked project, but `restart` and `duplicate` can still create new records under it.

The same weakness also affects the Web duplicate flow because the UI path ultimately calls the same save logic in `src/Controller/TimesheetAbstractController.php`:

*A PoC was provided, but removed for security reasons.*

### Impact

This vulnerability allows a user to keep writing new time entries into a project after project access has been revoked. That undermines administrative access-control changes and can pollute project time tracking, budget calculations, statistics, reports, and invoicing workflows.

Because both `restart` and `duplicate` can reuse historical project/activity bindings, old timesheet records effectively become reusable capability tokens that survive later access-control changes. This is not a UI [...truncated]

---

## R033

**Package:** github.com/ory/fosite

**Summary:** Ory fosite contains Improper Handling of Exceptional Conditions 

### Impact
The `TokenRevocationHandler` ignores errors coming from the storage. This can lead to unexpected 200 status codes indicating successful revocation while the token is still valid. Whether an attacker can use this for her advantage depends on the ability to trigger errors in the store.

### References
[RFC 7009](https://tools.ietf.org/html/rfc7009#section-2.2.1) states that a 503 HTTP code must be returned when the server has a problem.

---

## R034

**Package:** @strapi/strapi

**Summary:** Strapi is vulnerable to Insufficient Session Expiration

Strapi uses JSON Web Tokens (JWT) for authentication. After logout or account deactivation, the JWT is not invalidated, which allows an attacker who has stolen or intercepted the token to freely reuse it until its expiration date (which is set to 30 days by default, but can be changed). The existence of /admin/renew-token endpoint allows anyone to renew near-expiration tokens indefinitely, further increasing the impact of this attack. This issue has been fixed in version 5.24.1.

---

## R035

**Package:** open-webui

**Summary:** Open WebUI: Any authenticated user can cancel another user's chat generation via the chat delete endpoint

## Summary
`DELETE /api/v1/chats/{id}` cancelled a chat's in-flight tasks before it checked whether the caller was allowed to delete that chat. Any authenticated user who knew another user's chat id could therefore abort that user's running model response, title generation or tag generation. The deletion itself was still refused, so the only missing control was on the cancellation side effect.

## Preconditions
Default configuration, no special deployment shape. The attacker needs a normal account with the default `user` role and nothing else: the `chat.delete` permission is not required, and revoking it does not prevent the cancellation. The attacker also needs the victim's chat id, which is returned by the read-only shared-chat endpoint when a chat or a folder has been shared with them - otherwise enumerating the chat id requires guessing the chat id or brute forcing it, and the victim must have a generation running at that moment.

## Impact
A user can repeatedly interrupt another user's generations without any write access to the target chat. Nothing is deleted, modified or disclosed, and the victim can simply regenerate, so the effect is limited to availability of in-flight responses. Because the attacker only needs a chat id, the interruption can be scripted and repeated for as long as the id stays valid.

## Fix
Fixed in https://github.com/open-webui/open-webui/pull/27006, released in 0.11.0. The handler now resolves and authorizes the chat first and only cancels tasks and deletes once the caller is an admin or a permitted owner; an unauthorized caller gets 401 or 404 with no cancellation.

## Root cause
Affected component: `delete_chat_by_id` in `backend/open_webui/routers/chats.py`, serving `DELETE /api/v1/chats/{id}`. Affected setup: every build from 0.9.6 up to and including 0.10.2.

The cancellation was written as a cleanup step for the delete that follows it, and it was placed at the top of the handler so that it would run before the chat row disappeared. That put an unauthenticated-by-ownership side effect ahead of every check in the function: the admin branch, the `chat.delete` permission check, and the owner lookup all ran afterwards, so their outcome could no longer affect whether the tasks were stopped. The dedicated task-stop endpoint already verified ownership before calling the same helper, so the intended ordering existed elsewhere in the codebase.

## Proof of concept
Against a 0.10.2 instance with two accounts, a victim admin and an [...truncated]

---

## R036

**Package:** apache-airflow-providers-fab

**Summary:** Apache Airflow Fab Provider Insufficient Session Expiration vulnerability

Insufficient Session Expiration vulnerability in Apache Airflow Fab Provider.

This issue affects Apache Airflow Fab Provider: before 1.5.2.

When user password has been changed with admin CLI, the sessions for that user have not been cleared, leading to insufficient session expiration, thus logged users could continue to be logged in even after the password was changed. This only happened when the password was changed with CLI. The problem does not happen in case change was done with webserver thus this is different from [CVE-2023-40273](https://github.com/advisories/GHSA-pm87-24wq-r8w9) which was addressed in Apache-Airflow 2.7.0


Users are recommended to upgrade to version 1.5.2, which fixes the issue.

---

## R037

**Package:** keystone

**Summary:** OpenStack Keystone Improper Authentication vulnerability

OpenStack Keystone Folsom (2012.2) does not properly perform revocation checks for Keystone PKI tokens when done through a server, which allows remote attackers to bypass intended access restrictions via a revoked PKI token.

---

## R038

**Package:** github.com/goharbor/harbor

**Summary:** Harbor fails to validate the user permissions when updating project configurations

### Impact
Harbor fails to validate the maintainer role permissions when creating/updating/deleting project configurations - API call:

- PUT /projects/{project_name_or_id}/metadatas/{meta_name}
- POST /projects/{project_name_or_id}/metadatas/{meta_name}
- DELETE /projects/{project_name_or_id}/metadatas/{meta_name}

By sending a request to create/update/delete a metadata with an name that belongs to a project that the currently authenticated and granted to the maintainer role user doesn’t have access to, the attacker could modify configurations in the current project.

BTW: the maintainer role in Harbor was intended for individuals who closely support the project admin in maintaining the project but lack configuration management permissions. However, the maintainer role can utilize the metadata API to circumvent this limitation. It's important to note that any potential attacker must be authenticated and granted a specific project maintainer role to modify configurations, limiting their scope to only that project.


### Patches
Will be fixed in v2.9.5, v2.10.3 and v2.11.0

### Workarounds
There are no workarounds available.

### Credit
Thanks to Ravid Mazon(rmazon@paloaltonetworks.com), Jay Chen (jaychen@paloaltonetworks.com) Palo Alto Networks for reporting this issue.

---

## R039

**Package:** com.amazonaws:aws-dynamodb-encryption-java

**Summary:** Key Caching behavior in the DynamoDB Encryption Client.

### Impact
This advisory concerns users of MostRecentProvider in the DynamoDB Encryption Client with a key provider like AWS Key Management Service that allows for permissions on keys to be modified.

When key usage permissions were changed at the key provider, time-based key reauthorization logic in MostRecentProvider did not reauthorize the use of the key. This created the potential for keys to be used in the DynamoDB Encryption Client after permissions to do so were revoked at the key provider.

### Patches
Fixed as of 1.15.0.  We recommend users to modify their code and adopt `CachingMostRecentProvider`.

### Workarounds
Users who cannot upgrade to use the `CachingMostRecentProvider` can call `clear()` on the cache to manually flush all of its contents. Next use of the key will force a re-validation to occur with the key provider.

---

## R040

**Package:** github.com/cli/go-gh,github.com/cli/go-gh/v2

**Summary:** `auth.TokenForHost` violates GitHub host security boundary when sourcing authentication token within a codespace

### Summary

A security vulnerability has been identified in `go-gh` that could leak authentication tokens intended for GitHub hosts to non-GitHub hosts when within a codespace.

### Details

`go-gh` sources authentication tokens from different environment variables depending on the host involved:

- `GITHUB_TOKEN`, `GH_TOKEN` for GitHub.com and ghe.com
- `GITHUB_ENTERPRISE_TOKEN`, `GH_ENTERPRISE_TOKEN` for GitHub Enterprise Server

Prior to `2.11.1`, `auth.TokenForHost` could source a token from the `GITHUB_TOKEN` environment variable for a host other than GitHub.com or ghe.com when [within a codespace](https://github.com/cli/go-gh/blob/71770357e0cb12867d3e3e288854c0aa09d440b7/pkg/auth/auth.go#L73-L77).

In `2.11.1`, `auth.TokenForHost` will only source a token from the `GITHUB_TOKEN` environment variable for GitHub.com or ghe.com hosts.

### Impact

Successful exploitation could send authentication token to an unintended host. 

### Remediation and mitigation

1. Upgrade `go-gh` to `2.11.1`
2. Advise extension users to regenerate authentication tokens:
    - [Personal access tokens](https://docs.github.com/en/enterprise-cloud@latest/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
    - [GitHub CLI OAuth app](https://docs.github.com/en/apps/using-github-apps/reviewing-and-revoking-authorization-of-github-apps#reviewing-your-authorized-github-apps)
3. Advise extension users to review their personal [security log](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log) and any relevant [audit logs](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/identifying-audit-log-events-performed-by-an-access-token) for actions associated with their account or enterprise


---

## R041

**Package:** magento/community-edition

**Summary:** Magento Broken authentication and session managememt

Insecure authentication and session management vulnerability exists in Magento 2.2 prior to 2.2.10, Magento 2.3 prior to 2.3.3 or 2.3.2-p1. An unauthenticated user can append arbitrary session id that will not be invalidated by subsequent authentication.

---

## R042

**Package:** io.netty:netty-codec-http

**Summary:** Netty: HTTP Request Smuggling via Chunked Extension Quoted-String Parsing

## Summary

Netty incorrectly parses quoted strings in HTTP/1.1 chunked transfer encoding extension values, enabling request smuggling attacks.

## Background

This vulnerability is a new variant discovered during research into the "Funky Chunks" HTTP request smuggling techniques:

- <https://w4ke.info/2025/06/18/funky-chunks.html>
- <https://w4ke.info/2025/10/29/funky-chunks-2.html>

The original research tested various chunk extension parsing differentials but did not cover quoted-string handling within extension values.

## Technical Details

**RFC 9110 Section 7.1.1** defines chunked transfer encoding:

```
chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
chunk-ext-val = token / quoted-string
```

**RFC 9110 Section 5.6.4** defines quoted-string:

```
quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
```

Critically, the allowed character ranges within a quoted-string are:

```
qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
```

CR (`%x0D`) and LF (`%x0A`) bytes fall outside all of these ranges and are therefore **not permitted** inside chunk extensions—whether quoted or unquoted. A strictly compliant parser should reject any request containing CR or LF bytes before the actual line terminator within a chunk extension with a `400 Bad Request` response (as Squid does, for example).

## Vulnerability

Netty terminates chunk header parsing at `\r\n` inside quoted strings instead of rejecting the request as malformed. This creates a parsing differential between Netty and RFC-compliant parsers, which can be exploited for request smuggling.

**Expected behavior (RFC-compliant):**
A request containing CR/LF bytes within a chunk extension value should be rejected outright as invalid.

**Actual behavior (Netty):**

```
Chunk: 1;a="value
            ^^^^^ parsing terminates here at \r\n (INCORRECT)
Body: here"... is treated as body or the beginning of a subsequent request
```

The root cause is that Netty does not validate that CR/LF bytes are forbidden inside chunk extensions before the terminating CRLF. Rather than attempting to parse through quoted strings, the appropriate fix is to reject such requests entirely.

## Proof of Concept

```python
#!/usr/bin/env python3
import socket

payload = (
    b"POST / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b'1;a="\r\n'
     [...truncated]

---

## R043

**Package:** UmbracoForms

**Summary:** UmbracoForms Vulnerable to Remote Code Execution via Untrusted WSDL Compilation in Dynamic SOAP Client Generation

### Impact
Within Umbraco Forms, configuring a malicious URL on the Webservice data source can result in Remote Code Execution. This affects all Umbraco Forms versions running on .NET Framework (up to and including version 8).

### Patches
The affected Umbraco Forms versions are all End-of-Life (EOL) and not supported anymore, hence no patches will be released. Upgrading to any of the currently supported versions (v13, v16 or v17) is recommended.

### Workarounds
If none of the configured Forms data sources uses the Webservice type, it can be safely excluded by adding the following code to the application. This will completely remove the option to select/use this data source within the Backoffice and thereby mitigate the vulnerability.

```c#
using Umbraco.Core.Composing;
using Umbraco.Forms.Core.Providers;
using Umbraco.Forms.Core.Providers.DatasourceTypes;

internal sealed class RemoveFormsWebserviceDataSourceTypeComposer : IUserComposer
{
    public void Compose(Composition composition)
        => composition.WithCollectionBuilder<DataSourceCollectionBuilder>().Exclude<Webservice>();
}
```

Any Webservice data source that is configured and still in use should be replaced with a custom implementation instead, before applying the above code. If this is not feasible, the vulnerability can be minimized by revoking the 'Manage Data Sources' from any non-administrator user and/or inheriting from the default `Umbraco.Forms.Core.Providers.DatasourceTypes.Webservice` class and overriding the `ValidateSettings()` method to ensure only trusted URLs can be used.

### References
When upgrading to a supported version, please take the Forms [version specific upgrade notes](https://docs.umbraco.com/umbraco-forms/13.latest/upgrading/version-specific) into account and check the [CMS upgrade documentation](https://docs.umbraco.com/umbraco-cms/13.latest/fundamentals/setup/upgrading). Content and schema can also be migrated straight to the latest version using [Deploy export/import with migrations](https://docs.umbraco.com/umbraco-deploy/13.latest/deployment-workflow/import-export).

Implementation details on data sources are not extensively documented, but they follow the general Forms [provider model](https://docs.umbraco.com/umbraco-forms/13.latest/developer/extending/adding-a-type) and inherit from `Umbraco.Forms.Core.FormDataSource`.

A special thanks to Piotr Bazydlo (@chudyPB) of watchTowr for finding and disclosing this vulnerability

---

## R044

**Package:** wwbn/avideo

**Summary:** AVideo: Arbitrary Stripe Subscription Cancellation via Debug Endpoint and retrieveSubscriptions() Bug

## Summary

The StripeYPT plugin includes a `test.php` debug endpoint that is accessible to any logged-in user, not just administrators. This endpoint processes Stripe webhook-style payloads and triggers subscription operations, including cancellation. Due to a bug in the `retrieveSubscriptions()` method that cancels subscriptions instead of merely retrieving them, any authenticated user can cancel arbitrary Stripe subscriptions by providing a subscription ID.

## Details

At `plugin/StripeYPT/test.php:4`, the endpoint checks only for a logged-in user, not for admin privileges:

```php
if (!User::isLogged())
```

At lines 27-29, the endpoint accepts a JSON payload from the request and processes it through the Stripe metadata handler:

```php
$obj = StripeYPT::getMetadataOrFromSubscription(json_decode($_REQUEST['payload']));
```

The call chain proceeds as follows:
- `test.php` calls `getMetadataOrFromSubscription()`
- Which calls `getSubscriptionId()` to extract the subscription ID
- Which calls `retrieveSubscriptions()` to interact with the Stripe API

At `StripeYPT.php:933`, the `retrieveSubscriptions()` method contains a critical bug where it cancels the subscription instead of just retrieving it:

```php
$response = $sub->cancel();
```

This same bug also affects the production webhook processing path via `processSubscriptionIPN()`, meaning both the debug endpoint and the live webhook handler can trigger unintended cancellations.

## Proof of Concept

1. Log in as any regular (non-admin) user and obtain a session cookie.

2. Send a crafted payload to the test endpoint with a target subscription ID:

```bash
curl -b "PHPSESSID=USER_SESSION" \
  "https://your-avideo-instance.com/plugin/StripeYPT/test.php" \
  -d 'payload={"data":{"object":{"id":"sub_TARGET_SUBSCRIPTION_ID","customer":"cus_CUSTOMER_ID"}}}'
```

3. The endpoint processes the payload, calls `retrieveSubscriptions()`, and the subscription is cancelled via the Stripe API.

4. To enumerate subscription IDs, check if the application exposes them through other endpoints or use predictable patterns:

```bash
# Check user subscription details if accessible
curl -b "PHPSESSID=USER_SESSION" \
  "https://your-avideo-instance.com/plugin/StripeYPT/listSubscriptions.php"
```

5. The Stripe subscription is now cancelled. The affected user loses access to their paid features.

## Impact

Any logged-in user can cancel arbitrary Stripe subscriptions belonging to other users. This causes direct financial dam [...truncated]

---

## R045

**Package:** github.com/apernet/hysteria/core/v2

**Summary:** Hysteria has an authenticated UDP ACL bypass that enables localhost and private-network UDP SSRF

## Summary

Hysteria's UDP relay treats the destination address as packet-scoped, but ACL and outbound policy are applied only once when a new UDP session is created. After an authenticated client opens a UDP session using an allowed first destination, later packets in the same `Session ID` can be sent to different destinations without re-running ACL evaluation.

This allows an authenticated user to bypass server-side UDP ACL rules and reach localhost or RFC1918/private-network UDP services from the server's network perspective, even when those destinations are explicitly rejected by ACL.

Verified on current HEAD at commit `64c396385631579598cc29d5561bff98c439772f`.

## Why this is a security issue

This report is not based on the assumption that one UDP session must be bound to one destination. The protocol and official client both support per-packet destinations:

- `PROTOCOL.md:93-107` defines each `UDPMessage` as carrying its own `Addr` field.
- `core/client/udp.go:52-62` exposes `Send(data, addr)`, allowing the same UDP session to send to arbitrary addresses.

The problem is that the security-relevant destination is packet-scoped, while ACL and outbound authorization are cached at session scope.

This is also not a `RequestHook`-bypass claim. I understand `RequestHook` is first-packet-oriented. The broader issue is that operator-configured ACL policy intended to block UDP destinations is not enforced on later packets within the same session.

Because the ACL documentation is presented as the mechanism for handling or blocking client requests, and includes examples of denying `udp/443` and private network CIDRs, operators can reasonably rely on ACL as a UDP egress security boundary. This boundary can currently be bypassed by reusing a previously authorized UDP session.

## Root cause

The relevant flow appears to be:

- `core/server/udp.go:280-299`: when a new session is created, the first destination is passed through `m.io.Hook(...)`, logged, and then `m.io.UDP(addr)` is called once to create the outbound UDP connection.
- `core/server/server.go:397-398`: `m.io.UDP(addr)` delegates to `io.Outbound.UDP(reqAddr)`.
- `app/cmd/server.go:1187-1190`: resolver, ACL, and actual outbounds are intentionally chained through the `Outbound` interface.
- `core/server/udp.go:125`: the initial outbound connection is created only from the first packet via `DialFunc(firstMsg.Addr, firstMsg.Data)`.
- `core/server/udp.go:92-111`: later packets in the same session take  [...truncated]

---

## R046

**Package:** github.com/pocketbase/pocketbase

**Summary:** PocketBase vulnerable to account pre-hijacking via OAuth2 unverfied->verified autolinking upgrade

A pre-hijacking issue was discovered with the OAuth2 autolinking by [Alardiians](https://github.com/Alardiians).

In some situations, if an attacker knows the email address of the victim they can create and link an **unverified** PocketBase user in advance by authenticating with one of the OAuth2 app providers, e.g. "A". When the victim gets invited or decides to sign up to your app on their own with provider "B" _(PocketBase OAuth2 auth requires to be with a different provider because we don't allow multiple OAuth2 accounts from the same provider to be associated to a single PocketBase user)_, the user created previously by the attacker will be autolinked, upgraded to **"verified"** and its old password reset.

The upgrade flow operates within the expectations but the problem is that I forgot to clear the previous OAuth2 link(s) leaving the attacker to still have access to the initially created user.

Or in other words, the vulnerability is similar to the [mixed password + OAuth2 auth pre-hijacking issue](https://github.com/pocketbase/pocketbase/security/advisories/GHSA-m93w-4fxv-r35v) that we had in the past but with a slightly different angle.

So with that in mind, and to avoid introducing breaking changes to the auth flows, a new fix was applied that automatically deletes all such pre-existing OAuth2 links on "unverified" to "verified" upgrades.

**While the vulnerability requires some prerequisites, it is considered severe and it is strongly recommended to upgrade to v0.37.4 _(or to v0.22.42 if you are using an older <v0.23.0 release)_.**

---

## R047

**Package:** github.com/pterodactyl/wings,pterodactyl/panel

**Summary:** Pterodactyl Panel's SFTP sessions remain active after user account deletion or password change

### Summary
Deleting a user account with SFTP access or changing the user's password does not immediately terminate existing SFTP sessions, allowing continued filesystem access after credentials are revoked.
This can result in unintended and unauthorized access to server files even after administrators believe access has been fully invalidated.


### Details
When a user with SFTP access is deleted from the Pterodactyl Panel or when the user's password is changed while one or more SFTP connections are active, those existing connections remain fully functional.

Neither account deletion nor password change invalidates the authentication state of already-established SFTP sessions. As a result, the active SFTP connection pool continues to allow read and write operations until the client disconnects or the session times out.

This behavior occurs even when the password is changed by an administrator through the panel, meaning credential rotation does not revoke active access.

This suggests that active SFTP sessions are not tracked or forcefully terminated on credential revocation events. This effectively prevents administrators from responding to credential compromise incidents in real time.


### PoC
Scenario 1: Account deletion
1. Create a user with SFTP access to a server.
2. Connect to the server via SFTP using any SFTP client (e.g. sftp, FileZilla).
3. Keep the SFTP session open and active.
4. Delete the user account from the Pterodactyl Panel.
5. Continue performing file operations through the already-established SFTP connection.

Result:
The SFTP session remains active and usable despite the user account being deleted.

Scenario 2: Password change
1. Create a user with SFTP access to a server.
2. Establish an active SFTP connection.
3. Change the user's password (including via administrator panel).
4. Continue performing file operations using the existing SFTP connection.

Result:
The SFTP session remains active and usable even after the password has been changed.


### Impact
This issue prevents immediate revocation of compromised credentials. Vulnerability type: Access control / session invalidation issue

Impacted parties:

1. Server administrators
2. Hosting providers using Pterodactyl Panel

Security impact:

Deleted users may retain filesystem access longer than intended, which can lead to:

1. Unauthorized data access
2. Data modification or deletion
3. Compliance and security policy violations

---

## R048

**Package:** github.com/grafana/grafana

**Summary:** Grafana: Users can generate Service Account tokens after permissions removal

When a user's access to mint tokens for a service account is revoked, it is sometimes still possible to do so for a few seconds after the event. The user will eventually lose access to do this.

---

## R049

**Package:** sillytavern

**Summary:** SillyTavern: Existing sessions are not invalidated after password change, allowing session reuse and account takeover

### Summary
Changing a user’s password does not invalidate existing sessions, allowing an attacker with a stolen cookie to retain access even after the victim resets their password.

### Details
SillyTavern relies on cookie-session for authentication, storing all session data (user handle, permissions) in a signed cookie. The endpoints POST /api/users/change-password and POST /api/users/recover-step2 only update the password hash in the database but do not expire current sessions. Because the session is stateless and stored entirely in the client cookie, there is no server-side mechanism to revoke a token once issued.

### PoC
1.Log into the same SillyTavern account from two different browsers (e.g., Chrome and Firefox private mode).
2.In Chrome, change the account password under User Settings → Change Password.
3.In Firefox, refresh the page or perform a protected action (e.g., view API keys).
4.Expected: Firefox session should be invalidated and ask for login.
5.Actual: Firefox remains fully authenticated, able to perform all actions as the targeted user.

### Impact
An attacker who obtains a valid session cookie (via XSS, MITM, physical access, etc.) can continue using it indefinitely, even after the legitimate user changes their password.
This nullifies the most common recovery measure against session theft.
The default cookie lifespan is 400 days, giving an attacker a very long exploitation window.

### Resolution
A fix was released in the version 1.18.0, invalidating a session cookie on account password change.

---

## R050

**Package:** com.vaadin:vaadin-bom

**Summary:** Server session is not invalidated when logout() helper method of Authentication module is used in Vaadin 18-19

`Authentication.logout()` helper in `com.vaadin:flow-client` versions 5.0.0 prior to 6.0.0 (Vaadin 18), and 6.0.0 through 6.0.4 (Vaadin 19.0.0 through 19.0.3) uses incorrect HTTP method, which, in combination with Spring Security CSRF protection, allows local attackers to access Fusion endpoints after the user attempted to log out.

- https://vaadin.com/security/cve-2021-31408

---

## R051

**Package:** openclaw

**Summary:** OpenClaw: Slack and Zalo webhook secrets could remain active after secrets.reload

### Summary

Slack and Zalo webhook secrets could remain active after secrets.reload. In affected versions, a caller with an old webhook secret during the stale-secret window could keep accepting the previous secret after `secrets.reload`.

This advisory is scoped to the named feature and configuration. It does not change OpenClaw's trusted-operator model: authenticated Gateway operators, installed plugins, and intentional local execution surfaces remain trusted unless a separate policy, approval, allowlist, sandbox, or auth boundary is crossed.

### Impact

When the affected feature is enabled and reachable, this could deliver webhook events briefly after the operator expected revocation. Practical impact depends on the operator's configuration and whether lower-trust input can reach that path.

### Patched Versions

The first stable patched version is `2026.4.22`.

### Mitigations

restart the affected channel runtime after rotating webhook secrets until patched. As general hardening, keep channel and tool allowlists narrow, avoid sharing one Gateway between mutually untrusted users, and disable the affected feature when it is not needed.

---

## R052

**Package:** weblate

**Summary:** Weblate Doesn't Invalidate API Token on Password Change

### Impact
When a user changes their password, browser sessions are correctly invalidated via `cycle_session_keys()`, but DRF API tokens (`wlu_*` prefix) stored in `authtoken_token` are not revoked.

### Patches
* https://github.com/WeblateOrg/weblate/pull/19057

### Resources
Weblate thanks Sang Yu Jeon for reporting this via GitHub.

---

## R053

**Package:** org.graylog2:graylog2-server

**Summary:** Graylog token revocation endpoint allows authenticated users to delete other users’ access tokens

### Impact

Graylog contains an insecure direct object reference (IDOR) vulnerability in the token revocation endpoint. An authenticated user can delete access tokens belonging to other users, including service account tokens and administrator tokens, if they know or can guess a valid token identifier.

The issue does not expose token contents, but it allows unauthorized token deletion, leading to integrity impact and potential availability impact for access token based integrations.

### Patches

The issue has been fixed in the following Graylog versions: `6.3.12`, `7.0.7`, `7.1.2`. Users should upgrade to one of these versions or above to remediate the vulnerability.

Graylog Cloud has already been patched.

### Workarounds

There are no feasible workarounds for this issue. Upgrading to a patched version is recommended.

Customers using Graylog Enterprise or Security can review the audit log[^1] for suspicious activity. Audit log lines for successful token deletions begin with `access token deleted from user`. 

### Credits

Thanks to [michaelddickenson](https://github.com/michaelddickenson) and [sreelim](https://github.com/sreelim) for reporting.


[^1]: https://go2docs.graylog.org/current/interacting_with_your_log_data/audit_log.html

---

## R054

**Package:** pterodactyl/panel

**Summary:** Insufficient Session Expiration in Pterodactyl API

### Impact
A vulnerability exists in Pterodactyl Panel `<= 1.6.6` that could allow a malicious attacker that compromises an API key to generate an authenticated user session that is not revoked when the API key is deleted, thus allowing the malicious user to remain logged in as the user the key belonged to.

It is important to note that **a malicious user must first compromise an existing API key for a user to exploit this issue**. It cannot be exploited by chance, and requires a coordinated attack against an individual account using a known API key.

### Patches
This issue has been addressed in the `v1.7.0` release of Pterodactyl Panel.

### Workarounds
Those not wishing to upgrade may apply the change below:

```diff
diff --git a/app/Http/Middleware/Api/AuthenticateKey.php b/app/Http/Middleware/Api/AuthenticateKey.php
index eb25dac6..857bfab2 100644
--- a/app/Http/Middleware/Api/AuthenticateKey.php
+++ b/app/Http/Middleware/Api/AuthenticateKey.php
@@ -70,7 +70,7 @@ class AuthenticateKey
         } else {
             $model = $this->authenticateApiKey($request->bearerToken(), $keyType);

-            $this->auth->guard()->loginUsingId($model->user_id);
+            $this->auth->guard()->onceUsingId($model->user_id);
         }
```

### For more information
If you have any questions or comments about this advisory please reach out to `Tactical Fish#8008` on [Discord](https://discord.gg/pterodactyl) or email `dane@pterodactyl.io`.


---

## R055

**Package:** admidio/admidio

**Summary:** Insufficient Session Expiration in Admidio

Admidio prior to version 4.1.9 is vulnerable to insufficient session expiration. In vulnerable versions, changing the password in one session does not terminate sessions logged in with the old password, which could lead to unauthorized actors maintaining access to an account.

---

## R056

**Package:** admidio/admidio

**Summary:** Admidio is Missing CSRF Validation on Role Delete, Activate, and Deactivate Actions

## Summary

The `delete`, `activate`, and `deactivate` modes in `modules/groups-roles/groups_roles.php` perform destructive state changes on organizational roles but never validate an anti-CSRF token. The client-side UI passes a CSRF token to `callUrlHideElement()`, which includes it in the POST body, but the server-side handlers ignore `$_POST["adm_csrf_token"]` entirely for these three modes. An attacker who can discover a role UUID (visible in the public `cards` view when the module is publicly accessible) can embed a forged POST form on any external page and trick any user with the `rol_assign_roles` right into deleting or toggling roles for the organization. Role deletion is permanent and cascades to all memberships, event associations, and rights data.

## Details

### CSRF Token Is Sent but Never Validated

File: `D:/bugcrowd/admidio/repo/modules/groups-roles/groups_roles.php`, lines 150-173

The `save` mode (lines 143-148) is CSRF-protected via `RolesService::save()` which calls `getFormObject($_POST["adm_csrf_token"])->validate()`. The `delete`, `activate`, and `deactivate` modes receive no equivalent protection:

```php
case 'delete':
    // delete role from database
    $role = new Role($gDb);
    $role->readDataByUuid($getRoleUUID);
    if ($role->delete()) {
        echo json_encode(array('status' => 'success'));
    }
    break;

case 'activate':
    // set role active
    $role = new Role($gDb);
    $role->readDataByUuid($getRoleUUID);
    $role->activate();
    echo 'done';
    break;

case 'deactivate':
    // set role inactive
    $role = new Role($gDb);
    $role->readDataByUuid($getRoleUUID);
    $role->deactivate();
    echo 'done';
    break;
```

The only input validated is `$getRoleUUID` at line 41, checked as a `'uuid'` type. This prevents SQL injection but provides no CSRF protection.

### Client-Side UI Passes Token; Server Ignores It

File: `D:/bugcrowd/admidio/repo/system/js/common_functions.js`, lines 101-129

The presenter embeds the CSRF token into the JavaScript `callUrlHideElement()` call (GroupsRolesPresenter.php line 131). The function sends it in an AJAX POST body:

```javascript
function callUrlHideElement(elementId, url, csrfToken, callback) {
    $.post(url, {
        "adm_csrf_token": csrfToken,  // sent in POST body
        "uuid": elementId
    }, function(data) { ... });
}
```

The server-side handler reads `mode` from `$_GET` but never reads or validates `$_POST["adm_csrf_token"]` for `delete`, `activate`, or `d [...truncated]

---

## R057

**Package:** nats

**Summary:** Client TLS credentials sent raw to server in npm package nats

Nats is a Node.js client for the NATS messaging system.

## Problem Description

_Preview versions_ of two NPM packages and one Deno package from the NATS project contain an information disclosure flaw, leaking options to the NATS server; for one package, this includes TLS private credentials.

The _connection_ configuration options in these JavaScript-based implementations were fully serialized and sent to the server in the client's `CONNECT` message, immediately after TLS establishment.

The nats.js client supports Mutual TLS and the credentials for the TLS client key are included in the connection configuration options; disclosure of the client's TLS private key to the server has been observed.

Most authentication mechanisms are handled after connection, instead of as part of connection, so other authentication mechanisms are unaffected.
For clarity: NATS account NKey authentication **is NOT affected**.

Neither the nats.ws nor the nats.deno clients support Mutual TLS: the affected versions listed below are those where the logic flaw is
present.  We are including the nats.ws and nats.deno versions out of an abundance of caution, as library maintainers, but rate as minimal the likelihood of applications leaking sensitive data.


## Affected versions

### Security impact

* NPM package nats.js:
  + **mainline is unaffected**
  + beta branch is vulnerable from 2.0.0-201, fixed in 2.0.0-209

### Logic flaw

* NPM package nats.ws:
  + status: preview
  + flawed from 1.0.0-85, fixed in 1.0.0-111

* Deno repository https://github.com/nats-io/nats.deno
  + status: preview
  + flawed in all git tags prior to fix
  + fixed with git tag v1.0.0-9


## Impact

For deployments using TLS client certificates (for mutual TLS), private key material for TLS is leaked from the client application to the
server.  If the server is untrusted (run by a third party), or if the client application also disables TLS verification (and so the true identity of the server is unverifiable) then authentication credentials are leaked.

## Workaround

*None*

## Solution

Upgrade your package dependencies to fixed versions, and then reissue any TLS client credentials (with new keys, not just new certificates) and revoke the old ones.

---

## R058

**Package:** @paperclipai/server

**Summary:** Paperclip: Cross-tenant agent API token minting via missing assertCompanyAccess on /api/agents/:id/keys

<img width="7007" height="950" alt="01-setup" src="https://github.com/user-attachments/assets/1596b8d1-8de5-4c21-b1d2-2db41b568d7e" />

> Isolated paperclip instance running in authenticated mode (default config)
> on a clean Docker image matching commit b649bd4 (2026.411.0-canary.8, post
> the 2026.410.0 patch). This advisory was verified on an unmodified build.

### Summary

`POST /api/agents/:id/keys`, `GET /api/agents/:id/keys`, and
`DELETE /api/agents/:id/keys/:keyId` (`server/src/routes/agents.ts`
lines 2050-2087) only call `assertBoard` to authorize the caller. They never
call `assertCompanyAccess` and never verify that the caller is a member of the
company that owns the target agent.

Any authenticated board user (including a freshly signed-up account with zero
company memberships and no `instance_admin` role) can mint a plaintext
`pcp_*` agent API token for any agent in any company on the instance. The
minted token is bound to the **victim** agent's `companyId` server-side, so
every downstream `assertCompanyAccess` check on that token authorizes
operations inside the victim tenant.

This is a pure authorization bypass on the core tenancy boundary. It is
distinct from GHSA-68qg-g8mg-6pr7 (the unauth import → RCE chain disclosed in
2026.410.0): that advisory fixed one handler, this report is a different
handler with the same class of mistake that the 2026.410.0 patch did not
cover.

### Root Cause

`server/src/routes/agents.ts`, lines 2050-2087:

```ts
router.get("/agents/:id/keys", async (req, res) => {
  assertBoard(req);                             // <-- no assertCompanyAccess
  const id = req.params.id as string;
  const keys = await svc.listKeys(id);
  res.json(keys);
});

router.post("/agents/:id/keys", validate(createAgentKeySchema), async (req, res) => {
  assertBoard(req);                             // <-- no assertCompanyAccess
  const id = req.params.id as string;
  const key = await svc.createApiKey(id, req.body.name);
  ...
  res.status(201).json(key);                    // returns plaintext `token`
});

router.delete("/agents/:id/keys/:keyId", async (req, res) => {
  assertBoard(req);                             // <-- no assertCompanyAccess
  const keyId = req.params.keyId as string;
  const revoked = await svc.revokeKey(keyId);
  ...
});
```

Compare the handler 12 lines below, `router.post("/agents/:id/wakeup")`,
which shows the correct pattern: it fetches the agent, then calls
`assertCompanyAccess(req, agent.companyId)`. The thre [...truncated]

---

## R059

**Package:** mantisbt/mantisbt

**Summary:** MantisBT: Bugnote Revision Page Leaks Private Issue Metadata After Issue Access Is Revoked

MantisBT allows a bugnote author to access the note's Revisions page after losing access to the parent private issue.

### Impact
Disclosure of the private Issue's Id and Summary. The bugnote full revision body remains secure.

### Patches
- 71df1f67e05b2050cd4bd87839e6cc13747cf03f

### Workarounds
None

### Credits 
Thanks to Vishal Shukla for discovering and responsibly reporting the issue.

---

## R060

**Package:** renovate

**Summary:** Child processes spawned by Renovate incorrectly have full access to environment variables

When Renovate spawns child processes, their access to environment variables is filtered to an allowlist, to prevent unauthorized access to privileged credentials that the Renovate process has access to.

Since [42.68.1](https://github.com/renovatebot/renovate/releases/tag/42.68.1) (2025-12-30), this filtering had been **inadvertently removed**, and so any child processes spawned from these versions will have had access to any environment variables that Renovate has access to.

This could lead to [insider attackers](https://docs.renovatebot.com/security-and-permissions/#execution-of-code-insider-attack) and [outside attackers](https://docs.renovatebot.com/security-and-permissions/#execution-of-code-outsider-attack) being able to exflitrate secrets from the Renovate deployment.

It is recommended to rotate (+ revoke) any credentials that Renovate has access to, in case any spawned child processes have attempted to exfiltrate any secrets.

## Impact

Child processes spawned by Renovate (i.e. `npm install`, anything defined in [`postUpgradeTasks`](https://docs.renovatebot.com/configuration-options/#postupgradetasks) or [`postUpdateOptions`](https://docs.renovatebot.com/configuration-options/#postupdateoptions)) will have full access to the environment variables that the Renovate process has. 

This could lead to [insider attackers](https://docs.renovatebot.com/security-and-permissions/#execution-of-code-insider-attack) and [outside attackers](https://docs.renovatebot.com/security-and-permissions/#execution-of-code-outsider-attack) being able to exflitrate secrets from the Renovate deployment.

## Patches

This is patched in [42.96.3](https://github.com/renovatebot/renovate/releases/tag/42.96.3) and [43.4.4](https://github.com/renovatebot/renovate/releases/tag/43.4.4).

## Workarounds

There are no workarounds, other than upgrading your Renovate version.

## Why did this happen?

As part of work towards https://github.com/renovatebot/renovate/security/advisories/GHSA-pfq2-hh62-7m96, one of the [preparatory changes](https://github.com/renovatebot/renovate/pull/40212) we made was moving to [`execa`](https://www.npmjs.com/package/execa).

One of the default behaviours of `execa` is to [extend the process' environment variables with any new ones](https://github.com/sindresorhus/execa/tree/v8.0.1?tab=readme-ov-file#extendenv), rather than override them.

This was missed in code review, which meant that since this version, the full environment variables have been pro [...truncated]

---

## R061

**Package:** WWBN/AVideo

**Summary:** WWBN AVideo: Stored XSS via Hostile YouTube Video Title in AVideo YouTubeAPI Gallery Section

# Stored XSS via Hostile YouTube Video Title in AVideo YouTubeAPI Gallery Section

## Summary

A stored Cross-Site Scripting vulnerability (CWE-79; chained CWE-829, Inclusion of Functionality from Untrusted Control Sphere) in the AVideo YouTubeAPI plugin renders the `snippet.title` field returned by the YouTube Data API into the homepage gallery markup with no HTML encoding. The title is set by the YouTube video uploader (anyone in the world) and is treated by AVideo as trusted content. A YouTube uploader who controls a video matching the operator's configured query injects HTML into the AVideo homepage by setting their video's title to a JavaScript-bearing string; the payload then executes in the browser of every visitor who loads any page that renders the gallery.

## Details

`plugin/YouTubeAPI/YouTubeAPI.php::listVideos()` fetches search results from the YouTube Data API and stores the `snippet.title` field unchanged inside a `YPTvideoObject`:

```php
// plugin/YouTubeAPI/YouTubeAPI.php (listVideos excerpt)
$searchResponse = $youtube->search->listSearch(
    'snippet,contentDetails,statistics', $options
);
foreach ($searchResponse['items'] as $searchResult) {
    $vid = new YPTvideoObject(
        $searchResult["id"]["videoId"],
        $searchResult['snippet']["title"],          // uploader-controlled
        $searchResult['snippet']["description"],
        $searchResult['snippet']["thumbnails"]["high"]["url"],
        $searchResult['snippet']["channelTitle"],
        "https://www.youtube.com/embed/{$searchResult['id']['videoId']}"
    );
    $object->videos[] = $vid;
}
```

`plugin/YouTubeAPI/gallerySection.php` then renders the title into three HTML contexts inside each gallery card. Four reflection sites total, three of them completely unprotected:

```php
// plugin/YouTubeAPI/gallerySection.php (foreach body)
$youtubeTitle = $video->title;
...
<a class="evideo" href="<?php echo $youtubeEmbedLink; ?>" title="<?php echo $youtubeTitle; ?>">          <!-- (i) attribute -->
    <img src="<?php echo $youtubeThumbs; ?>" alt="<?php echo str_replace('"', '', $youtubeTitle); ?>" ... />  <!-- (ii) attribute, partial -->
</a>
<a class="h6 evideo" href="<?php echo $youtubeEmbedLink; ?>" title="<?php echo $youtubeTitle; ?>">       <!-- (iii) attribute -->
    <h2><?php echo $youtubeTitle; ?></h2>                                                              <!-- (iv) element body -->
</a>
```

Sites (i), (iii), and (iv) call no encoder. Site (ii) applies `str_re [...truncated]

---

## R062

**Package:** code.gitea.io/gitea

**Summary:** Gitea: Improper authorization on OAuth sign-in callback silently re-enables administrator-disabled accounts

### Summary

The OAuth2 sign-in callback in Gitea 1.26.1 unconditionally re-enables a locally-disabled account whenever the user authenticates through a linked external identity provider, silently undoing any administrator-initiated `Disable Account` action and issuing a fresh authenticated session in the same response. Once a user has linked any external IdP, the administrator's disable toggle becomes non-binding — the user can re-enable themselves on demand by completing one OAuth callback, regaining full read and write access to their repositories, organizations, and access tokens.

### Details

Improper Authorization is present on the `code` and `state` parameters of the `/user/oauth2/{source-name}/callback` endpoint in Gitea version 1.26.1. The handler `routers/web/auth/oauth.go::handleOAuth2SignIn` reads the local user's `IsActive` flag at lines 350-352 and, when it is `false`, sets `opts.IsActive = optional.Some(true)` before calling `user_service.UpdateUser` and immediately establishing a session. The active-state precondition that the request middleware `routers/web/web.go::verifyAuthWithOptions` enforces for every other request is therefore evaluated against the freshly-flipped row on the next request, so a site administrator's "disable user" action is silently undone the next time the user authenticates through any linked external identity provider.

The root cause is that the callback path treats the local `IsActive` flag as stale bookkeeping to reconcile against the external identity, rather than as an authoritative administrative override. The local-credential sign-in path correctly renders `IsErrUserInactive` in the same condition; only the OAuth callback path flips the flag and proceeds.

### PoC

1. As a site administrator, configure an OAuth2 authentication source via `Site Administration -> Authentication Sources -> Add Authentication Source`. Any external provider works (a self-hosted Keycloak, an upstream Gitea acting as OIDC, GitHub, GitLab, Microsoft, Google).
2. Have a normal user (`alice` in the example) sign in through that source at least once. The callback creates the row in `external_login_user` linking alice's local account to the IdP identity.
3. As the site administrator, disable alice's account: `Site Administration -> User Accounts -> alice -> "Disable Account"`. Confirm the flag is set with the admin API.

#### HTTP REQUEST

```http
GET /api/v1/admin/users/alice HTTP/1.1
Host: <HOST>
Authorization: token <ADMIN_TOKEN>
Acc [...truncated]

---

## R063

**Package:** github.com/0xJacky/Nginx-UI

**Summary:** Nginx-UI: Cross-Site WebSocket Hijacking (CSWSH) via missing origin validation on all WebSocket endpoints

## Summary

All WebSocket endpoints in nginx-ui use a gorilla/websocket Upgrader with CheckOrigin unconditionally returning true, allowing Cross-Site WebSocket Hijacking (CSWSH). Combined with the fact that authentication tokens are stored in browser cookies (set via JavaScript without HttpOnly or explicit SameSite attributes), a malicious webpage can establish authenticated WebSocket connections to the nginx-ui instance when a logged-in administrator visits the attacker-controlled page.

## Details

### Vulnerable Code Pattern

Every WebSocket endpoint in the codebase uses the same unsafe upgrader configuration:

```go
// Found in: api/terminal/pty.go, api/analytic/analytic.go, api/event/websocket.go,
// api/nginx_log/websocket.go, api/upstream/upstream.go, api/cluster/websocket.go,
// api/nginx/websocket.go, api/certificate/revoke.go, api/sites/websocket.go,
// api/llm/llm.go, api/llm/code_completion.go, api/system/upgrade.go
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true // Accepts ALL origins
    },
}
```

### Cookie-Based Authentication

The Vue.js frontend stores JWT tokens as cookies without security attributes (app/src/pinia/moudule/user.ts):

```typescript
watch(token, v => {
    cookies.set('token', v, { maxAge: 86400 })  // No HttpOnly, no SameSite
})
```

The backend middleware accepts tokens from cookies (internal/middleware/middleware.go):

```go
func getToken(c *gin.Context) (token string) {
    // ...
    if token, _ = c.Cookie("token"); token != "" {
        return token
    }
    return ""
}
```

### Affected Endpoints

All WebSocket endpoints under the authenticated router group are vulnerable:

| Endpoint | Impact |
|---|---|
| /api/nginx/detail_status/ws | Leak nginx performance metrics and configuration |
| /api/events | Leak system processing events |
| /api/analytic/intro | Leak CPU, memory, disk, network statistics |
| /api/nginx_log | Read nginx log files (access/error logs) |
| /api/pty | Interactive terminal access (RCE if OTP not enabled) |
| /api/upgrade/perform | Trigger system binary upgrade |
| /api/cluster/nodes/enabled | Leak and manipulate cluster node data |

## PoC

### Environment Setup

```yaml
services:
  nginx-ui:
    image: uozi/nginx-ui:latest
    ports:
      - "9000:80"
    volumes:
      - nginx-ui-config:/etc/nginx-ui
volumes:
  nginx-ui-config:
```

### Attack Page (hosted on attacker-controlled domain)

```html
<script>
// Attacker page at http://evil-at [...truncated]

---

## R064

**Package:** admidio/admidio

**Summary:** Admidio: OIDC Token Introspection Endpoint Returns Active for All Tokens Without Validation

## Summary

The OIDC token introspection endpoint (`/modules/sso/index.php/oidc/introspect`) always returns `{"active": true}` for every request, regardless of whether a valid token is provided, whether the token is expired, revoked, or completely fabricated. The endpoint performs no authentication of the calling resource server and no validation of the submitted token. Any resource server that relies on this introspection endpoint to validate access tokens will accept all requests as authorized, enabling complete authentication bypass.

Additionally, the OIDC token revocation endpoint (`/oidc/revoke`) returns `{"revoked": true}` without actually revoking any token, preventing resource servers from invalidating compromised credentials.

## Details

The vulnerability is in `src/SSO/Service/OIDCService.php`, lines 604-619:

```php
public function handleIntrospectionRequest() {
    // TODO_RK
    if (!$this->isServiceSetup) {
        $this->setupService();
    }
    return new JsonResponse(["active" => true]);
}

public function handleRevocationRequest() {
    // TODO_RK
    if (!$this->isServiceSetup) {
        $this->setupService();
    }

    return new JsonResponse(["revoked" => true]);
}
```

The introspection endpoint is routed at `modules/sso/index.php`, line 58-59:

```php
} elseif (strpos($requestUri, '/oidc/introspect') !== false) {
    $response = $oidcService->handleIntrospectionRequest();
```

The router comment at line 35 says "Login checks will be done in the individual endpoint handler functions!" but neither `handleIntrospectionRequest` nor `handleRevocationRequest` perform any authentication or authorization checks.

Per RFC 7662 (OAuth 2.0 Token Introspection), the introspection endpoint:
1. MUST authenticate the calling resource server (Section 2.1)
2. MUST validate the submitted token against its database
3. MUST return `{"active": false}` for invalid, expired, or revoked tokens

The current implementation violates all three requirements.

**Attack flow:**
1. Attacker obtains a resource server's endpoint URL that uses Admidio as its OIDC provider
2. Attacker crafts any arbitrary string as a Bearer token
3. Resource server sends the fabricated token to `/oidc/introspect` for validation
4. Admidio returns `{"active": true}` without any checks
5. Resource server accepts the fabricated token as valid and grants access

**The revocation bypass compounds this:** If a legitimate token is stolen, the resource server or client application cannot r [...truncated]

---

## R065

**Package:** github.com/nhost/nhost

**Summary:** nhost has Session Persistence After Password Change

## Description

When a user changes their password, either through the authenticated password change endpoint or a password reset ticket, the [`ChangePassword`](https://github.com/nhost/nhost/blob/main/services/auth/go/controller/workflows.go#L731-L759) workflow correctly hashes and persists the new password via [`UpdateUserChangePassword`](https://github.com/nhost/nhost/blob/main/services/auth/go/sql/query.sql#L314-L318). However, it does not revoke existing sessions. The `auth.refresh_tokens` and `auth.oauth2_refresh_tokens` tables are left untouched, meaning all previously issued refresh tokens remain valid and can continue generating new access tokens indefinitely.

This vulnerability affects all password change paths (handled in [`change_user_password.go`](https://github.com/nhost/nhost/blob/main/services/auth/go/controller/change_user_password.go)), since they share the same underlying workflow:

- Authenticated password change via the Nhost dashboard or client SDK
- Ticket-based password reset (magic links / recovery flows)
- OAuth2/OIDC sessions managed via `auth.oauth2_refresh_tokens`

## Attack Scenario

1. An attacker steals a victim's refresh token via XSS or a compromised device.
2. The victim changes their password, expecting it to terminate all active sessions.
3. The server updates `password_hash` but performs no session cleanup, the stolen token remains fully functional.

## Impact

The attacker retains persistent access even after the victim's password change. This is especially severe in credential theft scenarios, where the victim's only recovery action does nothing against an active session. Depending on configured TTL, the attacker's window could be days or weeks.

---

## R066

**Package:** pimcore/web2print-tools-bundle

**Summary:** Pimcore Web2Print Tools Bundle "Favourite Output Channel Configuration" Missing Function Level Authorization

### Summary
The application fails to enforce proper server-side authorization checks on the API endpoint responsible for managing "Favourite Output Channel Configurations." Testing revealed that an authenticated backend user without explicitely lacking permissions for this feature was still able to successfully invoke the endpoint and modify or retrieve these configurations. This violates the principle of least privilege and constitutes a classic example of Broken Access Control (OWASP Top 10 A01:2021). Because authorization is not validated at the function level, any authenticated user can perform actions intended only for privileged roles, leading to horizontal or vertical privilege escalation.

### Detail
The backend user without permission was still able to list, create, update "Favourite Output Channel Configuration" item

### Step to Reproduce the issue
login as Admin (full permission) and clicked "Favourite Output Channel Configurations"
<img width="949" height="860" alt="Screenshot 2025-12-10 at 8 52 55 PM" src="https://github.com/user-attachments/assets/86554e7e-86c1-469f-b09b-5f360c4507dd" />
Then, captured and saved the request:
-List API
<img width="923" height="662" alt="Screenshot 2025-12-10 at 8 55 49 PM" src="https://github.com/user-attachments/assets/21d90540-7a6b-4555-bbc0-ce74284dda67" />
-Create API
<img width="1245" height="783" alt="Screenshot 2025-12-10 at 9 01 46 PM" src="https://github.com/user-attachments/assets/38b5a771-ad17-459b-84e1-fe83c6d609a1" />
-Update API
<img width="1244" height="726" alt="Screenshot 2025-12-10 at 9 03 00 PM" src="https://github.com/user-attachments/assets/2167d48e-8941-4fff-be07-3050ffa7ad35" />

Next, login a backend user with no permission
<img width="1219" height="744" alt="Screenshot 2025-12-10 at 9 06 12 PM" src="https://github.com/user-attachments/assets/6b3981bc-4fe0-4c6e-8a5b-24523679ad4c" />
The copy the "Cookie" and "X-Pimcore-Csrf-Token"
<img width="1902" height="971" alt="Screenshot 2025-12-10 at 9 10 47 PM" src="https://github.com/user-attachments/assets/4f48f27a-6149-49fb-9209-220c2e62c25f" />
After that, pasted the copied  "Cookie" and "X-Pimcore-Csrf-Token" to captured request
- List API
<img width="1135" height="660" alt="Screenshot 2025-12-10 at 9 14 47 PM" src="https://github.com/user-attachments/assets/32ebdad2-771a-41dd-a4e6-13e8cb8ef201" />
- Create API
<img width="1140" height="697" alt="Screenshot 2025-12-10 at 9 16 43 PM" src="https://github.com/user-attachments/assets/25d5b7a9- [...truncated]

---

## R067

**Package:** @clerk/backend,@clerk/express,@clerk/fastify,@clerk/hono

**Summary:** Clerk: SSRF in the opt-in clerkFrontendApiProxy feature may leak secret keys to unintended host

## Summary

The `clerkFrontendApiProxy` function in `@clerk/backend` is vulnerable to Server-Side Request Forgery (SSRF). An unauthenticated attacker can craft a request path that causes the proxy to send the application's `Clerk-Secret-Key` to an attacker-controlled server.

## Affected packages

Only applications that have opted into the `frontendApiProxy` feature are affected. This feature is not enabled by default. **Users of `@clerk/nextjs` are not affected** due to how the framework handles repeated `/` in request paths.

| Package | Affected versions | Fixed version |
|---|---|---|
| `@clerk/backend` | `>= 3.0.0, <= 3.2.2` | `3.2.3` |
| `@clerk/express` | `>= 2.0.0, <= 2.0.6` | `2.0.7` |
| `@clerk/hono` | `>= 0.1.0, <= 0.1.4` | `0.1.5` |
| `@clerk/fastify` | `>= 3.1.0, <= 3.1.4` | `3.1.5` |

Search your codebase for the `frontendApiProxy` option. If none of the patterns below appear in your code, you are not affected.

**@clerk/express**
```ts
app.use(clerkMiddleware({ frontendApiProxy: { enabled: true } }));
```

**@clerk/hono**
```ts
app.use('*', clerkMiddleware({ frontendApiProxy: { enabled: true } }));
```

**@clerk/fastify**
```ts
fastify.register(clerkPlugin, { frontendApiProxy: { enabled: true } });
```

**@clerk/backend**
```ts
import { clerkFrontendApiProxy } from '@clerk/backend/proxy';
```

A quick way to check across your entire project:

```sh
grep -r "frontendApiProxy\|clerkFrontendApiProxy" .
```

If there are no matches, you are not using this feature.


## Recommended actions

Clerk's internal logs show no evidence of users utilizing the built-in proxy with the impacted versions. Despite that, if you are on an impacted version and use the built-in proxy we recommend upgrading and rotating your Clerk Secret Key immediately.

1. **Upgrade** to the patched version of `@clerk/backend` (and `@clerk/express`, `@clerk/hono`, etc.)
2. **Rotate your Clerk Secret Key** after upgrading - if an attacker exploited this vulnerability, they may have captured your key. Rotate it in the [Clerk Dashboard](https://dashboard.clerk.com) under **API Keys**.  You should deploy your application with the updated key before revoking the existing key.
3. **Audit access logs** for requests to your proxy endpoint (`/__clerk/` by default) containing double slashes in the path.



## Credit

Discovered during an internal code audit.

---

## R068

**Package:** github.com/cloudreve/Cloudreve/v4

**Summary:** Cloudreve has Broken Access Control - Revoked Share Access Still Allows Signed File URL Generation via Cached context_hint

## Summary
 
Cloudreve's file-listing responses hand the client a `context_hint` (UUID) that is meant to speed up follow-up operations. When that hint is replayed on the `file/url` (and `file/thumb`) routes, DBFS caches a `shareNavigatorState` containing the already-loaded share root and share row.
 
On a later request carrying the same hint, `shareNavigator.RestoreState` repopulates `shareRoot`, and `shareNavigator.To` then **skips `Root`**. `Root` is the only place that re-checks `inventory.IsValidShare` (share expiry, remaining-download count, owner status, source-file validity) and the share password. As a result, a recipient who prewarms a context hint while access is valid can keep minting signed file URLs for already-known shared file paths for up to the context-hint TTL (`5 * 60` = 300 s) after the owner deletes the share or the share expires — plus the lifetime of any signed entity URL minted in that window.
 
This is a **revocation / expiry bypass**, not a way to discover unknown share contents: the attacker must already have had access to the share and must know the target file URI from a prior listing.

## Root cause (verified at `26b6b10`)
 
**1. List responses leak the hint and each file URI** — `service/explorer/response.go` populates `ListResponse.ContextHint` and `FileResponse.Path` (`f.Uri(false).String()`).
 
**2. `file/url` and `file/thumb` accept the client-supplied hint** — `routers/router.go:631` and `:662`:
 
```go
file.POST("url",  middleware.ContextHint(), /* ... */ controllers.FileURL)
file.GET("thumb", middleware.ContextHint(), /* ... */ controllers.Thumb)
```
 
The `file` group's only auth gate is `middleware.RequiredScopes(types.ScopeFilesRead)` — there is **no** independent share-validation middleware on this route. All share validation lives inside DBFS.
 
**3. The middleware trusts the header verbatim** — `middleware/file.go:41`:
 
```go
func ContextHint() gin.HandlerFunc {
    return func(c *gin.Context) {
        if c.GetHeader(dbfs.ContextHintHeader) != "" { // X-Cr-Context-Hint
            util.WithValue(c, dbfs.ContextHintCtxKey{}, uuid.FromStringOrNil(c.GetHeader(dbfs.ContextHintHeader)))
        }
        c.Next()
    }
}
```
 
**4. DBFS restores cached navigator state on a hint hit** — `dbfs.go:745` (`ContextHintTTL = 5 * 60`, `dbfs.go:34`). On a miss it arms `PersistState`; the closure fires in `DBFS.Recycle()` at end of request.
 
**5. Persisted share state carries the loaded `shareRoot` + `share` row** — `share_n [...truncated]

---

## R069

**Package:** github.com/juev/nebula-mesh

**Summary:** Nebula Mesh: Web UI lacks ownership checks, enabling cross-operator access to hosts and networks (read, block, delete)

## Summary

The web UI (`/ui/*`) does not apply the per-operator CA scoping the JSON API received for GHSA-598g-h2vc-h5vg. Any authenticated non-admin operator (for example, one created via self-registration or OIDC) can access resources belonging to other operators.

## Impact

A non-admin operator can:

- **Block or delete any other operator's host.** `POST /ui/hosts/{id}/block` and `DELETE /ui/hosts/{id}` act on the URL `id` with no ownership check, so a non-admin can block (revoking the host's certificate via the blocklist) or delete any host in the deployment — a cross-operator denial of service.
- **Read every operator's hosts and networks.** The dashboard, `/ui/hosts`, the host detail page, `/ui/networks` (including the create-form error re-render), and the `/ui/events` stream all return data across all operators, exposing host names, Nebula IPs, public IPs, certificate fingerprints and expiry, and network names and CIDRs.

This is the same cross-operator class as GHSA-598g; that remediation covered the JSON API but not the web read/mutation surface. The host create/edit/mobile-bundle/network-create paths and all CA-management routes were already correctly scoped.

Affected handlers (`internal/web`): `handleHostDetail`, `handleHostBlock`, `handleHostDelete`, `handleDashboard`, `handlePartialStats`, `handleHosts`, `handleNetworks`, `renderNetworksError`, `handleHostEvents`.

## Conditions

Exposure requires at least one non-admin operator to exist (self-registration enabled, OIDC, or an admin-created user). A single-admin deployment with no additional operators is not affected.

## Fix

A complete candidate fix with regression tests is ready in a private repository shared with the maintainer (`ak2k/nebula-mesh-ghsa-web`, PR #1): scope these handlers to the session operator's owned CAs (admins keep the full view), mirroring the API's ownership checks.

---

## R070

**Package:** surrealdb

**Summary:** SurrealDB: LIVE query subscriptions survive session state changes, bypassing access controls

A `LIVE SELECT` subscription records the user's auth state (`$auth`, `$token`, `$session`, `$access`) when it is registered, and the server uses that recorded state to evaluate the table- and row-level `PERMISSIONS` clauses for every subsequent notification. The recorded state is never refreshed. 

When something changes the user's effective auth state — the originating session is invalidated, the session's TTL expires, or the user signs in, signs up, or authenticates as a different identity on the same connection — the subscription keeps delivering notifications under the old, stale auth state, and the `PERMISSIONS` that should now apply to the connection are never consulted.

### Impact

A user whose session has been revoked, expired, signed out of, or re-authenticated on the same connection continues to receive real-time notifications evaluated against the prior principal. The attacker does not gain access to new resources — only continued access to resources the prior principal was already permitted to read — but that continued access persists past the point the principal change should have ended it, and persists indefinitely until the originating connection is closed.

This is confidentiality-only: the dispatcher does not enable writes evaluated under the stranded principal.

### Patches

- **`invalidate()` and TTL expiry** — `RpcProtocol::invalidate` now calls `cleanup_lqs(session_id)` after clearing the session, dropping every LIVE owned by the now-invalidated session. The notification dispatcher additionally reads the originating session's `exp` and skips delivery once it has passed, closing the TTL-expiry leg without requiring the `Session` object to remain in memory.
- **Principal change on `signin` / `signup` / `authenticate` / `refresh`** — each of these RPC methods now snapshots the session's auth principal (`Auth::id()` + `Auth::level()`) before mutating the session and, if the principal has changed after the operation, calls `cleanup_lqs(session_id)`. Token refresh against the same identity is therefore preserved; identity change tears stranded subscriptions down.

Versions  3.1.0 and later are not affected by this issue.

### Workarounds

For unpatched versions, clients should call `reset()` (which tears down all LIVE queries owned by the session) or `kill` each outstanding `live query ID` before signing out, signing in as a different identity, or signing up on an existing connection. There is no client-side workaround for the TTL-expiry le [...truncated]

---

## R071

**Package:** org.keycloak:keycloak-services

**Summary:** Keycloak services allows the issuance of access and refresh tokens for disabled users

A flaw was found in the keycloak-services component of Keycloak. This vulnerability allows the issuance of access and refresh tokens for disabled users, leading to unauthorized use of previously revoked privileges, via a business logic vulnerability in the Token Exchange implementation when a privileged client invokes the token exchange flow.

---

## R072

**Package:** aws-lc-fips-sys,aws-lc-sys

**Summary:** CRL Distribution Point Scope Check Logic Error in AWS-LC

### Summary

AWS-LC is an open-source, general-purpose cryptographic library.

### Impact 

A logic error in CRL distribution point matching in AWS-LC allows a revoked certificate to bypass revocation checks during certificate validation, when the application enables CRL checking and uses partitioned CRLs with Issuing Distribution Point (IDP) extensions.

Customers of AWS services do not need to take action. aws-lc-sys and aws-lc-fips-sys contain code from AWS-LC. Applications using aws-lc-sys or aws-lc-fips-sys should upgrade to the most recent releases of aws-lc-sys or aws-lc-fips-sys.

### Impacted versions:
* aws-lc-sys >= v0.15.0, < v0.39.0
* aws-lc-fips-sys >= v0.13.0, < v0.13.13

### Patches 

The patch is included in aws-lc-sys v0.39.0 and aws-lc-fips-sys v0.13.13.

### Workarounds

Applications can workaround this issue if they do not enable CRL checking (X509_V_FLAG_CRL_CHECK). Applications using complete (non-partitioned) CRLs without IDP extensions are also not affected.

Otherwise, there is no workaround and applications using aws-lc-sys or aws-lc-fips-sys should upgrade to the most recent releases of aws-lc-sys or aws-lc-fips-sys.

### References

If you have any questions or comments about this advisory, we ask that you contact AWS Security via our [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/) or directly via email to [aws-security@amazon.com](mailto:aws-security@amazon.com). Please do not create a public GitHub issue.

---

## R073

**Package:** n8n

**Summary:** n8n: Cross-Tenant Credential Takeover via Dynamic Credentials EE Endpoints

## Impact
Three EE endpoints used by the Dynamic Credentials feature accepted any authenticated n8n session without performing per-resource ownership or scope checks on the target workflow or credential. An authenticated user with no project membership or credential sharing relationship could enumerate credential identifiers, names, and types referenced by any private workflow in the instance, initiate an OAuth authorization flow against another user's credential to overwrite its stored tokens with tokens bound to an account they control, or revoke another user's stored credential tokens entirely.

Workflows relying on a hijacked credential would subsequently execute under the attacker's OAuth identity, enabling data exfiltration to attacker-controlled external services and persistent takeover of integrations. Token revocation would break affected workflows.

This issue only affects Enterprise instances where the Dynamic Credentials feature is enabled.

## Patches
The issue has been fixed in n8n versions 1.123.55, 2.25.7, and 2.26.2. Users should upgrade to one of these versions or later to remediate the vulnerability.

## Workarounds
If upgrading is not immediately possible, administrators should consider the following temporary mitigations:
- Restrict n8n instance access to fully trusted users only.
- If the Dynamic Credentials feature is not actively required, disable it by unsetting `N8N_ENV_FEAT_DYNAMIC_CREDENTIALS`.

These workarounds do not fully remediate the risk and should only be used as short-term mitigation measures.

---
n8n has adopted CVSS 4.0 as primary score for all security advisories. CVSS 3.1 vector strings are provided for backwards compatibility.

CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L

---

## R074

**Package:** shopware/core

**Summary:** Shopware 6's password recovery link does not expire after email change

### Summary
When a customer changes their email address after requesting a password reset, the old password reset link (tied to the previous email) remains valid. An attacker with access to the old email inbox is potentially able to reset the customer’s password even after the user changes their email address.

### PoC

1. Log in to a Shopware account.
2. Request a password reset for your current email address.
3. Copy the password reset link but do not open it.
4. Log back into your account.n
5. Navigate to Account Settings → Email and change your email address.
6. Use the previously copied reset link (from before the email change).
7. The system allows password change using the old link.

### Impact
Reproduced on Stable 6.6.10.7 and trunk.

---

## R075

**Package:** reportico-web/reportico

**Summary:** Reportico Web fails to invalidate cookies upon logout

An issue in Reportico Web before v.8.1.0. This vulnerability arises from the failure of the web application to properly invalidate session cookies upon logout. When a user logs out of the application, the session cookie should be invalidated to prevent unauthorized access. However, due to the oversight in the application's implementation, the session cookie remains active even after logout. Consequently, if an attacker obtains the session cookie, they can exploit it to access the user's session and perform unauthorized actions.

---

## R076

**Package:** org.keycloak:keycloak-parent

**Summary:** Incorrect Authorization in keycloak

A flaw was found in keycloak before version 13.0.0. In some scenarios a user still has access to a resource after changing the role mappings in Keycloak and after expiration of the previous access token.

---

## R077

**Package:** github.com/0xJacky/Nginx-UI

**Summary:** Nginx-UI: Disabled users retain full API access through previously issued bearer tokens

### Summary

A user who was disabled by an administrator can use previously issued API tokens for up to the token lifetime. In practice, disabling a compromised account does not actually terminate that user’s access, so an attacker who already stole a JWT can continue reading and modifying protected resources after the account is marked disabled.

Since tokens can be used to create new accounts, it is possible the disabled user to maintain the privilege.

### Details

The application exposes an account-level disable control through the users management API. Login process correctly enforces that control:
https://github.com/0xJacky/nginx-ui/blob/6ec542fd97abf2c5950f374f78a32938ad0030e6/internal/user/login.go#L29-L31

However, token-based authentication does not enforce the same check (This code validates token structure and expiry, but returns that user object without checking `user.Status`.):
https://github.com/0xJacky/nginx-ui/blob/6ec542fd97abf2c5950f374f78a32938ad0030e6/internal/user/user.go#L44-L139

There’s also no token revocation feature, unlike when a password is changed:
https://github.com/0xJacky/nginx-ui/blob/6ec542fd97abf2c5950f374f78a32938ad0030e6/api/user/user.go#L38-L51

As a result, a disabled user can continue to have full API access. In particular, since that includes account creation, they can create a new account and keep operating even after the JWT expires.

### PoC

The issue was validated with version 2.3.3 using the `uozi/nginx-ui:sha-c92ec0a` docker image.

View the PoC video:


https://github.com/user-attachments/assets/7a5175cb-2f79-4c1b-adad-e7d0bf2ea2bd



### Impact

Administrators who rely on "disable user" as an authentication or authorization control can be bypassed.

The disabled user can keep reading sensitive configuration and executing authenticated state-changing actions allowed to that account.

---

## R078

**Package:** github.com/hashicorp/vault

**Summary:** HashiCorp Vault Improper Privilege Management

HashiCorp Vault and Vault Enterprise versions 0.9.0 through 1.3.3 may, under certain circumstances, have an Entity's Group membership inadvertently include Groups the Entity no longer has permissions to. Fixed in 1.3.4.

---

## R079

**Package:** PraisonAI,praisonaiagents

**Summary:** PraisonAI has unsafe tool resolution in `ToolExecutionMixin.execute_tool`: undeclared `__main__` callables execute

### Summary
`praisonaiagents` resolves unresolved tool names against module globals and `__main__` after it fails to match the declared tool list and the registry. With the default agent configuration, `_perm_allow` is `None`, so undeclared non-dangerous tool names are not rejected by the permission gate. An attacker who can influence tool-call names can therefore invoke unintended application callables that were never declared as tools.

### Details
The vulnerable resolution path is in [`[tool_execution.py](https://github.com/Users/shmulc/Documents/Codex/2026-05-03/please-go-over-tmp-tp-advisories/repos/PraisonAI/src/praisonai-agents/praisonaiagents/agent/tool_execution.py:734)`](/Users/shmulc/Documents/Codex/2026-05-03/please-go-over-tmp-tp-advisories/repos/PraisonAI/src/praisonai-agents/praisonaiagents/agent/tool_execution.py:734). After searching declared tools and the registry, execution falls back to `globals()` and then `__main__`:

```python
func = None
for tool in self.tools if isinstance(self.tools, (list, tuple)) else []:
    ...

if func is None:
    try:
        from ..tools.registry import get_registry
        registry = get_registry()
        func = registry.get(function_name)
    except ImportError:
        pass

if func is None:
    func = globals().get(function_name)
    if not func:
        import __main__
        func = getattr(__main__, function_name, None)
```

If a callable is found, it is executed directly:

```python
elif callable(func):
    casted_arguments = self._cast_arguments(func, arguments)
    return func(**casted_arguments)
```

The permission gate does not enforce a declared-tool allowlist by default. In [`[tool_execution.py](https://github.com/Users/shmulc/Documents/Codex/2026-05-03/please-go-over-tmp-tp-advisories/repos/PraisonAI/src/praisonai-agents/praisonaiagents/agent/tool_execution.py:550)`](/Users/shmulc/Documents/Codex/2026-05-03/please-go-over-tmp-tp-advisories/repos/PraisonAI/src/praisonai-agents/praisonaiagents/agent/tool_execution.py:550), execution is only rejected if `_perm_allow` is non-`None`:

```python
if self._perm_deny and function_name in self._perm_deny:
    return {"error": f"Tool '{function_name}' blocked by permission policy", "permission_denied": True}
if self._perm_allow is not None and function_name not in self._perm_allow:
    return {"error": f"Tool '{function_name}' not in allowed tools list", "permission_denied": True}
```

Default agent initialization sets `_perm_allow = None`, which mean [...truncated]

---

## R080

**Package:** github.com/mattermost/mattermost-server

**Summary:** Mattermost doesn't invalidate cached authentication state for active WebSocket connections during global session revocation

Mattermost versions 11.7.x <= 11.7.0, 11.6.x <= 11.6.2, 11.5.x <= 11.5.5, 10.11.x <= 10.11.17 fail to invalidate cached authentication state for active WebSocket connections during global session revocation, which allows a user with an existing WebSocket connection to remain authenticated and continue receiving real-time events until the cached session expires or the client reconnects.. Mattermost Advisory ID: MMSA-2026-00664

---

## R081

**Package:** org.apache.shiro:shiro-core

**Summary:** Apache Shiro has a session fixation vulnerability

Default configurations of Apache Shiro have a session fixation vulnerability.

This issue affects Apache Shiro from 1.0 to 2.1.0, and 3.0.0-alpha-1.

Users are recommended to upgrade to version 2.1.1, or 3.0.0-alpha-2 or later, which fixes the issue.

In the affected versions, when a session already exists, it is not invalidated upon successful login, nor is a new session being generated with a new ID.

---

## R082

**Package:** umami

**Summary:** Anyone with a share link can RESET all website data in Umami

### Summary
Anyone with a share link (permissions to view) can reset the website data.

### Details
When a user navigates to a `/share/` URL, he receives a share token which is used for authentication. This token is later verified by `useAuth`. After the token is verified, the user can call most of the `GET` APIs that allow fetching stats about a website.

The `POST /reset` endpoint is secured using `canViewWebsite` which is the incorrect verification for such destructive action. This makes it possible to completly reset all website data ONLY with view permissions - [permalink](https://github.com/umami-software/umami/blob/7bfbe264852558a148c7741f8637ff2b266d48cd/pages/api/websites/%5Bid%5D/reset.ts#L22)


### PoC
```bash
curl -X POST 'https://analytics.umami.is/api/websites/b8250618-ccb5-47fb-8350-31c96169a198/reset' \
  -H 'authority: analytics.umami.is' \
  -H 'accept: application/json' \
  -H 'accept-language: en-US,en;q=0.9' \
  -H 'authorization: Bearer undefined' \
  -H 'cache-control: no-cache' \
  -H 'content-type: application/json' \
  -H 'pragma: no-cache' \
  -H 'referer: https://analytics.umami.is/share/bw6MFhkwpwEXFsbd/test' \
  -H 'sec-ch-ua: "Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "Linux"' \
  -H 'sec-fetch-dest: empty' \
  -H 'sec-fetch-mode: cors' \
  -H 'sec-fetch-site: same-origin' \
  -H 'user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36' \
  -H 'x-umami-share-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ3ZWJzaXRlSWQiOiJiODI1MDYxOC1jY2I1LTQ3ZmItODM1MC0zMWM5NjE2OWExOTgiLCJpYXQiOjE2OTAzNjkxOTl9.zTfwFrfggE5na7rOOgkUobEBm48AH_8WVyh2RgJGzcw' \
  --compressed
```

You can reproduce this by:
* Accessing a website using it's share link
* Copy the `token` received from the the received from the `GET /share/{website-id}`
* Send a POST request to `https://analytics.umami.is/api/websites/b8250618-ccb5-47fb-8350-31c96169a198/reset` with `x-umami-share-token: ` header equal to the token copied in the previous step
* The website data is now cleared

### Impact
Everyone with an open share link exposed to the internet!

---

## R083

**Package:** github.com/rancher/rancher

**Summary:** Rancher generated tokens not revoked after modifications made to authentication provider

### Impact

This issue affects Rancher versions from 2.5.0 up to and including 2.5.16, from 2.6.0 up to and including 2.6.9 and 2.7.0. It only affects Rancher setups that have an external [authentication provider](https://ranchermanager.docs.rancher.com/pages-for-subheaders/authentication-config) configured or had one configured in the past.

It was discovered that when an external authentication provider is configured in Rancher and then disabled, the Rancher generated [tokens](https://ranchermanager.docs.rancher.com/reference-guides/about-the-api/api-tokens) associated with users who had access granted through the now disabled auth provider are not revoked. This allows users to retain access to Rancher and `kubectl` access to clusters managed by Rancher, according to their previous configured permissions, even after they are supposed to have lost it due to the auth provider been disabled.

The problem also occurs if the auth provider is configured (and is still enabled) to use the [access level scopes](https://ranchermanager.docs.rancher.com/pages-for-subheaders/authentication-config) `allow members of clusters and projects, plus authorized users & groups` and `restrict access to only the authorized users & groups`. In this case, removing users and groups from the authorized lists will not revoke the access tokens and they will remain valid.


An example scenario is:

1. OpenLDAP, MS Active Directory (AD) or any other external [authentication provider](https://ranchermanager.docs.rancher.com/pages-for-subheaders/authentication-config) is configured as an auth provider.
2. A user (`cluster-owner`) is granted `cluster-owner` permissions on a downstream cluster (`test-cluster`).
3. `cluster-owner` logs in using their external auth provider username and password.
4. `cluster-owner` generates a `kubeconfig` token for `test-cluster`.
5. The configured external auth provider is disabled.

In this scenario, the `kubeconfig` generated in step 4 will still be valid after step 5, and `test-cluster` can still be accessed using the `kubeconfig` token.

By default, tokens for authenticated session have their `ttl` (time to live) set to `960` minutes, so they will expire after `16` hours. `kubeconfig` tokens are configured to never expire, and their `ttl` is set to `0`. These configurations can be changed in the Rancher's settings (`Configuration > Global Settings > Settings`) with the [parameters](https://ranchermanager.docs.rancher.com/reference-guides/about-the-api/ [...truncated]

---

## R084

**Package:** github.com/fluxcd/flux2,github.com/fluxcd/helm-controller,github.com/fluxcd/kustomize-controller

**Summary:** Improper kubeconfig validation allows arbitrary code execution

Flux2 can reconcile the state of a remote cluster when provided with a [kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/#file-references) with the correct access rights. `Kubeconfig` files can define [commands](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins) to be executed to generate on-demand authentication tokens. A malicious user with write access to a Flux source or direct access to the target cluster, could craft a `kubeconfig` to execute arbitrary code inside the controller’s container.

In multi-tenancy deployments this can also lead to privilege escalation if the controller's service account has elevated permissions.

### Impact

Within the affected versions range, one of the permissions set below would be required for the vulnerability to be exploited:
- Direct access to the cluster to create Flux `Kustomization` or `HelmRelease` objects and Kubernetes Secrets.
- Direct access to the cluster to modify existing Kubernetes secrets being used as `kubeconfig` in existing Flux `Kustomization` or `HelmRelease` objects.
- Direct access to the cluster to modify existing Flux `Kustomization` or `HelmRelease` objects and access to create or modify existing Kubernetes secrets.
- Access rights to make changes to a configured Flux Source (i.e. Git repository).

### Patches

This vulnerability was fixed in kustomize-controller [v0.23.0](https://github.com/fluxcd/kustomize-controller/releases/tag/v0.23.0) and helm-controller [v0.19.0](https://github.com/fluxcd/helm-controller/releases/tag/v0.19.0), both included in flux2 [v0.29.0](https://github.com/fluxcd/flux2/releases/tag/v0.29.0). Starting from the fixed versions, both controllers disable the use of command execution from `kubeconfig` files by default, users have to opt-in by adding the flag `--insecure-kubeconfig-exec` to the controller’s command arguments. Users are no longer allowed to refer to files in the controller’s filesystem in the `kubeconfig` files provided for the remote apply feature.

### Workarounds

- The functionality can be disabled via Validating Admission webhooks (e.g. OPA Gatekeeper, Kyverno) by restricting users from being able to set the `spec.kubeConfig` field in Flux `Kustomization` and `HelmRelease` objects.
- Applying restrictive AppArmor and SELinux profiles on the controller’s pod to limit what binaries can be executed.

### Credits

The Flux engineering team found and patched [...truncated]

---

## R085

**Package:** code.gitea.io/gitea

**Summary:** Gitea: Notification API leaks private issue metadata after access revocation

# Summary

An information disclosure issue in the Gitea Notification API allows users who have lost access to a private repository to continue accessing private issue or pull request information through existing notification threads. Although repository information is hidden after access revocation, the `subject` field remains accessible and continues to expose private metadata.

# Details

CVE-2026-20800 was fixed in v1.25.4 to prevent users from accessing private repository information through notification APIs after their repository access had been revoked.

During testing on Gitea v1.26.2, the `repository` field in `NotificationThread` responses is correctly set to `null` after access revocation. However, the associated `subject` field remains available.

The exposed `subject` object may contain:

* Private issue or pull request titles
* Repository-related API and HTML URLs
* Issue or pull request state
* Latest comment URLs and comment identifiers

Additionally, the exposed notification data is not limited to historical information. If new comments are added to the issue or pull request while the notification remains unread, fields such as `latest_comment_url` and `updated_at` continue to change. As a result, a user whose repository access has been revoked can still observe ongoing issue or pull request activity through notification APIs.

The observed behavior suggests that access control is applied to the `repository` field but not consistently applied to the associated `subject` information.

# PoC

## Environment

* Gitea v1.26.2
* Private repository

## Steps to Reproduce

1. User `sun` creates a private repository and grants read access to user `li`.

2. User `li` subscribes to repository notifications.

3. User `sun` creates a private issue and adds a comment.

4. User `li` receives a notification (`thread_id = 14`).

5. User `sun` revokes `li`'s repository access.

6. User `li` requests:

   ```http
   GET /api/v1/repos/sun/{repo}/issues/1
   ```

   Response:

   ```text
   404 Not Found
   ```

7. User `li` requests:

   ```http
   GET /api/v1/notifications?all=true
   ```

8. User `li` requests:

   ```http
   GET /api/v1/notifications/threads/14
   ```

## Observed Result

The notification is returned successfully. The `repository` field is `null`, but the `subject` field still contains private issue metadata.

Example:

```json
{
  "id": 14,
  "repository": null,
  "subject": {
    "title": "private issue title",
    "url": "http://localh [...truncated]

---

## R086

**Package:** org.springframework.security:spring-security-core

**Summary:** Spring Security logout not clearing security context

In Spring Security, versions 5.7.x prior to 5.7.8, versions 5.8.x prior to 5.8.3, and versions 6.0.x prior to 6.0.3, the logout support does not properly clean the security context if using serialized versions. Additionally, it is not possible to explicitly save an empty security context to the HttpSessionSecurityContextRepository. This vulnerability can keep users authenticated even after they performed logout. Users of affected versions should apply the following mitigation. 5.7.x users should upgrade to 5.7.8. 5.8.x users should upgrade to 5.8.3. 6.0.x users should upgrade to 6.0.3.

---

## R087

**Package:** @better-auth/scim

**Summary:** @better-auth/scim: account takeover and stale access via SCIM provider-id collision

### Am I affected?

You are affected if your application registers the `@better-auth/scim` plugin and lets authenticated users generate SCIM tokens. The default `canGenerateToken` policy was affected, and custom policies were affected when they did not reject provider IDs already used by other account providers. The provider-ID collision issue additionally requires SSO, SAML, OIDC, generic OAuth, or social providers whose account rows use custom provider IDs, plus existing account rows under those IDs.

The deprovisioning and email-update issues require only the SCIM plugin and a valid SCIM bearer token. Published versions from `@better-auth/scim@1.4.0-beta.27` through `1.6.21` are affected. Beta versions from `1.7.0-beta.0` through `1.7.0-beta.9` are affected. Upgrade to `@better-auth/scim@1.6.22` or `1.7.0-beta.10`.

### Summary

`@better-auth/scim` used the same logical provider ID for SCIM provider configuration and account ownership. SCIM token issuance did not reject all account-provider namespaces. An authenticated user could therefore mint a SCIM token whose provider ID matched an existing SSO, SAML, OIDC, generic OAuth, or social provider. SCIM user routes then selected account rows by that provider ID and treated those users as SCIM-managed, even when the SCIM token had never provisioned them.

The same write path had 2 additional validation issues. First, SCIM `active: false` was not modeled, so identity providers could receive a successful response while the user stayed active. Second, SCIM PUT and PATCH updates changed global email addresses without the same uniqueness check used by create, and `emailVerified` stayed unchanged after an email reassignment.

### Details

The SCIM bearer middleware decoded the provider ID from the bearer token and loaded the matching `scimProvider` row. User listing and user lookup then queried ordinary account rows by `account.providerId`. This made the provider ID a user-controlled authorization key. If a SCIM token used a provider ID that belonged to SSO, SAML, OIDC, generic OAuth, or another account provider, the SCIM routes could resolve users that the token did not own.

The highest-impact path was non-organization deletion. On affected versions, `DELETE /scim/v2/Users/:id` for a non-organization SCIM token deleted the global Better Auth user and their sessions after resolving the user through the colliding provider ID. A low-privileged authenticated user could therefore delete users associated with a colli [...truncated]

---

## R088

**Package:** firefighter-incident

**Summary:** FireFighter has unauthenticated SSRF in its Raid jira_bot endpoint that allows IAM credential theft

### Impact
  The `POST /api/v2/firefighter/raid/jira_bot` endpoint (`CreateJiraBotView`) is
  reachable without authentication (`permission_classes = [permissions.AllowAny]`).
  Its `attachments` payload is fetched server-side via `httpx.get()` with no URL
  validation, then uploaded as an attachment on the Jira ticket that gets created.

  An unauthenticated caller able to reach the ingress can coerce the pod into
  fetching arbitrary URLs — including the cloud metadata endpoint at
  `http://169.254.169.254/` — and exfiltrate the response as a Jira attachment.

  On EC2/EKS deployments that do not enforce IMDSv2, this allows theft of the
  temporary AWS credentials attached to the pod's IAM role. The docstring on the
  view claims a Bearer token is required, but the code does not enforce it.

  Affected code paths:
  - `src/firefighter/raid/views/__init__.py` — `CreateJiraBotView`
  - `src/firefighter/raid/serializers.py` — `LandbotIssueRequestSerializer.attachments`
  - `src/firefighter/raid/client.py` — `RaidJiraClient.add_attachments_to_issue`

  ### Patches
  Fixed in `firefighter-incident` `0.0.54`:
  - `CreateJiraBotView` now enforces `BearerTokenAuthentication` + `IsAuthenticated`.
  - `attachments` URLs are validated: http(s) scheme only, max 10 URLs, rejection
    of any host resolving to a private, loopback, link-local, reserved, multicast
    or unspecified IP (IPv4 and IPv6).
  - Fixes an unrelated `KeyError('attachments')` surfaced during regression testing.

  Users should upgrade to `0.0.54` or later.

  ### Workarounds
  Until upgrade is possible, any one of the following blocks end-to-end exploitation:
  - Restrict ingress access to `/api/v2/firefighter/raid/jira_bot` to trusted
    networks only (VPN, internal load balancer).
  - Rotate or revoke the Jira API token configured as `RAID_JIRA_API_PASSWORD`;
    this breaks `jira.create_issue()` before the vulnerable attachment fetch is
    reached (legitimate traffic is also blocked — emergency mitigation only).
  - Enforce IMDSv2 with `HttpPutResponseHopLimit=1` on EC2/EKS nodes. This does
    not fix the SSRF itself but neutralises the IAM-credential-theft path.

  ### Resources
  - CWE-918: Server-Side Request Forgery
  - CWE-306: Missing Authentication for Critical Function

---

## R089

**Package:** org.openrefine:openrefine

**Summary:** OpenRefine leaks Google API credentials in releases

### Impact

OpenRefine releases contain Google API authentication keys ("client id" and "client secret") which can be extracted from released artifacts. For instance, download the package for OpenRefine 3.8.2 on linux. It contains the file `openrefine-3.8.2/webapp/extensions/gdata/module/MOD-INF/lib/openrefine-gdata.jar`, which can be extracted.
This archive then contains the file `com/google/refine/extension/gdata/GoogleAPIExtension.java`, which contains the following lines:

```java
    // For a production release, the second parameter (default value) can be set
    // for the following three properties (client_id, client_secret, and API key) to
    // the production values from the Google API console
    private static final String CLIENT_ID = System.getProperty("ext.gdata.clientid", new String(Base64.getDecoder().decode("ODk1NTU1ODQzNjMwLWhkZWwyN3NxMDM5ZjFwMmZ0aGE2M2VvcWFpY2JwamZoLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t")));
    private static final String CLIENT_SECRET = System.getProperty("ext.gdata.clientsecret", new String(Base64.getDecoder().decode("R2V2TnZiTnA2a3IxeDd5c3VZNENmYlNo")));
```

The Base64 encoding can then be decoded to obtain the client id and client secret.
Those credentials can then be used by other applications to request access to Google accounts, pretending they are OpenRefine. This assumes that they also get access to the user access tokens, which this vulnerability doesn't expose by itself.

### Patches

The bundled credentials should be revoked.

### Workarounds

Users should revoke access to their Google account if they have connected it to OpenRefine.


---

## R090

**Package:** gitea.dev

**Summary:** Gitea: Webhooks created by a collaborator keep firing after their repo access is revoked → ongoing real-time exfiltration of private repo content

## Affected product
Gitea — `services/repository/collaboration.go` (`DeleteCollaboration`) + webhook delivery

## Summary
When a collaborator with admin permission on a private repo creates a webhook, that webhook keeps firing
after the collaborator's access is revoked. Gitea's revocation cleanup `DeleteCollaboration` removes the
collaboration record, recalculates accesses, drops watches, and unassigns issues — but it does **not**
remove or disable webhooks the user created, and webhook delivery never re-checks whether the creator still
has repo access. The former collaborator therefore receives the full payload (issue/comment bodies, commit
data) of all future repository events at their controlled endpoint, indefinitely and invisibly.

## Affected code
- `services/repository/collaboration.go` → `DeleteCollaboration()` — cleans watches/assignees only; no
  webhook cleanup.
- Webhook delivery path — fires on repo events without re-validating the creator's current access.

## Steps to reproduce
Using the provided reproduction materials:
1. Attacker (admin collaborator) creates a webhook → revoke access.
2. Control: `GET /api/v1/repos/admin/wh-repo` (attacker) → **404**.
3. `GET .../hooks` → webhook still `active=true`.
4. Admin creates a new issue **after** revocation → the catcher receives `action:"opened"`,
   `issue.title:"CRITICAL SECRET: …"`, `issue.body` (sentinel private key), `repository.private:true`.
(Runtime-confirmed on `gitea/gitea:1.25.4`. Catcher is an internal sentinel listener; the payload is a
planted sentinel, not real data; nothing is sent to any external/metadata endpoint.)

## Impact
Authenticated former admin-collaborator → ongoing real-time exfiltration of private content created after
revocation; invisible to the owner; scope crosses from the application boundary to data the user should no
longer access.

## Suggested remediation
1. On revocation, delete/disable webhooks created by the removed collaborator (or hand them to the owner).
2. Re-validate the creator's current repo access before each webhook delivery.
3. At minimum, warn admins on revocation if the user created webhooks.

## Credit
Reported as part of an incomplete-patch / authorization-residue measurement study (responsible disclosure).

---

## R091

**Package:** typo3/cms-core

**Summary:** TYPO3 Install Tool vulnerable to Code Execution

### Problem
Several settings in the Install Tool for configuring the path to system binaries were vulnerable to code execution. Exploiting this vulnerability requires an administrator-level backend user account with system maintainer permissions.

The corresponding change for this advisory involves enforcing the known disadvantages described in [TYPO3-PSA-2020-002: Protecting Install Tool with Sudo Mode](https://typo3.org/security/advisory/typo3-psa-2020-002).

### Solution
Update to TYPO3 versions 8.7.57 ELTS, 9.5.46 ELTS, 10.4.43 ELTS, 11.5.35 LTS, 12.4.11 LTS, 13.0.1 that fix the problem described.

### Credits
Thanks to Rickmer Frier & Daniel Jonka who reported this issue and to TYPO3 core & security team member Benjamin Franzke who fixed the issue.

### References
* [TYPO3-CORE-SA-2024-002](https://typo3.org/security/advisory/typo3-core-sa-2024-002)

---

## R092

**Package:** open-webui

**Summary:** Open WebUI: Scheduled automations continue after pending-user deactivation and stored model ACL revocation

**Title:** Scheduled automations continue after pending-user deactivation and stored model ACL revocation

### Summary

Open WebUI documents `pending` as a zero-access role used for new sign-ups and deactivated users, and normal HTTP routes enforce that with `get_verified_user()` (which rejects `pending`), while automation create/update/run routes additionally require the `features.automations` permission. Two paths missed that lifecycle gate, so a deactivated (`pending`) account could keep acting through the background automation scheduler:

1. **Scheduler did not re-gate the owner.** When a stored automation became due, `execute_automation()` rehydrated the owner with `Users.get_user_by_id(...)` and re-entered the chat completion pipeline without re-checking that the owner was still `user`/`admin` or still held `features.automations`. A still-active automation therefore kept running after its owner was deactivated.
2. **Model ACL only enforced for exact role `user`.** `check_model_access()` applied private-model grants only when `user.role == "user"`, so a `pending` principal fell through a branch that denies a normal non-owner `user`.

Net effect: a deactivated account could continue scheduled chat generation through the background worker, consuming the operator's configured model-provider credentials and reaching a stored automation model ID that its current role/ACL state would no longer permit through normal routes.

### Impact

A `pending`/deactivated account continues to execute due scheduled automations after its access has been revoked, consuming the operator's provider credentials, quota and shared capacity, and bypassing the private-model ACL for the automation's stored model ID. Exploitation requires a previously created active automation and a later transition to `pending` (deactivation or approval rollback), so it is bounded and not interactive. It does not grant unauthenticated access, account takeover, code execution, or cross-user data exfiltration.

### Patched

In 0.10.0:

- `execute_automation()` aborts and records an error unless the rehydrated owner is still `user` or `admin` and (for non-admins) still holds `features.automations`, so a deactivated or de-permissioned owner's due automation no longer runs.
- `check_model_access()` enforces model ACLs for every non-admin role rather than only the exact role `user`, so a `pending` or otherwise unrecognised role no longer falls through.

### Credits

@rexpository

---

## R093

**Package:** github.com/coder/coder/v2

**Summary:** Suspended Coder users retain access to AI Bridge LLM proxy endpoints

### Summary

AI Bridge proxy endpoints authenticate via `Server.IsAuthorized` in `coderd/aibridgedserver`, which validates key format, expiry, secret and deleted or system users but does not check whether the account is suspended. Because suspension does not revoke existing API keys, a suspended user's unexpired token keeps working.

> **Note:** Practical impact is limited to already-issued API keys of suspended users until those keys are deleted.

### Impact

A suspended user with a previously issued long-lived token could continue calling AI Bridge LLM proxy endpoints, consuming paid provider resources billed to the deployment and, if injected MCP tools are enabled, invoking those tools. Access persists until the token expires, which may be months after suspension.

### Patches

The fix makes AI Bridge authorization reject non-active users like the standard API key middleware. AI Bridge was introduced in v2.30.0. The v2.29 ESR line is not affected.

The fix is available in the following releases:

| Release line | Patched version |
|---|---|
| 2.34 | [v2.34.2](https://github.com/coder/coder/releases/tag/v2.34.2) |
| 2.33 | [v2.33.8](https://github.com/coder/coder/releases/tag/v2.33.8) |
| 2.32 | [v2.32.7](https://github.com/coder/coder/releases/tag/v2.32.7) |

### Workarounds

On suspension, delete the user's API keys via `DELETE /api/v2/users/{user}/keys`.

### Resources

- Fix: #26173

### Credits

Coder would like to thank Anthropic's Security Team (ANT-2026-22446) for independently disclosing this issue!

---

## R094

**Package:** @openzeppelin/contracts-upgradeable

**Summary:** TimelockController vulnerability in OpenZeppelin Contracts

### Impact

A vulnerability in `TimelockController` allowed an actor with the executor role to take immediate control of the timelock, by resetting the delay to 0 and escalating privileges, thus gaining unrestricted access to assets held in the contract. Instances with the executor role set to "open" allow anyone to use the executor role, thus leaving the timelock at risk of being taken over by an attacker.

### Patches

A fix is included in the following releases of `@openzeppelin/contracts` and `@openzeppelin/contracts-upgradeable`:
- 4.3.1
- 3.4.2
- 3.4.2-solc-0.7

Deployed instances of `TimelockController` should be replaced with a fixed version by migrating all assets, ownership, and roles.

### Workarounds

Revoke the executor role from accounts not strictly under the team's control. We recommend revoking all executors that are not also proposers. When applying this mitigation, ensure there is at least one proposer and executor remaining.

### References

[Post-mortem](https://forum.openzeppelin.com/t/timelockcontroller-vulnerability-postmortem/14958).

### Credits

The issue was identified by an anonymous white hat hacker through [Immunefi](https://immunefi.com/).

### For more information

If you have any questions or comments about this advisory, or need assistance executing the mitigation, email us at security@openzeppelin.com.


---

## R095

**Package:** rustls-webpki

**Summary:** webpki: CRLs not considered authoritative by Distribution Point due to faulty matching logic

If a certificate had more than one `distributionPoint`, then only the first `distributionPoint` would be considered against each CRL's `IssuingDistributionPoint` `distributionPoint`, and then the certificate's subsequent `distributionPoint`s would be ignored.

The impact was that correct provided CRLs would not be consulted to check revocation. With `UnknownStatusPolicy::Deny` (the default) this would lead to incorrect but safe `Error::UnknownRevocationStatus`. With `UnknownStatusPolicy::Allow` this would lead to inappropriate acceptance of revoked certificates.

This vulnerability is thought to be of limited impact. This is because both the certificate and CRL are signed -- an attacker would need to compromise a trusted issuing authority to trigger this bug.  An attacker with such capabilities could likely bypass revocation checking through other more impactful means (such as publishing a valid, empty CRL.)

More likely, this bug would be latent in normal use, and an attacker could leverage faulty revocation checking to continue using a revoked credential.

---

## R096

**Package:** @nocobase/auth

**Summary:** Authentication Bypass via Default JWT Secret in NocoBase docker-compose Deployments

### Impact

CVE-2025-13877 is an **authentication bypass vulnerability caused by insecure default JWT key usage** in NocoBase Docker deployments.

Because the official one-click Docker deployment configuration historically provided a **public default JWT key**, attackers can **forge valid JWT tokens without possessing any legitimate credentials**. By constructing a token with a known `userId` (commonly the administrator account), an attacker can directly bypass authentication and authorization checks.

Successful exploitation allows an attacker to:

- Bypass authentication entirely
- Impersonate arbitrary users
- Gain full administrator privileges
- Access sensitive business data
- Create, modify, or delete users
- Access cloud storage credentials and other protected secrets

The vulnerability is **remotely exploitable**, requires **no authentication**, and **public proof-of-concept exploits are available**.  
This issue is functionally equivalent in impact to other JWT secret exposure vulnerabilities such as **CVE-2024-43441** and **CVE-2025-30206**.

Deployments that used the default Docker configuration without explicitly overriding the JWT secret are affected.

---

### Patches

✅ The vulnerability has been **fully patched** through a secure JWT key management redesign.

The remediation enforces the following security guarantees:

- JWT secrets are no longer allowed to fall back to public default values.
- Secrets must either:
  - Be explicitly provided by the user, or
  - Be securely generated using cryptographically strong randomness at first startup.
- Generated secrets are persisted securely with restricted filesystem permissions.
- Invalid or weak secret values immediately trigger a startup failure.

✅ Fixed Versions:
- **NocoBase ≥ 1.9.23**
- **NocoBase ≥ 1.9.0-beta.18**
- **NocoBase ≥ 2.0.0-alpha.52**

---

### Workarounds

If upgrading is not immediately possible, the following temporary mitigations **must** be performed to reduce risk:

1. Explicitly set a **strong, randomly generated JWT secret** via environment variables `APP_KEY`.
2. **Restart all running NocoBase instances** so the new secret takes effect.
3. **Invalidate all existing JWT sessions**, forcing complete user re-authentication.
4. Verify that **no default secret values** are present in:
   - `docker-compose.yml`
   - `.env` files
   - Kubernetes Secrets

---

### References

- **CVE Record:** CVE-2025-13877  
- **VulDB Entry:** https://vuldb.com/?id.334033  
- **Public Exploit [...truncated]

---

## R097

**Package:** snipe/snipe-it

**Summary:** Insufficient Session Expiration in snipe/snipe-it 

Session Fixation in GitHub repository snipe/snipe-it prior to version 6.0.10. The session is not invalidated after a password change.

---

## R098

**Package:** @openzeppelin/contracts

**Summary:** TimelockController vulnerability in OpenZeppelin Contracts 

### Impact

A vulnerability in `TimelockController` allowed an actor with the executor role to take immediate control of the timelock, by resetting the delay to 0 and escalating privileges, thus gaining unrestricted access to assets held in the contract. Instances with the executor role set to "open" allow anyone to use the executor role, thus leaving the timelock at risk of being taken over by an attacker.

### Patches

A fix is included in the following releases of `@openzeppelin/contracts` and `@openzeppelin/contracts-upgradeable`:
- 4.3.1
- 3.4.2
- 3.4.2-solc-0.7

Deployed instances of `TimelockController` should be replaced with a fixed version by migrating all assets, ownership, and roles.

### Workarounds

Revoke the executor role from accounts not strictly under the team's control. We recommend revoking all executors that are not also proposers. When applying this mitigation, ensure there is at least one proposer and executor remaining.

### References

[Post-mortem](https://forum.openzeppelin.com/t/timelockcontroller-vulnerability-postmortem/14958).

### Credits

The issue was identified by an anonymous white hat hacker through [Immunefi](https://immunefi.com/).

### For more information

If you have any questions or comments about this advisory, or need assistance executing the mitigation, email us at security@openzeppelin.com.


---

## R099

**Package:** github.com/lin-snow/ech0

**Summary:** ech0's acess tokens with expiry=never cannot be revoked: logout panics, delete does not blacklist JTI

## Summary

Access tokens created with the "never expire" option have no `exp` JWT claim. Three independent revocation mechanisms fail for this token type. Logout at `internal/handler/auth/auth.go:154` and `:163` dereferences `claims.ExpiresAt.Time`, panicking on the nil field so the token never hits the blacklist. `RevokeToken` at `internal/repository/auth/auth.go:45-50` skips when `remainTTL <= 0`. The admin's "Delete token" panel action at `internal/service/setting/access_token_service.go:183-185` removes the database record but does not call `RevokeToken` to blacklist the JTI. Once a never-expire token leaks, the JWT stays cryptographically valid until the admin rotates the signing key across the entire instance.

## Details

Creation path at `internal/util/jwt/jwt.go:103-105`:

```go
// expiry = 0 表示永不过期
if expiry > 0 {
    claims.ExpiresAt = jwt.NewNumericDate(time.Now().UTC().Add(time.Duration(expiry) * time.Second))
}
```

For `NEVER_EXPIRY`, `expiry = 0` and the conditional skips. The resulting JWT has no `exp` claim. The middleware at `internal/middleware/auth.go` accepts it; the `jwt/v5` parser does not require `exp` by default.

Failure mode 1, logout panic at `internal/handler/auth/auth.go:163`:

```go
// Refresh-token revocation at line 154 (safe in practice: refresh tokens always have exp).
// Access-token revocation, same pattern, at line 163 (the bug):
if claims, err := jwtUtil.ParseToken(authHeader[7:]); err == nil && claims.ID != "" {
    remaining := time.Until(claims.ExpiresAt.Time)  // nil deref when ExpiresAt is nil
    h.authService.RevokeToken(claims.ID, remaining)
}
```

For a never-expire access token, `claims.ExpiresAt` is nil. `claims.ExpiresAt.Time` panics. Gin's Recovery middleware catches it and returns HTTP 500; the JTI never reaches `RevokeToken`. Line 154 shares the same pattern against refresh tokens, but refresh tokens are always issued with an expiry so the nil dereference does not fire there in practice.

Failure mode 2, `RevokeToken` skip at `internal/repository/auth/auth.go:45-50`:

```go
func (authRepository *AuthRepository) RevokeToken(jti string, remainTTL time.Duration) {
    if jti == "" || remainTTL <= 0 {
        return
    }
    authRepository.cache.SetWithTTL(fmt.Sprintf("%s%s", blacklistPrefix, jti), true, 1, remainTTL)
}
```

Even if the logout path were patched to handle nil `ExpiresAt`, a caller computing `remainTTL = 0` would still skip the blacklist write.

Failure mode 3, admin delete at `internal/se [...truncated]

---

## R100

**Package:** github.com/mattermost/mattermost/server/v8

**Summary:** Mattermost fails to properly invalidate personal access tokens upon user deactivation

Mattermost versions 10.7.x <= 10.7.0, 10.6.x <= 10.6.2, 10.5.x <= 10.5.3, 9.11.x <= 9.11.12 fails to properly invalidate personal access tokens upon user deactivation, allowing deactivated users to maintain full system access by exploiting access token validation flaws via continued usage of previously issued tokens.

