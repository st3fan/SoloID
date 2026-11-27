# SoloID: design plan

A tiny self-hosted OpenID Connect provider, deployed as one Docker Compose service
behind an existing HTTPS reverse proxy. One JSON file configures multiple users
and apps, including Argon2id password hashes. No database or runtime disk writes.

## Scope

- Email/password sign-in and shared browser sessions across configured apps.
- The operator manages users, passwords, clients, and keys in the JSON file.
- No signup, password reset, second factor, web admin UI, or consent screen.
- No refresh tokens in v1. No implicit/hybrid flow, dynamic registration,
  introspection, token revocation endpoint, request objects, or PAR.
- Run one long-lived process/replica. Not serverless or horizontally replicated.
- Target standard authorization-code clients that support mandatory PKCE S256.
  Compatibility must be tested per app; this is not an OpenID-certified provider.

## Stack

| Concern | Choice |
| --- | --- |
| Runtime | Node 22, strict TypeScript |
| HTTP | Hono + `@hono/node-server` |
| HTML | Server-rendered `hono/jsx`; no browser JavaScript |
| Styling | Tailwind CSS v4 CLI, one stylesheet; simple card/input/button/alert UI inspired by shadcn/ui, without React |
| JWTs / JWKS | `jose`, RS256 signatures |
| Passwords | `@node-rs/argon2`, Argon2id PHC strings |
| Configuration | Zod schema, validated at startup and reload |
| Login failure counter | `rate-limiter-flexible`, `RateLimiterMemory` |
| CLI | Node `parseArgs`; shares config and hashing code with the server |
| Build / tests | tsup, tsx, Vitest, `openid-client` |
| Packaging | Multi-stage Docker build, distroless Node 22 non-root runtime |

Hono replaces the earlier Next.js/App Router choice. A React component library
adds no value to these server-rendered forms, so shadcn/ui is a visual reference,
not a dependency.

## State: no persistent state, not zero state

**Correction to the original plan:** PKCE does not make a replayable authorization
code safe. OAuth requires authorization codes to be single-use. Store opaque codes
in memory rather than using stateless encrypted codes.

| State | Location | Lifetime / consequence |
| --- | --- | --- |
| Users, clients, hashes, keys | Read-only JSON config | Operator-managed; the only durable state |
| Browser session | Signed HttpOnly cookie | Default 12 hours; survives restart with unchanged config |
| Pending authorization / CSRF | Signed cookie | 10 minutes; a new transaction replaces the old one in that browser |
| Logout confirmation / CSRF | Signed cookie | 10 minutes |
| Authorization codes | In-process map, indexed by code digest | Random 256-bit values; 60 seconds, atomic single use, maximum 10,000 |
| Access / ID tokens | Signed JWTs held by the client | 15 minutes / 5 minutes |
| Failed-login counts and locks | In-process memory, keyed by normalized email | One-hour counting window, 15-minute lockout; cleared on restart |
| Login queues / hashing concurrency | In-process memory | Serialize attempts per email and bound native memory use |

Reloading a validated config atomically replaces the runtime and clears pending
codes while retaining failure counters. Restarting clears both. Neither requires
a database; already-issued cookies and tokens survive if their keys and user
credentials are unchanged. A code exchange interrupted by restart/reload must
restart authorization.

Cookies are signed, not encrypted: they contain no passwords or private keys.
Use an HKDF-derived cookie key from the config's 32-byte random `secret`, with
distinct token types/audiences for session, pending-login, and logout cookies.
Tokens use a separate RSA signing key. Subjects are explicit, stable user IDs,
not emails or values derived from a rotating secret.

Check current configuration at authorization, token exchange, and `/userinfo`.
Removing a user/client or restricting an app blocks further provider access.
Bind sessions and access tokens to an HMAC of the current password hash; password
changes revoke that user's provider session and `/userinfo` access. Changing
`secret` revokes all such access, without changing user IDs. Existing app sessions
and externally verified ID tokens are not retroactively revoked.

Logout clears the browser cookies after confirmation. There is no server-side
session registry and no individual revocation of copied cookies. No coordinated
front-channel/back-channel logout of apps.

## Login failures and timing

| Situation | Message | Status |
| --- | --- | --- |
| Unknown email, wrong password, empty credentials, or user not allowed for the app | **Login Failed** | 401 |
| Email is locked | **Login Failed (Rate Limited)** | 429 plus `Retry-After` |

Refill the email as typed; never refill or reflect the password. Known-user and
unknown-user failures use the same form and status. HTML is not literally
byte-identical across transactions: the email and CSRF token differ. Invalid
transactions/CSRF and resource overload are separate protocol errors, not password
failure diagnoses.

For every ordinary, non-locked attempt, select the stored hash or a dummy hash,
then run the same Argon2id verifier before deciding success. Generate the dummy
hash from a random password when preparing the runtime. Require identical PHC
parameters for all configured hashes: Argon2id v19, 64 MiB, 3 passes, 4 lanes,
16-byte salt, 32-byte output. Unknown clients at `/token` also use a dummy check.

**Equal work is the objective, not an exact wall-clock guarantee.** Scheduling,
network noise, queue contention, lookup, and success redirects differ. Locked
attempts skip Argon2 equally for known and unknown emails. Overlong requests are
rejected before hashing for either kind of account. Cap passwords at 1024 UTF-8
bytes, emails at 254 characters, request bodies at 16 KiB, and URLs at 8192
characters. The CLI requires new passwords of at least 12 characters.

Run a diagnostic alternating wrong passwords for known users and unknown emails,
with warmup and 100 samples per group; report median/p95. Do not assert statistical
indistinguishability or put a fragile timing threshold in CI.

## Failed-login limiter

**Never key this limiter by IP.** Trim and lowercase the submitted email; apply
identical counting and lockout behavior to configured and nonexistent emails.
The defaults are fixed constants, not configuration knobs:

- Five failed passwords in a one-hour window starting at the first failure.
- The fifth failure returns `Login Failed` and starts a 15-minute lockout.
- Subsequent attempts, including correct passwords, return
  `Login Failed (Rate Limited)` until the lock expires. Retries do not extend it.
- After lock expiry, start a fresh count. A successful authorized login clears
  that email's failures. Correct credentials for a disallowed app fail generically,
  do not increase the counter, and create no session.
- Serialize attempts for the same email so parallel requests cannot evade the
  threshold. Retain counters across valid and failed config reloads.
- Bound tracked identities at 10,000, pending login attempts at 32, and concurrent
  native password verifications at two, including client-secret verification.
  Capacity exhaustion fails closed with 503 and `Retry-After`. Expiry alone is
  not a sufficient memory bound.

Tradeoffs: someone who knows an email can deliberately lock it. Rotating emails
can still consume CPU or fill the bounded identity table. Use infrastructure
resource limits for availability. A valid existing SSO session does not require
another password attempt and is not blocked by a password lockout.

## Configuration and CLI

The schema and example live in `src/config.ts` and `deploy/config.example.json`.
The example intentionally has invalid placeholders; `init` creates real keys.

- `issuer`: HTTPS origin, no path/query/trailing slash; HTTP localhost for dev.
- `secret`: canonical base64url encoding of 32 random bytes.
- `signing_key`: RSA private JWK, at least 2048 bits. Derive `kid` as its public
  RFC 7638 thumbprint. JWKS never exports private components.
- `previous_public_keys`: old public RSA keys retained during rotation.
- `session_ttl`: defaults to `12h`, up to 30 days.
- `users`: nonempty list of unique stable `id`, unique normalized `email`, optional
  `name`, `password_hash`, and `email_verified` (defaults false). The operator must
  actually verify email ownership before setting the last field true.
- `clients`: nonempty list of unique `client_id`, optional display `name`, exact
  `redirect_uris`, optional `post_logout_redirect_uris`, and either a hashed secret
  or `public: true`. Every client uses PKCE S256. Optional `allowed_users` contains
  **user IDs**; omitted means all users, empty means none.

Reject unknown fields, invalid keys/hashes, duplicates, dangling user references,
wildcards/fragments/credentials in redirect URLs, and inconsistent client auth.
Only HTTPS and HTTP localhost callbacks are supported, not custom native schemes.

CLI commands, bundled into `dist/cli.js`:

- `init`: print a skeleton with fresh cookie secret, RSA key, and user UUID.
- `hash`: prompt twice without echo; `--stdin` supports scripted input. Never
  accept a password as a command-line argument.
- `gen-secret`: print a random client secret and its Argon2id hash. Give the raw
  secret to the client, store only the hash in SoloID.
- `check --config PATH`: validate config without starting a server.

`SOLOID_CONFIG` selects the file. SIGHUP reloads it; invalid reloads retain the
previous runtime. Configuration and backups contain private keys and must not be
committed, logged, or world-readable.

## Protocol and browser flow

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery |
| `GET /jwks.json` | Current and retained public signing keys |
| `GET /authorize` | Authorization code request |
| `GET, POST /login` | Email/password form |
| `POST /token` | Single-use code exchange |
| `GET, POST /userinfo` | Scope-filtered claims using an access token |
| `GET, POST /logout` | Confirm and end the browser session |
| `GET /healthz`, `GET /app.css` | Health and static styling |

1. Validate client and exact registered callback before redirecting any error.
   Reject duplicate parameters. Require `response_type=code`, `openid`, and S256.
   Preserve `state`/`nonce` and include issuer identification in the callback.
2. Reuse a valid session unless `prompt=login`, `select_account`, or `max_age`
   requires reauthentication. `prompt=none` returns `login_required` if interaction
   is necessary. Explicit consent requests return `consent_required`.
3. Store the pending request and random CSRF token in a signed cookie. Login POST
   requires both the matching form token and exact configured issuer `Origin`.
4. On success, set the session cookie and issue a random code. Return a 303 to
   the registered callback. No password or token appears in HTML or logs.
5. `/token` accepts form-encoded authorization-code grants. Authenticate the client
   with Basic/Post secret or `none` for public clients. Atomically consume the code
   and validate expiry, client, exact callback, PKCE verifier, user, and current
   app authorization. Reject replay, including concurrent exchange attempts.
6. Sign an RS256 ID token (`JWT` type, client audience) and access token (`at+jwt`
   type, `/userinfo` audience). Never accept one token type as the other.
7. `/userinfo` verifies the token and current config. Expose `email` and
   `email_verified` only for the email scope; `name` only for profile. Always `sub`.

ID tokens include issuer, subject, audience, issued/expiry times, `auth_time`, and
the requested nonce. Access tokens are for SoloID `/userinfo`, not arbitrary app
APIs. Ignore and do not grant `offline_access`; never return a refresh token.

Logout accepts a registered `client_id` or verified `id_token_hint` and optional
registered post-logout URI/state. Always require CSRF-protected user confirmation,
including for expired but correctly signed ID-token hints.

## Browser and HTTP defenses

- HTTPS cookies: `__Host-` prefix, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain.
  HTTP localhost omits the prefix/Secure flag only for development.
- CSP blocks scripts, framing, and base URL changes; styles load from self.
  Omit `form-action` deliberately because browser enforcement on the post-login
  redirect can otherwise block app callbacks. Forms have fixed same-origin actions.
- Send `no-store`, `Referrer-Policy: same-origin`, `nosniff`, and
  `X-Frame-Options: DENY`. `no-referrer` suppresses Origin on browser form POSTs;
  `same-origin` preserves CSRF checks without sending referrers to external apps.
- CORS on protocol endpoints allows only origins of registered callbacks; do not
  allow credentialed cross-origin login/logout.
- Emit JSON outcome logs with normalized email, not passwords, tokens, codes, or
  key material. Emails are personal data. Proxy query logging needs separate care.

## Docker Compose and existing proxy

Ship `Dockerfile` and `deploy/compose.yaml`, with **only SoloID**. Do not deploy
Caddy or another proxy. The README includes Caddy examples for an existing proxy
on the host and one on a shared external Docker network.

- Multi-stage image: build TypeScript/CSS, retain production dependencies only,
  run as distroless non-root UID/GID 65532 with read-only root filesystem.
- Drop capabilities, set no-new-privileges; no writable volumes/tmpfs needed.
- Mount `./config:/config:ro` as a directory so atomic file replacement works.
  Directory mode 0750 and file mode 0640 with a readable group are suitable on a
  conventional Linux host. Directories require execute permission.
- Listen on port 3000; publish only `127.0.0.1` by default. For a remote proxy,
  bind a private interface and firewall access. For Docker networking, remove
  port publication and join the existing external proxy network.
- Proxy terminates HTTPS, serves the issuer at its own hostname/root, preserves
  cookies, and does not cache. Do not trust forwarded addresses for authentication.
- Build locally until images are published. CI tests pushes and PRs. A separate
  maintainer-triggered `v*` tag workflow publishes a GHCR image; no PR deployment.

## Verification and delivery

Deliver as one pull request with code, config example, CLI, deployment, tests,
and operational README. Do not merge or publish a release as part of the PR.

- Type-check, compile the server/CLI and CSS, then run HTTP contract tests.
- Cover redirect injection, duplicate parameters, CSRF/cookie forgery, scope and
  token-type separation, client authentication, PKCE, replay, expiry, SSO/logout,
  restrictions, and config changes. Test both known and unknown email lockouts,
  expiry boundaries, reset, and concurrent failures.
- Use a real server and `openid-client` to exercise discovery, login, code exchange,
  ID-token signature verification through JWKS, and userinfo. Exercise CLI and HUP.
- Build and boot Compose, validate health/discovery/public JWKS/CSS and container CLI.
- Inspect rendered login, failure, lockout, narrow layout, and logout states in a
  browser, including keyboard/pointer interaction. No browser JavaScript is required.
- Keep the timing diagnostic separate from deterministic CI assertions. Do not
  claim protocol certification or app interoperability that has not been tested.

## UX without refresh tokens

Server-side apps often keep their own sessions after login. Their session lifetime
is independent of SoloID's token lifetimes. When a new token is needed, the app
redirects through `/authorize`; an active SoloID session usually avoids another
password prompt, but the redirect still happens. Forced login or expired sessions
require credentials, and clients that require refresh tokens may be incompatible.

SPAs needing a fresh `/userinfo` access token must navigate through authorization
after 15 minutes, potentially losing unsaved state unless they preserve it. Hidden
iframe renewal is not supported (framing is denied and cookies are SameSite=Lax).
Native/CLI apps may reopen a browser and cannot renew credentials unattended;
custom-scheme native callbacks are also outside v1. No promise of seamless
background renewal. A future refresh-token design must address rotation, replay
detection, and revocation rather than simply issuing long-lived stateless tokens.
