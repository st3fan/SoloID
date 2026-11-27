# SoloID: design plan

A tiny OpenID Connect provider that you self-host with Docker Compose. It reads one JSON config file, signs users in with email and password, and serves several apps (OIDC clients). It keeps no lasting state: no database and no runtime writes to disk.

## Goals and non-goals

**Goals**

- **Simple:** a small Hono server with a handful of dependencies and no client-side JavaScript.
- **Self-hosted with Docker Compose:** one container (one long-lived Node process), started with `docker compose up -d`. There is no other supported way to deploy it.
- **Runs behind an existing reverse proxy.** The environment already has a reverse proxy that terminates TLS, outside this deployment. SoloID's Compose file doesn't include a proxy.
- Configured with one JSON file, which holds every secret and key.
- **Stateless:** nothing persists between requests except the config. A restart never breaks sign-in.
- **Several users:** the config holds a list of users. Each signs in with email and password, and each password is stored in the config as an **Argon2id** hash.
- Login failures never reveal whether an email exists, through either the error message or the response time.
- Several apps, each with its own client ID, secret, and redirect URIs.
- Works with standard OIDC client libraries (Grafana, Gitea, oauth2-proxy, Nextcloud, openid-client, and so on).

**Non-goals for v1:** refresh tokens (see Known limitations), a second factor (TOTP, WebAuthn), sign-up, password reset, a web admin UI, LDAP or social login, implicit and hybrid flows, dynamic client registration, and a consent screen. The owner configures every app, so the provider trusts all of them.

## Technology

| Concern | Choice | Notes |
| --- | --- | --- |
| Runtime | **Node 22 LTS**, TypeScript (strict) | |
| HTTP | **Hono** + `@hono/node-server` | Routing, cookies (`hono/cookie`), CSRF origin check (`hono/csrf`), CORS (`hono/cors`), static files |
| HTML | **`hono/jsx`**, rendered on the server | Two pages: login and error. No client JavaScript at all. |
| Styling | **Tailwind CSS v4**, built with `@tailwindcss/cli` into one static `app.css` | The pages borrow shadcn/ui's look (card, input, button, destructive alert) by reusing its Tailwind classes. shadcn itself isn't used because it needs React. |
| Tokens / JWKS | **`jose`** | Sign and verify RS256 tokens, encrypt authorization codes, export JWKS, compute key IDs |
| Password hashing | **`@node-rs/argon2`** | Argon2id with prebuilt binaries, so nothing compiles at install. Reads and writes PHC strings. |
| Config validation | **Zod** | One schema that validates the config and supplies its TypeScript types |
| Failed-login limiting | **`rate-limiter-flexible`** (`RateLimiterMemory`) | No dependencies of its own. Has a documented brute-force protection pattern. |
| CLI | `node:util` `parseArgs` | |
| Build / dev | `tsup` (bundles `server.ts` and `cli.ts`), `tsx watch` for development | |
| Tests | **Vitest** + **`openid-client`** | Hono's `app.request()` for handler tests |

- Runtime dependencies: `hono`, `@hono/node-server`, `jose`, `@node-rs/argon2`, `zod`, `rate-limiter-flexible`.
- Packaging: a multi-stage `Dockerfile` builds `dist/` and `app.css`, installs production dependencies only, and copies everything into a distroless Node 22 image that runs as non-root. It's published as `ghcr.io/st3fan/soloid`. See Deployment.
- TLS is the job of the existing reverse proxy. The README includes an example Caddy configuration.
- **One process.** SoloID runs as a single container. Don't scale it to several replicas: they wouldn't share the in-memory failure counter, which would make the limiter ineffective.

## State

**Decision:** SoloID has no lasting state. Every value it needs across requests is either in the config file or travels with the browser or the app in a signed or encrypted token. The only exception is the per-email failure counter for login limiting, which lives in memory and may be lost (see the last row).

| Thing | Where it lives | Consequence |
| --- | --- | --- |
| Keys | In the config: one `secret` (32 random bytes) and one RS256 `signing_key` (private JWK). The cookie, code-encryption, and `sub` keys are derived from `secret` with HKDF, using a different label for each key. | No files to generate or mount. The config file is sensitive, but it already holds the password hashes. |
| Login session | Signed cookie (email, `auth_time`, expiry) | Logout clears the cookie. A session can't be revoked on the server; changing `secret` ends all sessions. |
| Pending authorization request and CSRF token | Signed, short-lived cookie | None |
| Authorization code | An **encrypted token** (JWE, `dir` + A256GCM) with client ID, redirect URI, `sub`, nonce, PKCE challenge, `auth_time`, and a 60 s expiry | Codes can't be strictly single-use. This is mitigated by **requiring PKCE for every app**, client authentication for apps with a secret, and the 60 s expiry. It would fail the conformance suite's code-reuse test. |
| Access token | Signed JWT, 15 min | It can't be revoked before it expires. Removing a user from the config cuts them off at the next sign-in. |
| Refresh tokens | Not in v1 | Apps send the user back through `/authorize`, which is silent while the SoloID session lasts. Fine for server-side apps; see Known limitations for SPAs and native apps. |
| Failed-login counter | In memory, per email | Lost on restart. That only weakens limiting briefly and never breaks sign-in. |

**Revocation tools:** edit the config (remove a user, an app, or a redirect URI) and reload it. To kill everything at once, rotate `secret` and `signing_key`.

## Deployment (Docker Compose)

SoloID is deployed with Docker Compose as a single service. It sits behind a reverse proxy that is already set up in the environment and isn't part of this deployment. The repo ships `deploy/compose.yaml` and `deploy/config.example.json`.

```yaml
# compose.yaml
services:
  soloid:
    image: ghcr.io/st3fan/soloid:latest
    restart: unless-stopped
    environment:
      SOLOID_CONFIG: /config/config.json
    volumes:
      - ./config:/config:ro          # mount the directory, not the file (see below)
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
      interval: 30s
    ports:
      # Loopback only by default: the reverse proxy on this host connects to it.
      - "${SOLOID_BIND:-127.0.0.1}:${SOLOID_PORT:-3000}:3000"
```

**Connecting the existing reverse proxy**

- **Proxy on the same host:** it connects to `127.0.0.1:3000`. That's the default.
- **Proxy on another machine:** set `SOLOID_BIND` to the private interface address and firewall the port so only the proxy can reach it.
- **Proxy in another Compose project or Docker network:** remove `ports`, and attach SoloID to the proxy's network, which is declared `external: true`. The proxy then connects to `soloid:3000`. The README shows this variant.

**What the proxy must do**

- Terminate TLS for the issuer's host name (for example `id.example.com`). The issuer in the config must be that `https://` URL.
- Serve SoloID at the root of its own host name, not under a sub-path.
- Leave cookies and the `Set-Cookie` header untouched, and don't cache any SoloID response.

SoloID builds every URL from `issuer` and checks the login form's `Origin` against it, so it doesn't depend on `Host` or `X-Forwarded-*` headers.

**README: example Caddy configuration**

The README documents the proxy requirements above and includes this Caddy example (other proxies are left to the reader):

```
# Caddy on the same host
id.example.com {
  reverse_proxy 127.0.0.1:3000
}

# Caddy in Docker on a shared network
id.example.com {
  reverse_proxy soloid:3000
}
```

**Container details**

- The image runs as the distroless `nonroot` user with a read-only root filesystem. SoloID writes nothing at runtime, so it needs no tmpfs.
- The server listens on `0.0.0.0` and `PORT` (default 3000).
- The image's entrypoint is `node`, and the default command is `dist/server.js`. CLI commands run as `dist/cli.js …`.
- The healthcheck uses `node` because distroless images have no `curl` or `wget`.
- The config is mounted **read-only as a directory**. Editors and `git pull` replace files with new ones, and a single-file bind mount would keep showing the old file to the container.
- The port is bound to loopback by default, so nothing but the local reverse proxy can reach SoloID over plain HTTP.
- The config holds the signing key and secret: keep `config/` at mode 0600 or 0640 and out of Git (`deploy/.gitignore` ignores it).

**Operations**

| Task | Command |
| --- | --- |
| Create a config | `docker compose run --rm soloid dist/cli.js init > config/config.json` |
| Hash a password | `docker compose run --rm soloid dist/cli.js hash` |
| Create a client secret | `docker compose run --rm soloid dist/cli.js gen-secret` |
| Check the config after editing | `docker compose run --rm soloid dist/cli.js check --config /config/config.json` |
| Apply config changes without a restart | `docker compose kill -s HUP soloid` |
| Apply config changes with a restart | `docker compose restart soloid` (ends rate-limit lockouts, nothing else) |
| Upgrade | `docker compose pull && docker compose up -d` |
| Logs | `docker compose logs -f soloid` |

Because SoloID is stateless, restarts and upgrades log nobody out. Sessions, codes, and tokens stay valid as long as the config is unchanged.

## Login

### Failure messages

There are exactly two failure messages:

| Situation | Message | Status |
| --- | --- | --- |
| Unknown email, wrong password, user not in the app's `allowed_users`, empty field | **Login Failed** | 401 |
| The email is locked by the failure limiter | **Login Failed (Rate Limited)** | 429 |

- The message appears in a red alert box (shadcn's destructive alert style) above the form.
- The page and the response are byte-for-byte the same for an unknown email and for a wrong password. The email field is refilled exactly as typed in both cases.
- Nothing ever says "unknown user", "wrong password", or "not allowed for this app".
- A correct password for a user who isn't allowed in this app also shows **Login Failed**. It doesn't count as a failure and doesn't create a session.

### Equal timing for known and unknown emails

An unknown email goes through the same Argon2id verification as a known one. The only difference is the hash it is checked against.

- At startup, SoloID hashes a random 32-byte password once and keeps the result as the **dummy hash**. It uses the same Argon2 parameters as the users' hashes, so verifying it takes the same time.
- Config validation requires every `password_hash` to use the same Argon2 parameters, and `soloid check` reports any hash that differs. A user with a different `m`, `t`, or `p` would otherwise respond measurably faster or slower than an unknown email.
- The user lookup always produces a hash to verify against, so the code has no early return:

```ts
const user = users.get(normalize(email));            // Map lookup: microseconds either way
const hash = user?.passwordHash ?? dummyHash;
const passwordOk = await argon2.verify(hash, password);
const ok = user !== undefined && passwordOk;         // decided only after verify has run
```

- Argon2 verification takes about 50–100 ms and dominates the response time. The rest of the work is the same in both cases (render the page, consume the limiter). On success, the extra work is signing a cookie and a code, which takes microseconds and doesn't depend on whether the email exists.
- The input is normalized (trim and lowercase the email; cap the password at 1024 bytes) before any of this. That way, very long inputs can't create timing differences.

### Failed-login limiting

The count is kept **per email address**. IP addresses aren't used, because many users share one IP (carrier networks, VPNs, iCloud Private Relay) while one attacker can rotate through many.

```ts
const failures = new RateLimiterMemory({
  points: 5,              // 5 consecutive failures
  duration: 60 * 60,      // count expires 1 h after the first failure
  blockDuration: 15 * 60, // then locked for 15 min
});
```

Handling of `POST /login`:

1. `hono/csrf` rejects the request unless its `Origin` matches the issuer. Then SoloID checks the pending-request cookie and the CSRF token in the form.
2. Normalize the email to get the limiter key.
3. `failures.get(key)`. If the email is locked, show **Login Failed (Rate Limited)** right away, without verifying the password, even if the password is correct.
4. Verify the password as described above.
5. On success, `failures.delete(key)`, set the session cookie, and redirect (302) back to the app's `redirect_uri` with the code.
6. On failure, `failures.consume(key)` (a rejection only means the email is now locked) and show **Login Failed**.

Properties:

- **Unknown emails are counted and locked exactly like real ones.** So the rate-limited message doesn't reveal which emails exist either. Locked responses skip Argon2 for known and unknown emails alike, so they don't leak anything through timing.
- **Locked-out retries are cheap.** They never reach Argon2, so hammering a locked email doesn't load the CPU.
- **Memory stays bounded.** Keys expire on their own, so attempts with random emails don't pile up.
- **Known trade-off:** anyone who knows a user's email can keep that account locked by failing on purpose. That's annoying but never grants access. A possible mitigation if it matters later: let a browser that still has a valid SoloID session skip the lockout.
- **The limits are fixed:** 5 failures, a 1 h counting window, and a 15 min lockout. They're constants in `src/login.ts` and deliberately not configurable.

## Configuration file

```json
{
  "issuer": "https://id.example.com",
  "secret": "base64url-encoded 32 random bytes",
  "signing_key": { "kty": "RSA", "kid": "…", "n": "…", "e": "AQAB", "d": "…", "p": "…", "q": "…", "dp": "…", "dq": "…", "qi": "…" },
  "previous_public_keys": [],
  "session_ttl": "12h",
  "users": [
    {
      "email": "stefan@example.com",
      "name": "Stefan Arentz",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$hashhashhash"
    },
    {
      "email": "alex@example.com",
      "name": "Alex Example",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$..."
    }
  ],
  "clients": [
    {
      "client_id": "grafana",
      "client_secret_hash": "$argon2id$v=19$m=65536,t=3,p=4$...",
      "redirect_uris": ["https://grafana.example.com/login/generic_oauth"],
      "allowed_users": ["stefan@example.com"]
    },
    {
      "client_id": "my-spa",
      "public": true,
      "redirect_uris": ["https://app.example.com/callback"]
    }
  ]
}
```

**Rules**

- `users` is a list with at least one entry. Emails are compared case-insensitively and must be unique. `name` is optional and is returned as the `name` claim.
- Hashes use the PHC string format. The default parameters are m=64 MiB, t=3, p=4 (OWASP baseline or stronger). Every `password_hash` must use the same parameters (see Login).
- Client secrets are hashed the same way. Plaintext secrets never appear in the config.
- `public: true` marks a client with no secret (SPA, native app). Every client must use PKCE `S256`.
- `allowed_users` is optional. When it is absent, every configured user may sign in to that app.
- `previous_public_keys` keeps an old key in JWKS during a key rotation until tokens signed with it have expired.
- Startup validation fails fast with a clear error for:
  - an `issuer` that isn't HTTPS (`http://localhost` is allowed),
  - a missing or short `secret`,
  - an invalid signing key,
  - duplicate emails or client IDs,
  - malformed hashes or mismatched password-hash parameters,
  - redirect URIs with wildcards or fragments,
  - an app (client) that is neither public nor has a secret.
- The config path comes from the `SOLOID_CONFIG` environment variable (`/config/config.json` in the Compose setup).
- `SIGHUP` reloads the config. If the new config fails validation, SoloID keeps the old one and logs the error.

## CLI

```
soloid init                       # prints a config skeleton with a fresh secret and signing key
soloid hash                       # prompts twice without echo, prints an Argon2id PHC string
soloid gen-secret                 # prints a random client secret and its hash
soloid check  --config ...        # validates the config and exits
```

The CLI is `src/cli.ts`. It shares `src/config.ts` and `src/password.ts` with the server, is bundled into `dist/cli.js`, and ships in the same image. It runs through Compose, for example `docker compose run --rm soloid dist/cli.js hash`. See Deployment for the full list.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /jwks.json` | Public signing key(s) |
| `GET /authorize` | Starts the authorization code flow |
| `GET, POST /login` | Email and password form |
| `POST /token` | Exchanges an authorization code for tokens |
| `GET, POST /userinfo` | Claims for a bearer access token |
| `GET /logout` | RP-initiated logout (`post_logout_redirect_uri` must be registered) |
| `GET /healthz` | Liveness check |
| `GET /app.css` | The compiled Tailwind stylesheet |

`/token` and `/userinfo` send CORS headers through `hono/cors`, allowing the origins of the registered redirect URIs, so public SPA clients can call them.

**Supported:** `response_type=code` only; grant `authorization_code`; PKCE `S256` (required); token endpoint auth `client_secret_basic`, `client_secret_post`, or `none` for public clients; scopes `openid`, `email`, `profile`.

## Flow

1. The app redirects the browser to `/authorize?client_id&redirect_uri&scope&state&nonce&code_challenge…`.
2. SoloID validates the request. The client must exist, `redirect_uri` must **exactly** match a registered URI, the scope must include `openid`, and a PKCE challenge must be present. If the client or redirect URI is invalid, SoloID shows an error page and doesn't redirect anywhere. Any other error is sent back to the app's redirect URI.
3. With no valid session cookie, SoloID stores the request in a signed cookie and shows `/login`.
4. On a successful login (see Login), SoloID sets the session cookie, creates the encrypted code, and redirects to `redirect_uri?code&state`.
5. The app POSTs the code to `/token`. SoloID decrypts the code and checks: the expiry, that the client matches, the redirect URI, the PKCE verifier, the client credentials, and that the user and client still exist in the config. It returns an `id_token`, an `access_token`, and `expires_in`.
6. The app may call `/userinfo` with the access token.

## Tokens

- **Signing:** RS256, because OIDC requires it and every client supports it. `kid` is the RFC 7638 JWK thumbprint.
- **ID token:** `iss`, `sub`, `aud`, `exp` (5 min), `iat`, `auth_time`, `nonce`, plus `email`, `email_verified: true`, and `name` when the scope asks for them.
- **The `sub` claim:** HMAC-SHA256 over the normalized email, keyed with a key derived from `secret`, then base64url-encoded. It's stable and opaque, so apps never key on a raw email.
- **Access token:** a signed JWT, 15 min. `/userinfo` verifies it and looks up the user in the current config, so a removed user gets a 401.
- **Session cookie:** `__Host-soloid`, `HttpOnly`, `Secure`, `SameSite=Lax`, HMAC-signed.

## Other security details

- Login error messages, equal timing, and failure limiting are covered in Login.
- Client secrets are verified with Argon2id. Apps call `/token` from their servers rarely, so the cost is fine. Unknown client IDs are verified against a dummy hash too.
- Exact `redirect_uri` matching with no wildcards. `state` and `nonce` are passed through.
- **Security headers**, set by one small middleware on every response:
  - `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'`. The pages have no scripts, so nothing needs a nonce. `form-action` is left out on purpose: Chrome applies it to the redirect after the login POST, which would block the redirect back to the app.
  - `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`.
  - The token and login responses get `Cache-Control: no-store`.
- Logs are JSON lines on stdout. Passwords, codes, tokens, and secrets are never logged. Failed logins are logged with the normalized email and the outcome (`failed`, `rate_limited`) for auditing.

## Code layout

```
src/server.ts           start: load config, build app, listen, SIGHUP handler
src/app.ts              Hono app: routes and middleware (exported for tests)
src/config.ts           Zod schema, load, validate, reload, HKDF key derivation
src/password.ts         Argon2id hash and verify, dummy hash
src/login.ts            attemptLogin(): limiter, equal-timing check, messages
src/oidc.ts             request validation, PKCE, redirect URI matching
src/tokens.ts           ID/access token signing, code encrypt/decrypt, JWKS
src/cookies.ts          signed session and pending-request cookies
src/views/Layout.tsx    HTML shell, links app.css
src/views/Login.tsx     login form with the error alert
src/views/Error.tsx     invalid client or redirect URI page
src/styles.css          Tailwind entry file
src/cli.ts              init, hash, gen-secret, check
Dockerfile              multi-stage: build, prod deps, distroless nonroot
deploy/compose.yaml     the SoloID service only (no proxy)
deploy/config.example.json
README.md               setup, proxy requirements, example Caddy config
```

## Testing

- **Unit tests:**
  - PHC verify: correct password, wrong password, tampered parameters.
  - Config validation errors, including mismatched hash parameters.
  - Code encryption round trip, expiry, and tampering.
  - PKCE.
  - Redirect URI matching: a trailing slash, another port, or another path is rejected.
- **Login tests**, using Hono's `app.request()`:
  - An unknown email and a wrong password produce the same status (401) and a byte-identical body ("Login Failed").
  - The 6th attempt for an email returns 429 "Login Failed (Rate Limited)" after 5 failures, even when the 6th attempt has the correct password.
  - The same lockout happens for an unknown email.
  - A success resets the count.
  - A user who isn't allowed in the app gets "Login Failed" and doesn't increase the count.
  - A POST with a foreign `Origin` is rejected.
- **Timing check:** a script, not a CI test, because timing is too noisy for CI. It measures many logins with an unknown email and with a known email plus a wrong password, and reports the median and p95 for each. The medians should be within noise of each other.
- **End-to-end test:** start the server on a free port with a test config. `openid-client` builds the authorization URL, and the test follows it with plain `fetch` and a cookie jar, posting the login form like a browser would. No browser is needed because the pages have no JavaScript. `openid-client` then redeems the code and verifies the ID token through discovery and JWKS.
- **Compose smoke test (CI):** build the image, run `deploy/compose.yaml` with a test config (issuer `http://localhost:3000`), wait for the healthcheck, and fetch discovery and JWKS on the published port.
- **Manual check:** put SoloID behind the README's Caddy example and sign in to Grafana or oauth2-proxy through it.

## Milestones

1. Scaffold: TypeScript, Hono, `tsup`, Tailwind CLI, Vitest, the `Dockerfile`, and a first `deploy/compose.yaml`.
2. Config schema and validation, and the CLI (`init`, `hash`, `gen-secret`, `check`).
3. Keys, discovery, and JWKS.
4. Login page with failure limiting and equal timing, the session cookie, and `/authorize`.
5. Encrypted codes, `/token`, and `/userinfo`, with the end-to-end test.
6. Logout, security headers, SIGHUP reload, the timing script, the Compose smoke test, image publishing to GHCR, and a README that walks through the Compose setup, the reverse proxy requirements with the example Caddy configuration, and a Grafana example.

## Known limitations

### No refresh tokens in v1

SoloID v1 never issues refresh tokens. If a client asks for the `offline_access` scope, SoloID ignores it, and `/token` responses never contain a `refresh_token`. Discovery doesn't list `refresh_token` in `grant_types_supported`.

The effect depends on the kind of app:

- **Server-side web apps (the target for v1: Grafana, Gitea, Nextcloud, oauth2-proxy):** no noticeable effect. These apps keep their own session after login. When it expires, they redirect to SoloID, which comes straight back without a form while the 12 h SoloID session lasts. Users type their password at most once per `session_ttl` per browser.
- **SPAs that call APIs with the access token:** limited. Every 15 min, when the access token expires, the app must redirect the whole page through SoloID. That's a brief flash, and unsaved state is lost unless the app saves it first. Renewing in a hidden iframe isn't possible: SoloID sends `frame-ancestors 'none'`, and browsers block the third-party session cookie.
- **Native and CLI apps:** poor. Each expiry reopens the system browser sheet (on iOS with the "wants to use id.example.com to sign in" prompt), and background work can't renew tokens at all.

**Possible later addition:** stateless refresh tokens, encrypted like authorization codes, about 30 days long, and checked against the current config on every use. That would make SPAs and native apps work well without adding stored state.
