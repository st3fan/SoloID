import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { createApp } from '../src/app.js';
import { prepareConfig, type Runtime } from '../src/config.js';
import { hashPassword } from '../src/password.js';
import { authParams, Browser, clientSecret, fixture, obtainCode, password, tokenRequest, verifier } from './helpers.js';

let runtime: Runtime;
beforeAll(async () => { runtime = await fixture(); }, 30000);
afterEach(() => vi.useRealTimers());

describe('OIDC provider HTTP contract', () => {
  let provider: ReturnType<typeof createApp>, browser: Browser;
  beforeEach(() => { provider = createApp(runtime, () => {}); browser = new Browser(provider.app); });

  it('publishes only public signing keys and the supported flows', async () => {
    const discovery = await (await browser.request('/.well-known/openid-configuration')).json();
    expect(discovery.grant_types_supported).toEqual(['authorization_code']);
    expect(discovery.code_challenge_methods_supported).toEqual(['S256']);
    expect(discovery.issuer).toBe(runtime.config.issuer);
    const keys = await (await browser.request('/jwks.json')).json();
    expect(keys.keys[0]).toMatchObject({ kty: 'RSA', kid: runtime.kid, alg: 'RS256' });
    expect(keys.keys[0]).not.toHaveProperty('d');
  });

  it('signs and verifies ID/access tokens, preserves nonce/state/query, and scopes claims', async () => {
    await browser.start();
    const signedIn = await browser.login();
    const callback = new URL(signedIn.headers.get('location')!);
    expect(callback.searchParams.get('state')).toBe('state-value');
    expect(callback.searchParams.get('existing')).toBe('1');
    expect(callback.searchParams.get('iss')).toBe(runtime.config.issuer);
    const res = await browser.request('/token', tokenRequest(callback.searchParams.get('code')!));
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const tokens = await res.json();
    expect(tokens).not.toHaveProperty('refresh_token');
    const { payload } = await jwtVerify(tokens.id_token, createLocalJWKSet(runtime.jwks), {
      issuer: runtime.config.issuer, audience: 'web', algorithms: ['RS256'],
    });
    expect(payload).toMatchObject({ sub: 'user-one', nonce: 'nonce-value', email: 'one@example.com', email_verified: false, name: 'One User' });
    expect(payload.exp! - payload.iat!).toBe(300);
    const info = await browser.request('/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } });
    expect(await info.json()).toEqual({ sub: 'user-one', email: 'one@example.com', email_verified: false, name: 'One User' });
    expect((await browser.request('/userinfo', { headers: { authorization: `Bearer ${tokens.id_token}` } })).status).toBe(401);
    const code = await obtainCode(browser, 'public', { scope: 'openid offline_access' });
    const minimal = await (await browser.request('/token', tokenRequest(code, 'public'))).json();
    expect(minimal.scope).toBe('openid');
    expect(await (await browser.request('/userinfo', { method: 'POST', body: new URLSearchParams({ access_token: minimal.access_token }) })).json())
      .toEqual({ sub: 'user-one' });
  });

  it.each(['client_secret_basic', 'client_secret_post'])('authenticates confidential clients with %s', async method => {
    const code = await obtainCode(browser);
    const request = tokenRequest(code);
    if (method === 'client_secret_basic') {
      (request.body as URLSearchParams).delete('client_secret');
      request.headers = { authorization: `Basic ${Buffer.from(`web:${encodeURIComponent(clientSecret)}`).toString('base64')}` };
    }
    expect((await browser.request('/token', request)).status).toBe(200);
  });

  it('rejects missing/wrong client secrets without consuming a code', async () => {
    const code = await obtainCode(browser);
    expect((await browser.request('/token', tokenRequest(code, 'web', { client_secret: 'wrong' }))).status).toBe(400);
    expect((await browser.request('/token', tokenRequest(code))).status).toBe(200);
  });

  it.each([
    { code_verifier: 'z'.repeat(43) }, { code_verifier: '' }, { redirect_uri: 'https://app.example.com/callback?existing=2' },
  ] as Record<string, string>[])('rejects a code exchange with altered bindings %j', async changes => {
    const code = await obtainCode(browser, 'public');
    const res = await browser.request('/token', tokenRequest(code, 'public', changes));
    expect(await res.json()).toEqual({ error: 'invalid_grant' });
  });

  it('rejects code substitution between clients and concurrent replay', async () => {
    const stolen = await obtainCode(browser);
    expect(await (await browser.request('/token', tokenRequest(stolen, 'public'))).json()).toEqual({ error: 'invalid_grant' });
    const code = await obtainCode(browser, 'public');
    const responses = await Promise.all([browser.request('/token', tokenRequest(code, 'public')), browser.request('/token', tokenRequest(code, 'public'))]);
    expect(responses.map(r => r.status).sort()).toEqual([200, 400]);
  });

  it('does not return tokens if configuration reloads during signing', async () => {
    const code = await obtainCode(browser, 'public');
    const replacement = await fixture();
    const sign = crypto.subtle.sign.bind(crypto.subtle);
    // Force the reload at the asynchronous crypto boundary, using real signatures.
    const signing = vi.spyOn(crypto.subtle, 'sign').mockImplementationOnce(async (...args) => {
      const signature = await sign(...args);
      provider.reload(replacement);
      return signature;
    });
    try {
      const response = await browser.request('/token', tokenRequest(code, 'public'));
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error: 'temporarily_unavailable' });
    } finally { signing.mockRestore(); }
    // Restarting authorization works against the replacement runtime.
    const freshCode = await obtainCode(browser, 'public');
    expect((await browser.request('/token', tokenRequest(freshCode, 'public'))).status).toBe(200);
  });

  it('expires codes after 60 seconds and access tokens after 15 minutes', async () => {
    const now = Date.now();
    const code = await obtainCode(browser, 'public');
    const valid = await obtainCode(browser, 'public');
    const tokens = await (await browser.request('/token', tokenRequest(valid, 'public'))).json();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now + 61000);
    expect((await browser.request('/token', tokenRequest(code, 'public'))).status).toBe(400);
    vi.setSystemTime(now + 901000);
    expect((await browser.request('/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } })).status).toBe(401);
  });

  it('does not redirect untrusted or ambiguous authorization requests', async () => {
    for (const extra of [{ redirect_uri: 'https://evil.example/cb' }, { client_id: 'missing' },
      { redirect_uri: 'https://app.example.com/callback/?existing=1' }] as Record<string, string>[]) {
      const res = await browser.request(`/authorize?${authParams('web', extra)}`);
      expect(res.status).toBe(400); expect(res.headers.has('location')).toBe(false);
    }
    expect((await browser.request(`/authorize?${authParams()}&client_id=web`)).status).toBe(400);
  });

  it.each([
    [{ code_challenge_method: 'plain' }, 'invalid_request'], [{ code_challenge: '' }, 'invalid_request'],
    [{ response_type: 'token' }, 'unsupported_response_type'], [{ scope: 'email' }, 'invalid_scope'],
    [{ max_age: '-1' }, 'invalid_request'], [{ prompt: 'none login' }, 'invalid_request'],
    [{ request_uri: 'https://evil.example' }, 'request_uri_not_supported'],
  ] as const)('rejects unsupported authorization parameters %j', async (extra, error) => {
    const res = await browser.request(`/authorize?${authParams('web', extra)}`);
    expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe(error);
  });

  it('supports SSO, prompt=none, forced login, max_age, and session expiry', async () => {
    const silent = () => browser.request(`/authorize?${authParams('public', { prompt: 'none' })}`);
    expect(new URL((await silent()).headers.get('location')!).searchParams.get('error')).toBe('login_required');
    await obtainCode(browser);
    expect(new URL((await silent()).headers.get('location')!).searchParams.has('code')).toBe(true);
    expect((await browser.request(`/authorize?${authParams('web', { max_age: '0' })}`)).headers.get('location')).toBe('/login');
    expect((await browser.request(`/authorize?${authParams('web', { prompt: 'login' })}`)).headers.get('location')).toBe('/login');
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(Date.now() + 13 * 3600000);
    expect(new URL((await silent()).headers.get('location')!).searchParams.get('error')).toBe('login_required');
  });

  it('checks app restrictions at login, SSO, and userinfo after reload', async () => {
    await browser.start(authParams('restricted'));
    expect((await browser.login()).status).toBe(401);
    const code = await obtainCode(browser);
    const tokens = await (await browser.request('/token', tokenRequest(code))).json();
    const blocked = await browser.request(`/authorize?${authParams('restricted')}`);
    expect(new URL(blocked.headers.get('location')!).searchParams.get('error')).toBe('access_denied');
    const config = structuredClone(runtime.config); config.clients[0].allowed_users = ['user-two'];
    provider.reload(await prepareConfig(config));
    expect((await browser.request('/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } })).status).toBe(401);
  });

  it('rejects CSRF, forged cookies, duplicate fields, and oversized requests', async () => {
    await browser.start();
    // Browser form POSTs need Origin; no-referrer turns it into null in Chromium.
    expect((await browser.request('/login')).headers.get('referrer-policy')).toBe('same-origin');
    expect((await browser.login('one@example.com', password, { origin: 'https://evil.example' })).status).toBe(403);
    const original = browser.csrf; browser.csrf = 'wrong';
    expect((await browser.login()).status).toBe(403); browser.csrf = original;
    expect((await browser.request('/login', { method: 'POST', headers: { origin: runtime.config.issuer },
      body: new URLSearchParams([['csrf', original], ['email', 'one@example.com'], ['email', 'two@example.com']]) })).status).toBe(403);
    browser.cookies.set('soloid-pending', 'tampered');
    expect((await browser.login()).status).toBe(403);
    expect((await browser.request('/token', { method: 'POST', body: 'x'.repeat(17000) })).status).toBe(413);
  });

  it('uses identical failure rendering for unknown accounts without reflecting passwords or HTML', async () => {
    await browser.start();
    const bad = await browser.login('one@example.com', '<script>secret</script>');
    const missing = await browser.login('absent@example.com', '<script>secret</script>');
    expect(bad.status).toBe(401); expect(missing.status).toBe(401);
    const a = await bad.text(), b = await missing.text();
    expect(a.replaceAll('one@example.com', 'EMAIL')).toBe(b.replaceAll('absent@example.com', 'EMAIL'));
    expect(a).not.toContain('secret'); expect(a).not.toContain('<script>');
  });

  it.each(['one@example.com', 'absent@example.com'])('locks %s after five failures for exactly fifteen minutes, not by IP', async email => {
    await browser.start();
    for (let i = 0; i < 5; i++) {
      expect((await browser.login(email, 'wrong', { 'x-forwarded-for': `192.0.2.${i}` })).status).toBe(401);
    }
    const blocked = await browser.login(email, password);
    expect(blocked.status).toBe(429); expect(await blocked.text()).toContain('Login Failed (Rate Limited)');
    expect(Number(blocked.headers.get('retry-after'))).toBeGreaterThan(890);
    expect((await browser.login('two@example.com', 'wrong')).status).toBe(401);
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(Date.now() + 901000);
    // Start a fresh transaction because the 10-minute form has expired too.
    await browser.start();
    expect((await browser.login(email, 'wrong')).status).toBe(401);
  });

  it('serializes simultaneous failures and resets counters on success', async () => {
    await browser.start();
    const results = await Promise.all(Array.from({ length: 6 }, () => browser.login('one@example.com', 'wrong')));
    expect(results.map(r => r.status).sort()).toEqual([401, 401, 401, 401, 401, 429]);
    // A different email remains independent, and a valid login clears its prior failures.
    for (let i = 0; i < 4; i++) expect((await browser.login('two@example.com', 'wrong')).status).toBe(401);
    expect((await browser.login('two@example.com', 'another strong password')).status).toBe(303);
    await browser.start(authParams('web', { prompt: 'login' }));
    for (let i = 0; i < 5; i++) expect((await browser.login('two@example.com', 'wrong')).status).toBe(401);
  });

  it('preserves stable subjects, revokes password-changed sessions, and drops codes on restart', async () => {
    const code = await obtainCode(browser, 'public');
    const fresh = createApp(runtime, () => {});
    expect((await fresh.app.request('/token', tokenRequest(code, 'public'))).status).toBe(400);
    const config = structuredClone(runtime.config);
    config.users[0].email = 'renamed@example.com';
    const renamed = await prepareConfig(config); provider.reload(renamed);
    const sso = await browser.request(`/authorize?${authParams('public')}`);
    const renamedCode = new URL(sso.headers.get('location')!).searchParams.get('code')!;
    const tokens = await (await browser.request('/token', tokenRequest(renamedCode, 'public'))).json();
    expect((await jwtVerify(tokens.id_token, createLocalJWKSet(runtime.jwks))).payload.sub).toBe('user-one');
    config.users[0].password_hash = await hashPassword('a new and different password');
    provider.reload(await prepareConfig(config));
    expect((await browser.request(`/authorize?${authParams()}`)).headers.get('location')).toBe('/login');
    expect((await browser.request('/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } })).status).toBe(401);
  });

  it('keeps old tokens and expired logout hints valid while their signing key is retained', async () => {
    const code = await obtainCode(browser);
    const tokens = await (await browser.request('/token', tokenRequest(code))).json();
    const config = structuredClone(runtime.config);
    config.signing_key = (await fixture()).config.signing_key;
    config.previous_public_keys = runtime.jwks.keys;
    provider.reload(await prepareConfig(config));
    const info = () => browser.request('/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } });
    expect((await info()).status).toBe(200);
    expect((await (await browser.request('/jwks.json')).json()).keys).toHaveLength(2);
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(Date.now() + 6 * 60000);
    const logout = new URLSearchParams({ client_id: 'web', post_logout_redirect_uri: 'https://app.example.com/signed-out', id_token_hint: tokens.id_token });
    expect((await browser.request(`/logout?${logout}`)).status).toBe(200);
    config.previous_public_keys = [];
    provider.reload(await prepareConfig(config));
    expect((await info()).status).toBe(401);
    expect((await browser.request(`/logout?${logout}`)).status).toBe(400);
    logout.delete('id_token_hint');
    expect((await browser.request(`/logout?${logout}`)).status).toBe(200);
  });

  it('sets host-only Secure cookies behind HTTPS and preserves sessions across a restart', async () => {
    const secure = await prepareConfig({ ...runtime.config, issuer: 'https://id.example.com' });
    const first = createApp(secure, () => {});
    const b = new Browser(first.app, secure.config.issuer);
    const start = await b.start();
    expect(start.headers.get('set-cookie')).toMatch(/^__Host-soloid-pending=/);
    for (const flag of ['HttpOnly', 'Secure', 'SameSite=Lax', 'Path=/']) {
      expect(start.headers.get('set-cookie')).toContain(flag);
    }
    expect(start.headers.get('set-cookie')).not.toContain('Domain=');
    expect((await b.login()).status).toBe(303);
    const restarted = new Browser(createApp(secure, () => {}).app, secure.config.issuer);
    restarted.cookies = new Map(b.cookies);
    const sso = await restarted.request(`/authorize?${authParams('public', { prompt: 'none' })}`);
    expect(new URL(sso.headers.get('location')!).searchParams.has('code')).toBe(true);
  });

  it('limits CORS to registered origins', async () => {
    const good = await browser.request('/token', { method: 'OPTIONS', headers: { origin: 'https://spa.example.com', 'access-control-request-method': 'POST' } });
    expect(good.headers.get('access-control-allow-origin')).toBe('https://spa.example.com');
    const bad = await browser.request('/token', { method: 'OPTIONS', headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' } });
    expect(bad.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('requires logout confirmation, prevents open redirects, and clears the session', async () => {
    await obtainCode(browser);
    expect((await browser.request('/logout?client_id=web&post_logout_redirect_uri=https://evil.example')).status).toBe(400);
    const page = await browser.request('/logout?client_id=web&post_logout_redirect_uri=https://app.example.com/signed-out&state=bye');
    const csrf = (await page.text()).match(/name="csrf" value="([^"]+)"/)![1];
    expect(browser.cookies.has('soloid-session')).toBe(true);
    const send = (origin: string) => browser.request('/logout', { method: 'POST', headers: { origin }, body: new URLSearchParams({ csrf }) });
    expect((await send('https://evil.example')).status).toBe(403);
    expect((await send(runtime.config.issuer)).headers.get('location')).toBe('https://app.example.com/signed-out?state=bye');
    expect(browser.cookies.has('soloid-session')).toBe(false);
    const result = await browser.request(`/authorize?${authParams('public', { prompt: 'none' })}`);
    expect(new URL(result.headers.get('location')!).searchParams.get('error')).toBe('login_required');
  });
});

describe('configuration validation', () => {
  it.each([
    (c: any) => { c.users.push({ ...c.users[0], id: 'duplicate', email: ' ONE@EXAMPLE.COM ' }); },
    (c: any) => { c.users[0].password_hash = c.users[0].password_hash.replace('t=3', 't=1'); },
    (c: any) => { c.users[0].password_hash = c.users[0].password_hash.slice(0, -1) + 'B'; },
    (c: any) => { c.clients[0].redirect_uris = ['https://app.example.com/*']; },
    (c: any) => { c.clients[0].redirect_uris = ['https://app.example.com/callback#fragment']; },
    (c: any) => { c.clients[0].redirect_uris = ['https://app.example.com/callback#']; },
    (c: any) => { c.clients[0].post_logout_redirect_uris = ['https://app.example.com/signed-out#']; },
    (c: any) => { c.clients[0].client_secret_hash = undefined; },
    (c: any) => { c.clients[1].client_secret_hash = c.clients[0].client_secret_hash; },
    (c: any) => { c.clients[0].allowed_users = ['missing']; },
    (c: any) => { c.issuer = 'http://unsafe.example'; },
    (c: any) => { c.issuer = 'not a URL'; },
    (c: any) => { c.secret = 'short'; },
    (c: any) => { c.previous_public_keys = [c.signing_key]; },
    (c: any) => { c.session_ttl = '999999999999999999d'; },
  ])('rejects unsafe or inconsistent config %#', async change => {
    const input = structuredClone(runtime.config); change(input);
    await expect(prepareConfig(input)).rejects.toThrow();
  });
});
