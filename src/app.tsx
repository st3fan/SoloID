import { Hono, type Context } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { cors } from 'hono/cors';
import { readFile } from 'node:fs/promises';
import { allowed, type Runtime } from './config.js';
import { LoginLimiter } from './login.js';
import { BusyError, verifyPassword } from './password.js';
import { clearCookie, credentialVersion, equal, readCookie, session, writeCookie } from './cookies.js';
import { authorization, callback, challenge, Codes, randomToken, uniqueParams, type Authorization } from './oidc.js';
import { claims, issueTokens, logoutClient, verifyAccess } from './tokens.js';
import { LoginPage, LogoutPage, MessagePage } from './views.js';

type Env = { Variables: { runtime: Runtime } };
const html = (view: unknown) => `<!DOCTYPE html>${view}`;
const failure = (c: Context, message = 'Return to your app and start signing in again.', status: 400 | 403 | 503 = 400) =>
  c.html(html(<MessagePage title="Unable to continue" message={message} />), status);

async function form(c: Context) {
  if (c.req.header('content-type')?.split(';')[0].trim() !== 'application/x-www-form-urlencoded') return;
  const p = new URLSearchParams(await c.req.text());
  return uniqueParams(p) ? p : undefined;
}

export function createApp(initial: Runtime, log: (event: Record<string, unknown>) => void = event => console.log(JSON.stringify(event))) {
  let runtime = initial;
  const codes = new Codes();
  const limiter = new LoginLimiter();
  const app = new Hono<Env>();
  let stylesheet: string | undefined;

  app.use('*', async (c, next) => {
    c.set('runtime', runtime);
    c.header('Cache-Control', 'no-store');
    c.header('Pragma', 'no-cache');
    // no-referrer also suppresses Origin on browser form POSTs, breaking CSRF checks.
    c.header('Referrer-Policy', 'same-origin');
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('X-Frame-Options', 'DENY');
    c.header('Content-Security-Policy', "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'");
    if (c.req.url.length > 8192) return failure(c);
    await next();
  });
  app.use('*', bodyLimit({ maxSize: 16384, onError: c => c.json({ error: 'invalid_request' }, 413) }));
  for (const path of ['/token', '/userinfo', '/jwks.json', '/.well-known/openid-configuration']) {
    app.use(path, cors({
      origin: (origin, c) => {
        const r = c.get('runtime') as Runtime;
        return r.config.clients.some(client => client.redirect_uris.some(uri => new URL(uri).origin === origin)) ? origin : undefined;
      }, allowMethods: ['GET', 'POST', 'OPTIONS'], allowHeaders: ['Authorization', 'Content-Type'],
    }));
  }
  app.onError((error, c) => {
    log({ event: 'request_error', kind: error instanceof BusyError ? 'busy' : 'internal' });
    if (error instanceof BusyError) { c.header('Retry-After', '5'); return c.json({ error: 'temporarily_unavailable' }, 503); }
    return c.json({ error: 'server_error' }, 500);
  });
  app.notFound(c => c.html(html(<MessagePage title="Page not found" message="Open your app to start signing in." />), 404));
  app.get('/', c => c.html(html(<MessagePage title="Your identity. Your server." message="SoloID connects you to your apps. Open an app to sign in, or visit /logout to end your SoloID session." />)));
  app.get('/healthz', c => c.json({ status: 'ok' }));
  app.get('/app.css', async c => {
    stylesheet ??= await readFile(new URL('../dist/app.css', import.meta.url), 'utf8');
    return c.text(stylesheet, 200, { 'Content-Type': 'text/css; charset=utf-8' });
  });
  app.get('/.well-known/openid-configuration', c => {
    const issuer = c.get('runtime').config.issuer;
    return c.json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`, jwks_uri: `${issuer}/jwks.json`, end_session_endpoint: `${issuer}/logout`,
      response_types_supported: ['code'], response_modes_supported: ['query'], grant_types_supported: ['authorization_code'],
      subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'email', 'profile'], code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email', 'email_verified', 'name'],
      claims_parameter_supported: false, request_parameter_supported: false, request_uri_parameter_supported: false,
      authorization_response_iss_parameter_supported: true,
    });
  });
  app.get('/jwks.json', c => c.json(c.get('runtime').jwks));

  app.get('/authorize', async c => {
    const r = c.get('runtime'), params = new URL(c.req.url).searchParams;
    const { request, error, redirect } = authorization(r, params);
    if (!request) return redirect
      ? c.redirect(callback(r, redirect, { error: error! }, params.get('state') ?? undefined)) : failure(c);
    const client = r.clients.get(request.client_id)!;
    const current = await session(c, r);
    const prompt = (params.get('prompt') ?? '').split(' ');
    const maxAge = params.has('max_age') ? Number(params.get('max_age')) : Infinity;
    const force = prompt.includes('login') || prompt.includes('select_account') || maxAge === 0;
    if (current && !force && Date.now() / 1000 - current.authTime <= maxAge) {
      if (!allowed(client, current.user)) return c.redirect(callback(r, redirect!, { error: 'access_denied' }, request.state));
      const code = codes.issue(r, request, current.user, current.authTime);
      return c.redirect(callback(r, request.redirect_uri, { code }, request.state));
    }
    if (prompt.includes('none')) return c.redirect(callback(r, request.redirect_uri, { error: 'login_required' }, request.state));
    await writeCookie(c, r, 'pending', { request, csrf: randomToken() }, 600);
    return c.redirect('/login');
  });

  async function pending(c: Context, r: Runtime) {
    const data = await readCookie(c, r, 'pending');
    if (!data || typeof data.csrf !== 'string' || !data.request) return;
    const request = data.request as Authorization;
    const client = r.clients.get(request.client_id);
    if (!client || !client.redirect_uris.includes(request.redirect_uri)) return;
    return { request, client, csrf: data.csrf };
  }
  app.get('/login', async c => {
    const p = await pending(c, c.get('runtime'));
    if (!p) return failure(c);
    return c.html(html(<LoginPage app={p.client.name ?? p.client.client_id} csrf={p.csrf} />));
  });
  app.post('/login', async c => {
    const r = c.get('runtime');
    const p = await pending(c, r);
    const body = await form(c);
    if (c.req.header('origin') !== r.config.issuer || !p || !body || !equal(body.get('csrf') ?? '', p.csrf)) return failure(c, undefined, 403);
    const email = body.get('email') ?? '', password = body.get('password') ?? '';
    if (email.length > 254 || Buffer.byteLength(password) > 1024) {
      return c.html(html(<LoginPage app={p.client.name ?? p.client.client_id} csrf={p.csrf} error="Login Failed" />), 401);
    }
    const result = await limiter.attempt(r, p.client.client_id, email, password);
    // Do not complete a login checked against configuration replaced during Argon2.
    if (runtime !== r) throw new BusyError();
    log({ event: 'login', email: email.trim().toLowerCase(), outcome: result.outcome });
    if (result.outcome !== 'success') {
      const limited = result.outcome === 'rate_limited';
      if (limited) c.header('Retry-After', String(result.retryAfter));
      return c.html(html(<LoginPage app={p.client.name ?? p.client.client_id} csrf={p.csrf} email={email}
        error={limited ? 'Login Failed (Rate Limited)' : 'Login Failed'} />), limited ? 429 : 401);
    }
    const authTime = Math.floor(Date.now() / 1000);
    const code = codes.issue(r, p.request, result.user, authTime);
    await writeCookie(c, r, 'session', { sub: result.user.id, auth_time: authTime, cv: credentialVersion(r, result.user) }, r.sessionSeconds);
    clearCookie(c, r, 'pending');
    return c.redirect(callback(r, p.request.redirect_uri, { code }, p.request.state), 303);
  });

  app.post('/token', async c => {
    const r = c.get('runtime'), body = await form(c);
    if (!body) return c.json({ error: 'invalid_request' }, 400);
    if (body.get('grant_type') !== 'authorization_code') return c.json({ error: 'unsupported_grant_type' }, 400);
    let clientID = body.get('client_id') ?? '', secret = body.get('client_secret') ?? '';
    const auth = c.req.header('authorization');
    if (auth) {
      if (body.has('client_secret') || !/^Basic [A-Za-z0-9+/]+=*$/i.test(auth)) return c.json({ error: 'invalid_request' }, 400);
      try {
        const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8');
        const colon = decoded.indexOf(':');
        if (colon < 0) throw new Error();
        const decode = (s: string) => decodeURIComponent(s.replace(/\+/g, ' '));
        const id = decode(decoded.slice(0, colon));
        if (body.has('client_id') && clientID !== id) return c.json({ error: 'invalid_request' }, 400);
        clientID = id; secret = decode(decoded.slice(colon + 1));
      } catch { return c.json({ error: 'invalid_request' }, 400); }
    }
    const client = r.clients.get(clientID);
    let authenticated = false;
    if (client?.public) authenticated = !auth && !body.has('client_secret');
    else if (Buffer.byteLength(secret) <= 1024) {
      const correct = await verifyPassword(client?.client_secret_hash ?? r.dummyHash, secret);
      authenticated = !!client && correct;
    }
    if (!authenticated) {
      if (auth) c.header('WWW-Authenticate', 'Basic realm="SoloID"');
      return c.json({ error: 'invalid_client' }, auth ? 401 : 400);
    }
    if (runtime !== r) throw new BusyError();
    const code = codes.take(body.get('code') ?? '');
    const user = code ? r.users.get(code.sub) : undefined;
    const verifier = body.get('code_verifier') ?? '';
    if (!code || !user || code.client_id !== client!.client_id || code.redirect_uri !== body.get('redirect_uri') ||
      !client!.redirect_uris.includes(code.redirect_uri) || !allowed(client!, user) || code.cv !== credentialVersion(r, user) ||
      !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || !equal(code.code_challenge, challenge(verifier))) {
      return c.json({ error: 'invalid_grant' }, 400);
    }
    const tokens = await issueTokens(r, code, user);
    // Signing yields twice; a reload can invalidate credentials during either await.
    if (runtime !== r) throw new BusyError();
    return c.json(tokens);
  });

  app.on(['GET', 'POST'], '/userinfo', async c => {
    const r = c.get('runtime');
    let token = c.req.header('authorization')?.match(/^Bearer ([A-Za-z0-9._~-]+)$/i)?.[1];
    if (c.req.method === 'POST') {
      const body = await form(c);
      if (body?.has('access_token')) {
        if (c.req.header('authorization')) return c.json({ error: 'invalid_request' }, 400);
        token = body.get('access_token')!;
      }
    }
    try {
      if (!token || token.length > 8192) throw new Error();
      const p = await verifyAccess(r, token);
      const user = r.users.get(p.sub!), client = r.clients.get(String(p.client_id));
      if (!user || !client || !allowed(client, user) || p.cv !== credentialVersion(r, user) || typeof p.scope !== 'string') throw new Error();
      return c.json(claims(user, p.scope));
    } catch {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      return c.json({ error: 'invalid_token' }, 401);
    }
  });

  app.get('/logout', async c => {
    const r = c.get('runtime'), p = new URL(c.req.url).searchParams;
    if (!uniqueParams(p) || (p.get('state')?.length ?? 0) > 256) return failure(c);
    let clientID = p.get('client_id') ?? undefined;
    if (p.has('id_token_hint')) {
      const hinted = await logoutClient(r, p.get('id_token_hint')!);
      if (!hinted || (clientID && clientID !== hinted)) return failure(c);
      clientID = hinted;
    }
    const redirect = p.get('post_logout_redirect_uri');
    if (redirect && (!clientID || !r.clients.get(clientID)?.post_logout_redirect_uris.includes(redirect))) return failure(c);
    const csrf = randomToken();
    await writeCookie(c, r, 'logout', { csrf, clientID, redirect, state: p.get('state') }, 600);
    return c.html(html(<LogoutPage csrf={csrf} />));
  });
  app.post('/logout', async c => {
    const r = c.get('runtime'), p = await readCookie(c, r, 'logout'), body = await form(c);
    if (c.req.header('origin') !== r.config.issuer || !p || typeof p.csrf !== 'string' || !body || !equal(p.csrf, body.get('csrf') ?? '')) return failure(c, undefined, 403);
    if (typeof p.redirect === 'string' && !r.clients.get(String(p.clientID))?.post_logout_redirect_uris.includes(p.redirect)) return failure(c);
    for (const kind of ['session', 'pending', 'logout']) clearCookie(c, r, kind);
    if (typeof p.redirect === 'string') {
      const url = new URL(p.redirect);
      if (typeof p.state === 'string') url.searchParams.set('state', p.state);
      return c.redirect(url.toString(), 303);
    }
    return c.html(html(<MessagePage title="You're signed out" message="You can close this window. Open an app when you're ready to sign in again." />));
  });
  return { app, reload(next: Runtime) { runtime = next; codes.clear(); } };
}
