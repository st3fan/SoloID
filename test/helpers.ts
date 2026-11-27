import { randomBytes } from 'node:crypto';
import { exportJWK, generateKeyPair } from 'jose';
import { hashPassword } from '../src/password.js';
import { prepareConfig } from '../src/config.js';
import { createApp } from '../src/app.js';
import { challenge } from '../src/oidc.js';

export const password = 'correct horse battery staple';
export const clientSecret = 'test client secret +:/?!';
export const verifier = 'a'.repeat(43);
export async function fixture() {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  return prepareConfig({
    issuer: 'http://localhost:3000', secret: randomBytes(32).toString('base64url'),
    signing_key: await exportJWK(privateKey),
    users: [{ id: 'user-one', email: 'one@example.com', name: 'One User', password_hash: await hashPassword(password) },
      { id: 'user-two', email: 'two@example.com', name: 'Two User', password_hash: await hashPassword('another strong password') }],
    clients: [
      { client_id: 'web', name: 'Demo app', client_secret_hash: await hashPassword(clientSecret),
        redirect_uris: ['https://app.example.com/callback?existing=1'], post_logout_redirect_uris: ['https://app.example.com/signed-out'] },
      { client_id: 'public', public: true, redirect_uris: ['https://spa.example.com/callback'] },
      { client_id: 'restricted', public: true, redirect_uris: ['https://restricted.example.com/callback'], allowed_users: ['user-two'] },
    ],
  });
}

export function authParams(client = 'web', extra: Record<string, string> = {}) {
  return new URLSearchParams({ client_id: client, response_type: 'code', scope: 'openid email profile',
    redirect_uri: client === 'web' ? 'https://app.example.com/callback?existing=1' : `https://${client === 'public' ? 'spa' : client}.example.com/callback`,
    code_challenge: challenge(verifier), code_challenge_method: 'S256', state: 'state-value', nonce: 'nonce-value', ...extra });
}

export class Browser {
  cookies = new Map<string, string>();
  csrf = '';
  constructor(readonly app: ReturnType<typeof createApp>['app'], readonly issuer = 'http://localhost:3000') {}
  async request(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers);
    headers.set('cookie', [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '));
    const res = await this.app.request(new URL(path, this.issuer), { ...init, headers });
    for (const item of res.headers.getSetCookie()) {
      const part = item.split(';')[0], i = part.indexOf('=');
      if (item.includes('Max-Age=0')) this.cookies.delete(part.slice(0, i));
      else this.cookies.set(part.slice(0, i), part.slice(i + 1));
    }
    return res;
  }
  async start(params = authParams()) {
    const res = await this.request(`/authorize?${params}`);
    if (res.headers.get('location') !== '/login') return res;
    const page = await this.request('/login');
    this.csrf = (await page.text()).match(/name="csrf" value="([^"]+)"/)![1];
    return res;
  }
  login(email = 'one@example.com', pass = password, headers: Record<string, string> = {}) {
    return this.request('/login', { method: 'POST', headers: { origin: this.issuer, ...headers },
      body: new URLSearchParams({ email, password: pass, csrf: this.csrf }) });
  }
}

export async function obtainCode(browser: Browser, client = 'web', extra: Record<string, string> = {}) {
  await browser.start(authParams(client, { prompt: 'login', ...extra }));
  const response = await browser.login();
  if (response.status !== 303) throw new Error(`Login failed: ${response.status} ${await response.text()}`);
  return new URL(response.headers.get('location')!).searchParams.get('code')!;
}

export function tokenRequest(code: string, client = 'web', extra: Record<string, string> = {}): RequestInit {
  return { method: 'POST', body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: client,
    ...(client === 'web' ? { client_secret: clientSecret } : {}), redirect_uri: authParams(client).get('redirect_uri')!,
    code_verifier: verifier, ...extra }) };
}
