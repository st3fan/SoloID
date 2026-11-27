import { spawn, spawnSync, execFileSync, type ChildProcess } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { afterAll, beforeAll, expect, it } from 'vitest';
import * as oidc from 'openid-client';
import { fixture, password, clientSecret } from './helpers.js';
import type { Config } from '../src/config.js';

let server: ChildProcess, directory: string, issuer: string, config: Config, logs = '';
beforeAll(async () => {
  const reservation = createServer().listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = (reservation.address() as { port: number }).port;
  await new Promise<void>(resolve => reservation.close(() => resolve()));
  issuer = `http://localhost:${port}`;
  config = (await fixture()).config; config.issuer = issuer;
  // openid-client derives redirect_uri by stripping the callback's query.
  // Query-preserving redirects are covered by the provider HTTP tests.
  config.clients[0].redirect_uris = ['https://app.example.com/callback'];
  await mkdir('deploy/config', { recursive: true });
  directory = await mkdtemp('deploy/config/integration-');
  await writeFile(`${directory}/config.json`, JSON.stringify(config), { mode: 0o600 });
  server = spawn(process.execPath, ['dist/server.js'], { env: { ...process.env, SOLOID_CONFIG: resolve(directory, 'config.json'), PORT: String(port),
    SOLOID_VERSION: 'v99.0.0', SOLOID_COMMIT: '0'.repeat(40) }, stdio: ['ignore', 'pipe', 'pipe'] });
  server.stdout!.on('data', b => { logs += b.toString(); });
  server.stderr!.on('data', b => { logs += b.toString(); });
  await waitFor(async () => { try { return (await fetch(`${issuer}/healthz`)).ok; } catch { return false; } });
}, 30000);
afterAll(async () => {
  if (server && server.exitCode === null) { server.kill('SIGTERM'); await once(server, 'exit'); }
  if (directory) await rm(directory, { recursive: true, force: true });
});

async function waitFor(check: () => Promise<boolean>) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise(r => setTimeout(r, 50));
  }
  throw new Error('Server did not reach expected state');
}

it('completes discovery → browser login → code exchange → signed ID token → userinfo with openid-client', async () => {
  const client = await oidc.discovery(new URL(issuer), 'web', clientSecret, oidc.ClientSecretBasic(clientSecret), {
    execute: [oidc.allowInsecureRequests, oidc.enableNonRepudiationChecks],
  });
  const verifier = oidc.randomPKCECodeVerifier(), state = oidc.randomState(), nonce = oidc.randomNonce();
  const url = oidc.buildAuthorizationUrl(client, { scope: 'openid email profile', redirect_uri: config.clients[0].redirect_uris[0],
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256', state, nonce });
  const start = await fetch(url, { redirect: 'manual' });
  expect(start.status).toBe(302);
  const cookie = start.headers.getSetCookie().map(c => c.split(';')[0]).join('; ');
  const page = await fetch(`${issuer}/login`, { headers: { cookie } });
  const text = await page.text();
  expect(text).toContain('Welcome back');
  expect(text).not.toContain('<script');
  expect(text).not.toContain('One account. Your apps.');
  expect(text).not.toContain('Your account is managed by your server administrator.');
  const csrf = text.match(/name="csrf" value="([^"]+)"/)![1];
  const login = await fetch(`${issuer}/login`, { method: 'POST', redirect: 'manual', headers: { cookie, origin: issuer },
    body: new URLSearchParams({ csrf, email: 'one@example.com', password }) });
  expect(login.status).toBe(303);
  const callback = new URL(login.headers.get('location')!);
  const tokens = await oidc.authorizationCodeGrant(client, callback, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true });
  expect(tokens.claims()).toMatchObject({ sub: 'user-one', email: 'one@example.com', nonce });
  expect(await oidc.fetchUserInfo(client, tokens.access_token, 'user-one')).toMatchObject({ sub: 'user-one', name: 'One User' });
  expect((await fetch(`${issuer}/app.css`)).headers.get('content-type')).toContain('text/css');
  expect(logs).not.toContain(password);
  expect(logs).not.toContain(tokens.access_token);
});

it('shows linked build identity, not runtime overrides, without the removed slogans', async () => {
  const page = await (await fetch(`${issuer}/`)).text();
  const footer = page.match(/<footer\b[^>]*>([\s\S]*?)<\/footer>/)![1];
  const commit = process.env.SOLOID_COMMIT ?? execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  expect(footer).toContain(`href="https://github.com/st3fan/SoloID/commit/${commit}"`);
  expect(footer).toContain(`>${commit.slice(0, 7)}</a>`);
  if (process.env.SOLOID_VERSION) {
    expect(footer).toContain(`href="https://github.com/st3fan/SoloID/releases/tag/${encodeURIComponent(process.env.SOLOID_VERSION)}"`);
    expect(footer).toContain(`>v${process.env.SOLOID_VERSION.replace(/^v/, '')}</a>`);
  } else {
    expect(footer).not.toContain('/releases/tag/');
  }
  expect(footer).toContain('Powered by SoloID');
  expect(page).not.toContain('YOUR IDENTITY. YOUR SERVER.');
  expect(page).not.toContain('Simple, private sign-in.');
});

it('validates configuration with the CLI and reloads atomically on SIGHUP', async () => {
  const path = resolve(directory, 'config.json');
  expect(execFileSync(process.execPath, ['dist/cli.js', 'check', '--config', path], { encoding: 'utf8' })).toContain('Configuration valid');
  await writeFile(path, '{ broken JSON');
  server.kill('SIGHUP');
  await waitFor(async () => logs.includes('config_reload_failed'));
  expect((await fetch(`${issuer}/.well-known/openid-configuration`)).status).toBe(200);
  // A changed issuer is visible only after the complete replacement validates.
  await writeFile(path, JSON.stringify({ ...config, issuer: 'https://changed.example.com' }));
  server.kill('SIGHUP');
  await waitFor(async () => (await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()).issuer === 'https://changed.example.com');
  expect(logs).toContain('config_reloaded');
});

it('provides CLI initialization, password hashing and client-secret generation', async () => {
  const invoke = (args: string[], input?: string) => execFileSync(process.execPath, ['dist/cli.js', ...args], { encoding: 'utf8', input });
  const initial = JSON.parse(invoke(['init']));
  expect(initial.signing_key.kty).toBe('RSA');
  expect(initial.users[0].id).toBeTruthy();
  const hash = invoke(['hash', '--stdin'], `${password}\n`).trim();
  expect(hash).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=4\$/);
  const secret = JSON.parse(invoke(['gen-secret']));
  expect(secret.client_secret).toHaveLength(43);
  expect(secret.client_secret_hash).toMatch(/^\$argon2id\$/);
});

it('counts password code points while preserving the UTF-8 byte limit', () => {
  const hash = (input: string) => spawnSync(process.execPath, ['dist/cli.js', 'hash', '--stdin'], { encoding: 'utf8', input });
  for (const input of ['😀'.repeat(6), '😀'.repeat(11)]) {
    const result = hash(input);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('at least 12');
    expect(result.stdout).toBe('');
  }
  expect(hash('😀'.repeat(12)).status).toBe(0);
  expect(hash('😀'.repeat(256)).status).toBe(0);
  expect(hash('😀'.repeat(257)).status).toBe(1);
});
