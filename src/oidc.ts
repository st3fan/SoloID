import { createHash, randomBytes } from 'node:crypto';
import type { Runtime, User } from './config.js';
import { credentialVersion } from './cookies.js';
import { BusyError } from './password.js';

export const randomToken = () => randomBytes(32).toString('base64url');
export const challenge = (verifier: string) => createHash('sha256').update(verifier).digest('base64url');
export type Authorization = {
  client_id: string; redirect_uri: string; scope: string; code_challenge: string;
  state?: string; nonce?: string;
};
export type Code = Authorization & { sub: string; auth_time: number; cv: string; exp: number };

export function uniqueParams(params: URLSearchParams) {
  return [...new Set(params.keys())].every(key => params.getAll(key).length === 1);
}

export function authorization(r: Runtime, p: URLSearchParams): { request?: Authorization; error?: string; redirect?: string } {
  const client = r.clients.get(p.get('client_id') ?? '');
  const redirect = p.get('redirect_uri') ?? '';
  // Never redirect an ambiguous request, even to an apparently registered URI.
  if (!uniqueParams(p) || !client || !client.redirect_uris.includes(redirect)) return { error: 'invalid_request' };
  const fail = (error: string) => ({ error, redirect });
  if (p.get('response_type') !== 'code') return fail('unsupported_response_type');
  if (p.has('request')) return fail('request_not_supported');
  if (p.has('request_uri')) return fail('request_uri_not_supported');
  if (p.has('registration')) return fail('registration_not_supported');
  if (p.has('claims') || p.has('id_token_hint')) return fail('invalid_request');
  if (p.has('response_mode') && p.get('response_mode') !== 'query') return fail('invalid_request');
  const scope = [...new Set((p.get('scope') ?? '').split(' ').filter(Boolean))];
  if (!scope.includes('openid') || scope.some(s => !['openid', 'email', 'profile', 'offline_access'].includes(s))) {
    return fail('invalid_scope');
  }
  if (p.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(p.get('code_challenge') ?? '')) {
    return fail('invalid_request');
  }
  const prompts = (p.get('prompt') ?? '').split(' ').filter(Boolean);
  if (prompts.some(s => !['none', 'login', 'select_account', 'consent'].includes(s)) ||
    (prompts.includes('none') && prompts.length !== 1)) return fail('invalid_request');
  if (prompts.includes('consent')) return fail('consent_required');
  if (p.has('max_age') && !/^(0|[1-9][0-9]{0,8})$/.test(p.get('max_age')!)) return fail('invalid_request');
  if (['state', 'nonce', 'login_hint'].some(key => (p.get(key)?.length ?? 0) > 256)) return fail('invalid_request');
  const request: Authorization = {
    client_id: client.client_id, redirect_uri: redirect,
    scope: scope.filter(s => s !== 'offline_access').join(' '), code_challenge: p.get('code_challenge')!,
  };
  if (p.has('state')) request.state = p.get('state')!;
  if (p.has('nonce')) request.nonce = p.get('nonce')!;
  // Signed pending cookies must fit within browser limits.
  if (JSON.stringify(request).length > 2400) return fail('invalid_request');
  return { request, redirect };
}

export function callback(r: Runtime, redirect: string, params: Record<string, string>, state?: string) {
  const url = new URL(redirect);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  if (state !== undefined) url.searchParams.set('state', state);
  url.searchParams.set('iss', r.config.issuer);
  return url.toString();
}

export class Codes {
  private values = new Map<string, Code>();
  issue(r: Runtime, request: Authorization, user: User, authTime: number) {
    for (const [key, code] of this.values) if (code.exp <= Date.now()) this.values.delete(key);
    if (this.values.size >= 10000) throw new BusyError();
    const code = randomToken();
    this.values.set(challenge(code), { ...request, sub: user.id, auth_time: authTime,
      cv: credentialVersion(r, user), exp: Date.now() + 60000 });
    return code;
  }
  // Taking and deleting are synchronous, before token-signing awaits: one winner.
  take(value: string) {
    const key = challenge(value);
    const code = this.values.get(key);
    this.values.delete(key);
    return code && code.exp > Date.now() ? code : undefined;
  }
  clear() { this.values.clear(); }
}
