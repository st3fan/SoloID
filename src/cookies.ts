import { createHmac, timingSafeEqual } from 'node:crypto';
import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import type { Context } from 'hono';
import type { Runtime, User } from './config.js';

export function equal(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function credentialVersion(r: Runtime, user: User) {
  return createHmac('sha256', r.cookieKey).update(user.password_hash).digest('base64url');
}

function cookieName(r: Runtime, kind: string) {
  return `${r.config.issuer.startsWith('https:') ? '__Host-' : ''}soloid-${kind}`;
}

export async function writeCookie(c: Context, r: Runtime, kind: string, payload: JWTPayload, ttl: number) {
  const token = await new SignJWT(payload).setProtectedHeader({ alg: 'HS256', typ: `soloid-${kind}` })
    .setIssuer(r.config.issuer).setAudience(`soloid:${kind}`).setIssuedAt().setExpirationTime(`${ttl}s`).sign(r.cookieKey);
  if (token.length > 3800) throw new Error('Cookie payload too large');
  setCookie(c, cookieName(r, kind), token, {
    path: '/', secure: r.config.issuer.startsWith('https:'), httpOnly: true, sameSite: 'Lax', maxAge: ttl,
  });
}

export async function readCookie(c: Context, r: Runtime, kind: string): Promise<JWTPayload | undefined> {
  const token = getCookie(c, cookieName(r, kind));
  if (!token) return;
  try {
    return (await jwtVerify(token, r.cookieKey, {
      algorithms: ['HS256'], typ: `soloid-${kind}`, issuer: r.config.issuer, audience: `soloid:${kind}`,
      requiredClaims: ['exp', 'iat'],
    })).payload;
  } catch { return; }
}

export function clearCookie(c: Context, r: Runtime, kind: string) {
  deleteCookie(c, cookieName(r, kind), { path: '/', secure: r.config.issuer.startsWith('https:') });
}

export async function session(c: Context, r: Runtime) {
  const value = await readCookie(c, r, 'session');
  const user = value?.sub ? r.users.get(value.sub) : undefined;
  if (!user || value?.cv !== credentialVersion(r, user) || typeof value.auth_time !== 'number') return;
  return { user, authTime: value.auth_time };
}
