import { SignJWT, createLocalJWKSet, jwtVerify, compactVerify } from 'jose';
import type { Runtime, User } from './config.js';
import type { Code } from './oidc.js';

export function claims(user: User, scope: string) {
  const scopes = scope.split(' ');
  return {
    sub: user.id,
    ...(scopes.includes('email') ? { email: user.email, email_verified: user.email_verified } : {}),
    ...(scopes.includes('profile') && user.name ? { name: user.name } : {}),
  };
}

export async function issueTokens(r: Runtime, code: Code, user: User) {
  const id = new SignJWT({ ...claims(user, code.scope), auth_time: code.auth_time,
    ...(code.nonce !== undefined ? { nonce: code.nonce } : {}) })
    .setProtectedHeader({ alg: 'RS256', kid: r.kid, typ: 'JWT' })
    .setIssuer(r.config.issuer).setAudience(code.client_id).setIssuedAt().setExpirationTime('5m');
  const access = new SignJWT({ scope: code.scope, client_id: code.client_id, cv: code.cv })
    .setProtectedHeader({ alg: 'RS256', kid: r.kid, typ: 'at+jwt' })
    .setIssuer(r.config.issuer).setAudience(`${r.config.issuer}/userinfo`).setSubject(user.id)
    .setIssuedAt().setExpirationTime('15m');
  return { id_token: await id.sign(r.signingKey), access_token: await access.sign(r.signingKey),
    token_type: 'Bearer', expires_in: 900, scope: code.scope };
}

export async function verifyAccess(r: Runtime, token: string) {
  return (await jwtVerify(token, createLocalJWKSet(r.jwks), {
    algorithms: ['RS256'], typ: 'at+jwt', issuer: r.config.issuer,
    audience: `${r.config.issuer}/userinfo`, requiredClaims: ['sub', 'exp', 'iat', 'scope', 'client_id', 'cv'],
  })).payload;
}

// Logout hints may legitimately be expired. Verify signature/type/issuer/audience,
// but do not use the hint to authenticate: logout always requires confirmation.
export async function logoutClient(r: Runtime, token: string): Promise<string | undefined> {
  try {
    const result = await compactVerify(token, createLocalJWKSet(r.jwks), { algorithms: ['RS256'] });
    const p = JSON.parse(new TextDecoder().decode(result.payload));
    if (result.protectedHeader.typ !== 'JWT' || p.iss !== r.config.issuer ||
      typeof p.sub !== 'string' || typeof p.aud !== 'string' || !r.clients.has(p.aud)) return;
    return p.aud;
  } catch { return; }
}
