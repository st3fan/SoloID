import { randomBytes } from 'node:crypto';
import { Algorithm, hash, verify } from '@node-rs/argon2';

export const passwordOptions = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
  outputLen: 32,
};

// Fix cost and lengths so unknown accounts take the same password-check path.
export const hashPattern = /^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{21}[AQgw]\$[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$/;
export const hashPassword = (password: string) => hash(password, { ...passwordOptions, salt: randomBytes(16) });

export class BusyError extends Error {}
let active = 0;

export async function verifyPassword(encoded: string, password: string): Promise<boolean> {
  // Bound native memory use, including requests to /token. No IP-based limiting.
  if (active >= 2) throw new BusyError('Password verifier busy');
  active++;
  try {
    return await verify(encoded, password);
  } finally {
    active--;
  }
}
