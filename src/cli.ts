import { randomBytes, randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';
import { emitKeypressEvents } from 'node:readline';
import { exportJWK, generateKeyPair } from 'jose';
import { ZodError } from 'zod';
import { loadConfig } from './config.js';
import { hashPassword } from './password.js';

async function promptPassword(label: string): Promise<string> {
  if (!process.stdin.isTTY) throw new Error('Use an interactive terminal or hash --stdin');
  process.stderr.write(label);
  emitKeypressEvents(process.stdin);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let value = '';
    const finish = (error?: Error) => {
      process.stdin.off('keypress', onKey);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stderr.write('\n');
      error ? reject(error) : resolve(value);
    };
    const onKey = (text: string | undefined, key: { name?: string; ctrl?: boolean }) => {
      if (key.ctrl && key.name === 'c') return finish(new Error('Cancelled'));
      if (key.name === 'return' || key.name === 'enter') return finish();
      if (key.name === 'backspace') value = [...value].slice(0, -1).join('');
      else if (text && !key.ctrl && !text.includes('\x1b')) value += text;
      if (Buffer.byteLength(value) > 1024) finish(new Error('Password must be at most 1024 bytes'));
    };
    process.stdin.on('keypress', onKey);
  });
}

async function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    config: { type: 'string' }, stdin: { type: 'boolean' }, help: { type: 'boolean' },
  } });
  const command = positionals[0];
  if (values.help || !command) {
    console.log('SoloID\n\n  init                  Print a fresh config skeleton\n  hash [--stdin]        Hash a password (otherwise prompts without echo)\n  gen-secret            Print a client secret and its hash\n  check --config PATH   Validate configuration');
    return;
  }
  if (positionals.length !== 1) throw new Error('Do not pass passwords as command arguments');
  if (command === 'init') {
    const { privateKey } = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
    console.log(JSON.stringify({ issuer: 'https://id.example.com', secret: randomBytes(32).toString('base64url'),
      signing_key: await exportJWK(privateKey), previous_public_keys: [], session_ttl: '12h',
      users: [{ id: randomUUID(), email: 'you@example.com', name: 'Your name', email_verified: false,
        password_hash: 'REPLACE_WITH_OUTPUT_OF_HASH' }],
      clients: [{ client_id: 'grafana', name: 'Grafana', client_secret_hash: 'REPLACE_WITH_HASH_FROM_GEN_SECRET',
        redirect_uris: ['https://grafana.example.com/login/generic_oauth'], post_logout_redirect_uris: [] }],
    }, null, 2));
  } else if (command === 'hash') {
    let password: string;
    if (values.stdin) {
      let input = '';
      for await (const chunk of process.stdin) {
        input += chunk.toString();
        if (Buffer.byteLength(input) > 1026) throw new Error('Password too long');
      }
      password = input.replace(/\r?\n$/, '');
    } else {
      password = await promptPassword('Password: ');
      if (password !== await promptPassword('Confirm password: ')) throw new Error('Passwords do not match');
    }
    if ([...password].length < 12 || Buffer.byteLength(password) > 1024) throw new Error('Use at least 12 Unicode code points and at most 1024 bytes');
    console.log(await hashPassword(password));
  } else if (command === 'gen-secret') {
    const secret = randomBytes(32).toString('base64url');
    console.log(JSON.stringify({ client_secret: secret, client_secret_hash: await hashPassword(secret) }, null, 2));
  } else if (command === 'check') {
    const path = values.config ?? process.env.SOLOID_CONFIG;
    if (!path) throw new Error('Pass --config PATH or set SOLOID_CONFIG');
    try { await loadConfig(path); }
    catch (error) {
      if (error instanceof ZodError) {
        throw new Error(error.issues.map(issue => `${issue.path.join('.')}: ${issue.message}`).join('\n'));
      }
      throw new Error('Cannot load configuration: check JSON syntax, permissions, unique IDs/emails, allowed_users, TTL, and RSA keys');
    }
    console.log('Configuration valid');
  } else throw new Error('Unknown command; run with --help');
}
main().catch(error => { console.error(error instanceof Error ? error.message : 'Command failed'); process.exitCode = 1; });
