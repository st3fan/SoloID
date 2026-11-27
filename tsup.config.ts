import { execFileSync } from 'node:child_process';
import { defineConfig } from 'tsup';
import { valid } from 'semver';

// Embed identity in the bundle, not mutable runtime environment variables.
const version = process.env.SOLOID_VERSION ?? '';
let commit = process.env.SOLOID_COMMIT;
if (!commit) {
  try { commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
  catch { commit = 'unknown'; }
}
if (commit !== 'unknown' && !/^[0-9a-f]{40}$/.test(commit)) throw new Error('SOLOID_COMMIT must be a full Git commit SHA');
if (version && (!valid(version.replace(/^v/, '')) || commit === 'unknown')) {
  throw new Error('Release builds require a semantic SOLOID_VERSION and full SOLOID_COMMIT');
}

export default defineConfig({
  define: {
    'process.env.SOLOID_VERSION': JSON.stringify(version),
    'process.env.SOLOID_COMMIT': JSON.stringify(commit),
  },
});
