#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root. Never replace an operator's existing config.
if [[ -e deploy/config/config.json ]]; then
  echo 'Refusing to replace deploy/config/config.json' >&2
  exit 1
fi
mkdir -p deploy/config
cleanup() {
  docker compose -p soloid-smoke -f deploy/compose.yaml logs --no-color || true
  docker compose -p soloid-smoke -f deploy/compose.yaml down || true
  rm -f deploy/config/config.json
}
trap cleanup EXIT
npx tsx scripts/fixture-config.ts > deploy/config/config.json
# Disposable fixture only: the non-root container needs read access.
chmod 644 deploy/config/config.json
docker compose -p soloid-smoke -f deploy/compose.yaml up --build -d --wait --wait-timeout 120
node --input-type=module <<'JS'
import assert from 'node:assert/strict';
const discovery = await (await fetch('http://localhost:3000/.well-known/openid-configuration')).json();
assert.equal(discovery.issuer, 'http://localhost:3000');
assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']);
const jwks = await (await fetch(discovery.jwks_uri)).json();
assert.equal(jwks.keys.length, 1);
assert.equal(jwks.keys[0].kty, 'RSA');
assert.equal(jwks.keys[0].d, undefined);
assert.equal((await fetch('http://localhost:3000/app.css')).status, 200);
console.log('Compose smoke test passed: healthy, discovery, public JWKS, CSS');
JS
docker compose -p soloid-smoke -f deploy/compose.yaml exec -T soloid /nodejs/bin/node dist/cli.js check --config /config/config.json
