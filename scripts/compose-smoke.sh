#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root. Never replace an operator's existing config.
export SOLOID_COMMIT="${SOLOID_COMMIT:-$(git rev-parse HEAD)}"
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
go run ./scripts/fixture-config > deploy/config/config.json
# Disposable fixture only: the non-root container needs read access.
chmod 644 deploy/config/config.json
docker compose -p soloid-smoke -f deploy/compose.yaml up --build -d --wait --wait-timeout 120
curl -fsS http://localhost:3000/.well-known/openid-configuration | jq -e '.issuer == "http://localhost:3000" and .code_challenge_methods_supported == ["S256"]'
curl -fsS http://localhost:3000/jwks.json | jq -e '(.keys | length) == 1 and .keys[0].kty == "RSA" and .keys[0].d == null'
curl -fsS http://localhost:3000/app.css > /dev/null
page=$(curl -fsS http://localhost:3000/)
[[ "$page" == *"href=\"https://github.com/st3fan/SoloID/commit/$SOLOID_COMMIT\""* ]]
[[ "$page" == *">${SOLOID_COMMIT:0:7}</a>"* ]]
if [[ -n "${SOLOID_VERSION:-}" ]]; then
  [[ "$page" == *"href=\"https://github.com/st3fan/SoloID/releases/tag/$SOLOID_VERSION\""* ]]
else
  [[ "$page" != *'/releases/tag/'* ]]
fi
docker compose -p soloid-smoke -f deploy/compose.yaml exec -T soloid /soloid check --config /config/config.json
echo 'Compose smoke test passed: healthy, discovery, public JWKS, embedded CSS, build identity, CLI'
