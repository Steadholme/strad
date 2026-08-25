#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --estate-root PATH --release-env FILE --release-evidence FILE" >&2
  exit 2
}

estate_root=""
release_env=""
release_evidence=""
while (($#)); do
  case "$1" in
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --release-env) [[ $# -ge 2 ]] || usage; release_env=$2; shift 2 ;;
    --release-evidence) [[ $# -ge 2 ]] || usage; release_evidence=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$estate_root" && -n "$release_env" && -n "$release_evidence" ]] || usage
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$script_dir/common.sh"
holdfast_require_absolute "$estate_root"
holdfast_require_absolute "$release_env"
holdfast_require_absolute "$release_evidence"

docker_bin=docker
if [[ -n "${HOLDFAST_DOCKER_BIN:-}" ]]; then
  [[ "${HOLDFAST_TEST_MODE:-0}" == "1" ]] || holdfast_die "Docker command override is test-only"
  docker_bin=$HOLDFAST_DOCKER_BIN
fi
compose=("$docker_bin" compose --env-file "$estate_root/deploy/.env" -f "$estate_root/deploy/docker-compose.yml")

release_value() {
  local key=$1
  awk -F= -v wanted="$key" '
    $1 == wanted { if (seen++) exit 3; print substr($0, length($1) + 2); seen=1 }
    END { if (!seen) exit 4 }
  ' "$release_env"
}

[[ "$(holdfast_sha256 "$release_env")" == "$(jq -er '.release_env_sha256' "$release_evidence")" ]] || \
  holdfast_die "runtime release env differs from RELEASE-EVIDENCE"

services=(access-governance rikune-analyzer strad verdict newapi sluice sluice-internal)
for service in "${services[@]}"; do
  container_id=$("${compose[@]}" ps -q "$service")
  [[ -n "$container_id" ]] || holdfast_die "runtime container is absent: $service"
  [[ "$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")" == "running" ]] || \
    holdfast_die "runtime container is not running: $service"
done

while IFS=' ' read -r service release_key; do
  container_id=$("${compose[@]}" ps -q "$service")
  expected=$(release_value "$release_key")
  configured=$("$docker_bin" inspect -f '{{.Config.Image}}' "$container_id")
  image_id=$("$docker_bin" inspect -f '{{.Image}}' "$container_id")
  [[ "$configured" == "$expected" ]] || holdfast_die "runtime image reference differs: $service"
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || holdfast_die "runtime image ID is not immutable: $service"
done <<'EOF'
access-governance ACCESS_GOVERNANCE_IMAGE
rikune-analyzer STRAD_ANALYZER_IMAGE
strad STRAD_IMAGE
verdict VERDICT_IMAGE
newapi NEWAPI_IMAGE
sluice SLUICE_IMAGE
sluice-internal SLUICE_IMAGE
EOF

"${compose[@]}" exec -T access-governance access-governance healthcheck
"${compose[@]}" exec -T verdict verdict healthcheck
"${compose[@]}" exec -T newapi wget -q -O /dev/null http://127.0.0.1:9080/readyz
"${compose[@]}" exec -T sluice /usr/local/bin/sluice -healthcheck
"${compose[@]}" exec -T sluice-internal /usr/local/bin/sluice -healthcheck
"${compose[@]}" exec -T rikune-analyzer /usr/local/bin/node /opt/strad-bridge/dist/src/healthcheck.js
"${compose[@]}" exec -T strad /app/strad readycheck

runtime_contract=$("${compose[@]}" exec -T strad /app/strad runtime-contract)
expected_model=$(release_value STRAD_NEWAPI_MODEL)
jq -e --arg model "$expected_model" '
  type == "object"
  and keys == ["newapi_context_tokens", "newapi_model"]
  and .newapi_context_tokens >= 32768
  and .newapi_model == $model
' <<<"$runtime_contract" >/dev/null || holdfast_die "actual Strad/NewAPI model contract differs"

echo "runtime images, readiness, and model alias are exact"
