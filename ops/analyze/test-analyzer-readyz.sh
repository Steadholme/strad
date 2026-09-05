#!/usr/bin/env bash
set -euo pipefail

image=""
while (($# > 0)); do
  case "$1" in
    --image)
      image="${2:-}"
      shift 2
      ;;
    *)
      echo "unknown argument" >&2
      exit 64
      ;;
  esac
done
test -n "$image"
docker image inspect "$image" >/dev/null

container="strad-analyzer-readyz-${RANDOM}-$$"
probe_root="$(mktemp -d /tmp/strad-analyzer-readyz.XXXXXX)"
bridge_token="$(openssl rand -hex 32)"
file_key="$(openssl rand -hex 32)"

cleanup() {
  docker stop --time 1 "$container" >/dev/null 2>&1 || true
  docker rm "$container" >/dev/null 2>&1 || true
  find "$probe_root" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p \
  "$probe_root/workspaces/ghidra-projects" \
  "$probe_root/storage" \
  "$probe_root/state" \
  "$probe_root/cache" \
  "$probe_root/audit/ghidra"
chown -R 1000:1000 "$probe_root"

docker run -d --name "$container" --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 127.0.0.1::18090 \
  -v "$probe_root/workspaces:/data/workspaces" \
  -v "$probe_root/storage:/data/storage" \
  -v "$probe_root/state:/data/state" \
  -v "$probe_root/cache:/data/cache" \
  -v "$probe_root/audit:/data/audit" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700 \
  -e STRAD_BRIDGE_TOKEN="$bridge_token" \
  -e RIKUNE_FILE_SERVER_API_KEY="$file_key" \
  "$image" >/dev/null

port="$(docker port "$container" 18090/tcp | sed 's/.*://')"
response=""
for _ in $(seq 1 240); do
  if [ "$(docker inspect -f '{{.State.Running}}' "$container")" != true ]; then
    break
  fi
  if response="$(curl --silent --show-error --fail --max-time 15 "http://127.0.0.1:${port}/readyz" 2>/dev/null)"; then
    break
  fi
  sleep 1
done

if ! printf '%s' "$response" | jq -e '. == {"status":"ready"}' >/dev/null 2>&1; then
  docker logs --tail 80 "$container" 2>&1 \
    | sed -e "s/${bridge_token}/[REDACTED]/g" -e "s/${file_key}/[REDACTED]/g" >&2 || true
  echo "ASSERT: analyzer service /readyz must pass" >&2
  exit 1
fi

printf '%s\n' 'analyzer service /readyz: pass'
