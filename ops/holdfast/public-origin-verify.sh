#!/usr/bin/env bash
set -euo pipefail

url=${1:-https://rikune.w33d.xyz/}
[[ "$url" == "https://rikune.w33d.xyz/" ]] || { echo "unexpected public URL" >&2; exit 2; }
probe_dir=$(mktemp -d "${TMPDIR:-/var/tmp}/holdfast-public-probe.XXXXXX")
trap 'rm -rf -- "$probe_dir"' EXIT

for family in 4 6; do
  headers="$probe_dir/headers-$family"
  status=$(curl "-$family" --silent --show-error --max-time 20 --connect-timeout 10 \
    --dump-header "$headers" --output /dev/null --write-out '%{http_code}' "$url")
  [[ "$status" == "200" || "$status" == "302" || "$status" == "401" || "$status" == "403" ]] || {
    echo "public IPv$family probe returned $status" >&2
    exit 1
  }
  if grep -Eiq '^(x-github-request-id|x-proxy-cache|x-served-by):|^via:.*varnish|^server:[[:space:]]*GitHub\.com' "$headers"; then
    echo "public IPv$family probe still resolves to GitHub Pages/Fastly" >&2
    exit 1
  fi
  cache_control=$(awk 'BEGIN{IGNORECASE=1} /^cache-control:/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print}' "$headers" | tail -n 1)
  [[ "${cache_control// /}" == "private,no-store" ]] || {
    echo "public IPv$family workbench response is not private,no-store" >&2
    exit 1
  }
done
echo "public IPv4/IPv6 origin is no longer GitHub Pages and is private,no-store"
