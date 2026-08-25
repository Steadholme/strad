#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --mode closed|open [--url https://analyze.w33d.xyz/]" >&2
  exit 2
}

mode=""
url="https://analyze.w33d.xyz/"
while (($#)); do
  case "$1" in
    --mode) [[ $# -ge 2 ]] || usage; mode=$2; shift 2 ;;
    --url) [[ $# -ge 2 ]] || usage; url=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$mode" == "closed" || "$mode" == "open" ]] || usage
[[ "$url" == "https://analyze.w33d.xyz/" ]] || { echo "unexpected public URL" >&2; exit 2; }
probe_dir=$(mktemp -d "${TMPDIR:-/var/tmp}/holdfast-public-probe.XXXXXX")
trap 'rm -rf -- "$probe_dir"' EXIT

max_attempts=15
retry_seconds=5
if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" ]]; then
  max_attempts=1
  retry_seconds=0
fi
hsts_pattern='^max-age=([3-9][0-9]{7,}|[1-9][0-9]{8,});[[:space:]]*includeSubDomains$'
sso_location_pattern='^https://sso\.w33d\.xyz/authorize(\?.*)?$'
for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  round_ok="true"
  round_errors=""
  for family in 4 6; do
    headers="$probe_dir/headers-$attempt-$family"
    if ! status=$(curl --disable "-$family" --silent --show-error --max-time 5 --connect-timeout 3 \
      --header 'Cookie:' --header 'Authorization:' \
      --dump-header "$headers" --output /dev/null --write-out '%{http_code}' "$url"); then
      round_ok="false"
      round_errors+=" IPv$family transport-error;"
      continue
    fi
    if grep -Eiq '^(x-github-request-id|x-proxy-cache|x-served-by):|^via:.*varnish|^server:[[:space:]]*GitHub\.com' "$headers"; then
      round_ok="false"
      round_errors+=" IPv$family pages-or-fastly-marker;"
      continue
    fi
    mapfile -t cache_controls < <(
      awk 'BEGIN{IGNORECASE=1} /^cache-control:/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print}' "$headers"
    )
    if [[ "$mode" == "closed" ]]; then
      if [[ "$status" != "404" ]]; then
        round_ok="false"
        round_errors+=" IPv$family status=$status expected=404;"
      fi
      mapfile -t hsts_values < <(
        awk 'BEGIN{IGNORECASE=1} /^strict-transport-security:/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print}' "$headers"
      )
      mapfile -t content_type_values < <(
        awk 'BEGIN{IGNORECASE=1} /^x-content-type-options:/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print tolower($0)}' "$headers"
      )
      mapfile -t frame_values < <(
        awk 'BEGIN{IGNORECASE=1} /^x-frame-options:/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print toupper($0)}' "$headers"
      )
      mapfile -t referrer_values < <(
        awk 'BEGIN{IGNORECASE=1} /^referrer-policy:/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print tolower($0)}' "$headers"
      )
      if [[ ${#hsts_values[@]} -ne 1 || ! "${hsts_values[0]:-}" =~ $hsts_pattern ]]; then
        round_ok="false"
        round_errors+=" IPv$family unsafe-or-duplicate-hsts;"
      fi
      if [[ ${#content_type_values[@]} -ne 1 || "${content_type_values[0]:-}" != "nosniff" ]]; then
        round_ok="false"
        round_errors+=" IPv$family unsafe-or-duplicate-content-type-options;"
      fi
      if [[ ${#frame_values[@]} -ne 1 || "${frame_values[0]:-}" != "SAMEORIGIN" ]]; then
        round_ok="false"
        round_errors+=" IPv$family unsafe-or-duplicate-frame-options;"
      fi
      if [[ ${#referrer_values[@]} -ne 1 || "${referrer_values[0]:-}" != "strict-origin-when-cross-origin" ]]; then
        round_ok="false"
        round_errors+=" IPv$family unsafe-or-duplicate-referrer-policy;"
      fi
      for cache_control in "${cache_controls[@]}"; do
        normalized_cache=${cache_control,,}
        normalized_cache=${normalized_cache//[[:space:]]/}
        if [[ "$normalized_cache" != "private,no-store" && "$normalized_cache" != "no-store,private" ]]; then
          round_ok="false"
          round_errors+=" IPv$family unsafe-cache-control=$cache_control;"
        fi
      done
      continue
    fi

    if [[ "$status" != "302" ]]; then
      round_ok="false"
      round_errors+=" IPv$family status=$status expected=302;"
      continue
    fi
    mapfile -t locations < <(
      awk 'BEGIN{IGNORECASE=1} /^location:/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print}' "$headers"
    )
    if [[ ${#locations[@]} -ne 1 || ! "${locations[0]:-}" =~ $sso_location_pattern ]]; then
      round_ok="false"
      round_errors+=" IPv$family untrusted-or-duplicate-location;"
    fi
    if [[ ${#cache_controls[@]} -eq 0 ]]; then
      round_ok="false"
      round_errors+=" IPv$family cache-control=absent;"
    fi
    for cache_control in "${cache_controls[@]}"; do
      normalized_cache=${cache_control,,}
      normalized_cache=${normalized_cache//[[:space:]]/}
      if [[ "$normalized_cache" != "private,no-store" && "$normalized_cache" != "no-store,private" ]]; then
        round_ok="false"
        round_errors+=" IPv$family unsafe-cache-control=$cache_control;"
      fi
    done
  done

  # A result is accepted only when IPv4 and IPv6 satisfy the requested mode in this same round.
  if [[ "$round_ok" == "true" ]]; then
    if [[ "$mode" == "closed" ]]; then
      echo "public IPv4/IPv6 route is absent with exact 404 responses on the existing W33D Sluice edge"
    else
      echo "public IPv4/IPv6 route is open with trusted SSO 302 and private,no-store responses"
    fi
    exit 0
  fi
  echo "public origin $mode verification round $attempt/$max_attempts failed:$round_errors" >&2
  if ((attempt < max_attempts)); then
    sleep "$retry_seconds"
  fi
done
echo "public origin $mode verification did not converge in $max_attempts dual-stack rounds" >&2
exit 1
