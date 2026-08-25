#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --estate-root PATH --output NEW_PATH" >&2
  exit 2
}

estate_root=""
output=""
while (($#)); do
  case "$1" in
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$estate_root" && -n "$output" ]] || usage
[[ "$estate_root" = /* && "$output" = /* && "$estate_root" != "/" && "$output" != "/" ]] || {
  echo "estate and output paths must be explicit absolute non-root paths" >&2
  exit 2
}
[[ ! -e "$output" && ! -L "$output" ]] || {
  echo "output already exists: $output" >&2
  exit 1
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/render.py" \
  --estate-root "$estate_root" \
  --stage-root "$output" \
  --catalog-only
