#!/usr/bin/env bash
set -euo pipefail
umask 077
script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_root/l2_runtime.py" "$@"
