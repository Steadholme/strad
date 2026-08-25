#!/usr/bin/env bash

holdfast_die() {
  echo "holdfast: $*" >&2
  exit 1
}

holdfast_require_absolute() {
  local value=$1
  [[ "$value" = /* && "$value" != "/" ]] || holdfast_die "unsafe path: $value"
}

holdfast_acquire_lock() {
  local lock_path=/run/lock/holdfast-rikune.lock
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && -n "${HOLDFAST_LOCK_PATH:-}" ]]; then
    lock_path=$HOLDFAST_LOCK_PATH
  fi
  holdfast_require_absolute "$lock_path"
  mkdir -p -- "$(dirname -- "$lock_path")"
  exec 9>"$lock_path"
  flock -n 9 || holdfast_die "another Holdfast estate mutation is active"
}

holdfast_receipt_value() {
  local receipt=$1
  local key=$2
  awk -F= -v wanted="$key" '
    $1 == wanted { if (seen++) exit 3; print substr($0, length($1) + 2); seen=1 }
    END { if (!seen) exit 4 }
  ' "$receipt"
}

holdfast_sha256() {
  sha256sum "$1" | cut -d' ' -f1
}

holdfast_atomic_receipt() {
  local source=$1
  local target=$2
  local parent temporary
  parent=$(dirname -- "$target")
  mkdir -p -- "$parent"
  chmod 0700 -- "$parent"
  temporary="$parent/.holdfast-receipt-$$-$(basename -- "$target")"
  install -o 0 -g 0 -m 0600 -- "$source" "$temporary"
  mv -fT -- "$temporary" "$target"
}
