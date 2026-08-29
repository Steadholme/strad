#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --estate-root PATH --release-env FILE --secret-env FILE --supply-chain-evidence FILE --supply-chain-signature FILE --supply-chain-public-key FILE --output NEW_PATH [--successor --current-state FILE --predecessor-candidate PATH --predecessor-stage PATH --recovery-completion-root PATH]" >&2
  exit 2
}

estate_root=""
release_env=""
secret_env=""
output=""
supply_chain_evidence=""
supply_chain_signature=""
supply_chain_public_key=""
successor=false
current_state=""
predecessor_candidate=""
predecessor_stage=""
recovery_completion_root=""
while (($#)); do
  case "$1" in
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --release-env) [[ $# -ge 2 ]] || usage; release_env=$2; shift 2 ;;
    --secret-env) [[ $# -ge 2 ]] || usage; secret_env=$2; shift 2 ;;
    --supply-chain-evidence) [[ $# -ge 2 ]] || usage; supply_chain_evidence=$2; shift 2 ;;
    --supply-chain-signature) [[ $# -ge 2 ]] || usage; supply_chain_signature=$2; shift 2 ;;
    --supply-chain-public-key) [[ $# -ge 2 ]] || usage; supply_chain_public_key=$2; shift 2 ;;
    --output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
    --successor) successor=true; shift ;;
    --current-state) [[ $# -ge 2 ]] || usage; current_state=$2; shift 2 ;;
    --predecessor-candidate) [[ $# -ge 2 ]] || usage; predecessor_candidate=$2; shift 2 ;;
    --predecessor-stage) [[ $# -ge 2 ]] || usage; predecessor_stage=$2; shift 2 ;;
    --recovery-completion-root) [[ $# -ge 2 ]] || usage; recovery_completion_root=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$estate_root" && -n "$release_env" && -n "$secret_env" && -n "$output" && -n "$supply_chain_evidence" && -n "$supply_chain_signature" && -n "$supply_chain_public_key" ]] || usage
[[ "$estate_root" = /* && "$release_env" = /* && "$secret_env" = /* && "$output" = /* && "$supply_chain_evidence" = /* && "$supply_chain_signature" = /* && "$supply_chain_public_key" = /* ]] || {
  echo "all paths must be explicit absolute paths" >&2
  exit 2
}
[[ "$estate_root" != "/" && "$output" != "/" && ! -e "$output" && ! -L "$output" ]] || {
  echo "unsafe estate root or output already exists" >&2
  exit 1
}
output_parent=${output%/*}
[[ -n "$output_parent" && -d "$output_parent" && ! -L "$output_parent" ]] || {
  echo "output parent must be an existing directory" >&2
  exit 1
}
[[ "$(realpath -e -- "$output_parent")" == "$output_parent" ]] || {
  echo "output parent must be canonical" >&2
  exit 1
}
read -r output_parent_uid output_parent_mode < <(stat -c '%u %a' -- "$output_parent")
((output_parent_uid == 0 && (8#$output_parent_mode & 0022) == 0)) || {
  echo "output parent must be root-owned and not group/world writable" >&2
  exit 1
}
if [[ "$successor" == true ]]; then
  [[ -n "$current_state" && -n "$predecessor_candidate" && -n "$predecessor_stage" ]] || usage
  for path in "$current_state" "$predecessor_candidate" "$predecessor_stage"; do
    [[ "$path" = /* && "$path" != "/" ]] || usage
  done
  if [[ -n "$recovery_completion_root" ]]; then
    [[ "$recovery_completion_root" = /* && "$recovery_completion_root" != "/" ]] || usage
  fi
elif [[ -n "$current_state" || -n "$predecessor_candidate" || -n "$predecessor_stage" || -n "$recovery_completion_root" ]]; then
  usage
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
successor_policy_schema=0
if [[ "$successor" == true ]]; then
  successor_policy_schema=$(jq -er '.schema_version | select(. == 1 or . == 2 or . == 3)' \
    "$script_dir/successor-policy.json")
  predecessor_validation_args=(
    --policy "$script_dir/successor-policy.json"
    --current-state "$current_state"
    --estate-root "$estate_root"
    --predecessor-candidate "$predecessor_candidate"
    --predecessor-stage "$predecessor_stage"
    --successor-preimages "$script_dir/successor-preimages.sha256"
  )
  if [[ -n "$recovery_completion_root" ]]; then
    predecessor_validation_args+=(--recovery-completion-root "$recovery_completion_root")
  fi
  # This complete validation is deliberately before the first output write.
  python3 "$script_dir/successor_binding.py" "${predecessor_validation_args[@]}"
fi
umask 077
mkdir -m 0700 -- "$output"
python3 -c 'import os,sys; fd=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)' "$output_parent"
mkdir -m 0700 -- "$output/inputs"
if [[ "$successor_policy_schema" == "3" ]]; then
  recovery_completion_snapshot="$output/inputs/recovery-completion"
  mkdir -m 0700 -- "$recovery_completion_snapshot"
  python3 -c 'import os,sys; fd=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)' "$output/inputs"
  python3 - "$script_dir" "$script_dir/successor-policy.json" \
    "$recovery_completion_root" "$recovery_completion_snapshot" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from successor_binding import (  # noqa: E402
    read_recovery_completion_bundle,
    require_same_recovery_completion_snapshot,
    validate_policy,
    write_recovery_completion_bundle,
)

policy = validate_policy(Path(sys.argv[2]))
completion = policy["predecessor"]["completion"]
source = read_recovery_completion_bundle(Path(sys.argv[3]), completion)
write_recovery_completion_bundle(Path(sys.argv[4]), completion, source)
snapshot = read_recovery_completion_bundle(Path(sys.argv[4]), completion)
require_same_recovery_completion_snapshot(source, snapshot)
PY
  recovery_completion_root="$recovery_completion_snapshot"
fi
install -m 0600 -- "$release_env" "$output/inputs/release.env"
install -m 0600 -- "$secret_env" "$output/inputs/secret.env"
install -m 0600 -- "$supply_chain_evidence" "$output/inputs/SUPPLY-CHAIN.json"
install -m 0600 -- "$supply_chain_signature" "$output/inputs/SUPPLY-CHAIN.sig"
install -m 0600 -- "$supply_chain_public_key" "$output/inputs/SUPPLY-CHAIN.pub"
release_env="$output/inputs/release.env"
secret_env="$output/inputs/secret.env"
supply_chain_evidence="$output/inputs/SUPPLY-CHAIN.json"
supply_chain_signature="$output/inputs/SUPPLY-CHAIN.sig"
supply_chain_public_key="$output/inputs/SUPPLY-CHAIN.pub"
supply_args=(
  --release-env "$release_env" \
  --evidence "$supply_chain_evidence" \
  --signature "$supply_chain_signature" \
  --public-key "$supply_chain_public_key" \
  --dockerfile "$script_dir/../../Dockerfile.analyzer" \
  --bridge-lock "$script_dir/../../bridge/package-lock.json"
)
if [[ "$successor" == true ]]; then
  supply_args+=(--successor-policy "$script_dir/successor-policy.json")
fi
python3 "$script_dir/supply_chain_evidence.py" "${supply_args[@]}"
render_args=(
  --estate-root "$estate_root" \
  --stage-root "$output/stage" \
  --release-env "$release_env" \
  --secret-env "$secret_env"
)
if [[ "$successor" == true ]]; then
  render_args+=(
    --successor
    --current-state "$current_state"
    --predecessor-candidate "$predecessor_candidate"
    --predecessor-stage "$predecessor_stage"
  )
  if [[ "$successor_policy_schema" == "3" ]]; then
    render_args+=(--recovery-completion-root "$recovery_completion_root")
  fi
fi
python3 "$script_dir/render.py" "${render_args[@]}"
python3 "$script_dir/validate_release_evidence.py" \
  --evidence "$output/stage/RELEASE-EVIDENCE.json"
mkdir -m 0700 -- "$output/stage/evidence"
install -m 0600 -- "$supply_chain_evidence" "$output/stage/evidence/SUPPLY-CHAIN.json"
install -m 0600 -- "$supply_chain_signature" "$output/stage/evidence/SUPPLY-CHAIN.sig"
install -m 0600 -- "$supply_chain_public_key" "$output/stage/evidence/SUPPLY-CHAIN.pub"
staged_supply_args=(
  --release-env "$release_env" \
  --evidence "$output/stage/evidence/SUPPLY-CHAIN.json" \
  --signature "$output/stage/evidence/SUPPLY-CHAIN.sig" \
  --public-key "$output/stage/evidence/SUPPLY-CHAIN.pub" \
  --dockerfile "$script_dir/../../Dockerfile.analyzer" \
  --bridge-lock "$script_dir/../../bridge/package-lock.json" \
  --release-evidence "$output/stage/RELEASE-EVIDENCE.json"
)
if [[ "$successor" == true ]]; then
  staged_supply_args+=(--successor-policy "$script_dir/successor-policy.json")
fi
python3 "$script_dir/supply_chain_evidence.py" "${staged_supply_args[@]}"
python3 -m unittest discover -s "$script_dir/tests" -p 'test_*.py'

mkdir -m 0700 -- "$output/patches"
while IFS= read -r relative; do
  [[ -n "$relative" ]] || continue
  safe_name=${relative//\//__}
  if [[ "$relative" == "deploy/.env" ]]; then
    python3 "$script_dir/redact_env_diff.py" \
      "$estate_root/$relative" "$output/stage/$relative" "$output/patches/${safe_name}.redacted.json"
    continue
  fi
  old_path="$estate_root/$relative"
  [[ -e "$old_path" || -L "$old_path" ]] || old_path=/dev/null
  set +e
  diff -u --label "a/$relative" --label "b/$relative" \
    "$old_path" "$output/stage/$relative" >"$output/patches/${safe_name}.patch"
  diff_status=$?
  set -e
  [[ $diff_status -eq 0 || $diff_status -eq 1 ]] || {
    echo "diff failed for $relative" >&2
    exit 1
  }
done < <(awk '{print $2}' "$output/stage/TARGETS.sha256")

(
  cd "$output/stage"
  sha256sum --check TARGETS.sha256
)
(
  cd "$output/stage/access-governance"
  cargo fmt --check
  scripts/generate_permission_catalog.sh --check
  python3 scripts/validate_authz_manifests.py
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$output/cargo-target}" cargo test --locked --lib catalog
)
docker compose \
  --env-file "$output/stage/deploy/.env" \
  -f "$output/stage/deploy/docker-compose.yml" \
  config --quiet
bash -n \
  "$script_dir/build-access-candidate.sh" \
  "$script_dir/candidate-source.sh" \
  "$script_dir/common.sh" \
  "$script_dir/dry-run.sh" \
  "$script_dir/apply.sh" \
  "$script_dir/apply-recover.sh" \
  "$script_dir/open-ingress.sh" \
  "$script_dir/public-origin-verify.sh" \
  "$script_dir/verify.sh" \
  "$script_dir/rollback.sh" \
  "$script_dir/runtime-backup.sh" \
  "$script_dir/runtime-restore.sh" \
  "$script_dir/runtime-verify.sh"
python3 -m py_compile \
  "$script_dir/render.py" \
  "$script_dir/render_input_binding.py" \
  "$script_dir/successor_binding.py" \
  "$script_dir/recovery_completion_attestation.py" \
  "$script_dir/redact_env_diff.py" \
  "$script_dir/authority_evidence.py" \
  "$script_dir/edge_evidence.py" \
  "$script_dir/estate_transaction.py" \
  "$script_dir/supply_chain_evidence.py" \
  "$script_dir/validate_release_evidence.py"

targets_digest=$(sha256sum "$output/stage/TARGETS.sha256" | cut -d' ' -f1)
evidence_digest=$(sha256sum "$output/stage/RELEASE-EVIDENCE.json" | cut -d' ' -f1)
release_env_digest=$(sha256sum "$release_env" | cut -d' ' -f1)
{
  if [[ "$successor" == true ]]; then
    printf 'generator=%s\n' "$(tr -d '\n' <"$script_dir/SUCCESSOR_GENERATOR_VERSION")"
    printf 'release_mode=successor\n'
    printf 'predecessor_current_sha256=%s\n' "$(sha256sum "$current_state" | cut -d' ' -f1)"
    printf 'successor_delta_sha256=%s\n' "$(sha256sum "$output/stage/SUCCESSOR-DELTA.sha256" | cut -d' ' -f1)"
    printf 'holdfast_release_tool_revision=%s\n' "$(awk -F= '$1 == "HOLDFAST_RELEASE_TOOL_REVISION" {print $2}' "$release_env")"
    if [[ "$successor_policy_schema" == "3" ]]; then
      printf 'predecessor_completion_kind=%s\n' "$(jq -er '.predecessor_binding.completion.kind' "$output/stage/RELEASE-EVIDENCE.json")"
      printf 'predecessor_completion_attestation_sha256=%s\n' "$(jq -er '.predecessor_binding.completion.attestation_sha256' "$output/stage/RELEASE-EVIDENCE.json")"
      printf 'predecessor_completion_signature_sha256=%s\n' "$(jq -er '.predecessor_binding.completion.signature_sha256' "$output/stage/RELEASE-EVIDENCE.json")"
      printf 'predecessor_completion_public_key_sha256=%s\n' "$(jq -er '.predecessor_binding.completion.public_key_sha256' "$output/stage/RELEASE-EVIDENCE.json")"
    fi
  else
    printf 'generator=%s\n' "$(tr -d '\n' <"$script_dir/GENERATOR_VERSION")"
  fi
  printf 'targets_sha256=%s\n' "$targets_digest"
  printf 'release_evidence_sha256=%s\n' "$evidence_digest"
  printf 'release_env_sha256=%s\n' "$release_env_digest"
  printf 'apply_preimages_sha256=%s\n' "$(sha256sum "$output/stage/APPLY-PREIMAGES.sha256" | cut -d' ' -f1)"
  printf 'apply_absent_sha256=%s\n' "$(sha256sum "$output/stage/APPLY-ABSENT.paths" | cut -d' ' -f1)"
  printf 'render_inputs_sha256=%s\n' "$(sha256sum "$output/stage/RENDER-INPUTS.sha256" | cut -d' ' -f1)"
  printf 'supply_chain_evidence_sha256=%s\n' "$(sha256sum "$output/stage/evidence/SUPPLY-CHAIN.json" | cut -d' ' -f1)"
  printf 'supply_chain_signature_sha256=%s\n' "$(sha256sum "$output/stage/evidence/SUPPLY-CHAIN.sig" | cut -d' ' -f1)"
  printf 'supply_chain_public_key_sha256=%s\n' "$(sha256sum "$output/stage/evidence/SUPPLY-CHAIN.pub" | cut -d' ' -f1)"
  printf 'cargo_gate=passed\n'
  printf 'secrets=redacted\n'
} >"$output/DRY-RUN.receipt"
chmod 0600 "$output/DRY-RUN.receipt"
echo "dry-run complete: $output"
