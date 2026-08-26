#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --execute --estate-root PATH --dry-run-dir PATH --release-env FILE --backup-root PATH [--state-dir PATH] [--activate-services] [--successor]" >&2
  exit 2
}

execute="false"
activate="false"
successor="false"
estate_root=""
dry_run_dir=""
release_env=""
backup_root=""
state_dir="/var/lib/holdfast-rikune"
while (($#)); do
  case "$1" in
    --execute) execute="true"; shift ;;
    --activate-services) activate="true"; shift ;;
    --successor) successor="true"; shift ;;
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --dry-run-dir) [[ $# -ge 2 ]] || usage; dry_run_dir=$2; shift 2 ;;
    --release-env) [[ $# -ge 2 ]] || usage; release_env=$2; shift 2 ;;
    --backup-root) [[ $# -ge 2 ]] || usage; backup_root=$2; shift 2 ;;
    --state-dir) [[ $# -ge 2 ]] || usage; state_dir=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$execute" == "true" && -n "$estate_root" && -n "$dry_run_dir" && -n "$release_env" && -n "$backup_root" ]] || usage
if [[ "$successor" == "true" && "$activate" != "true" ]]; then
  echo "successor apply requires --activate-services" >&2
  exit 2
fi
[[ $EUID -eq 0 ]] || { echo "apply requires root" >&2; exit 1; }
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
# shellcheck disable=SC1091
source "$script_dir/common.sh"
for path in "$estate_root" "$dry_run_dir" "$release_env" "$backup_root" "$state_dir"; do
  holdfast_require_absolute "$path"
done

# Acquire before receipt, preimage, or expected-absent validation.
holdfast_acquire_lock
stage="$dry_run_dir/stage"
receipt="$dry_run_dir/DRY-RUN.receipt"
targets="$stage/TARGETS.sha256"
apply_preimages="$stage/APPLY-PREIMAGES.sha256"
apply_absent="$stage/APPLY-ABSENT.paths"
render_inputs="$stage/RENDER-INPUTS.sha256"
successor_delta="$stage/SUCCESSOR-DELTA.sha256"
supply_evidence="$stage/evidence/SUPPLY-CHAIN.json"
supply_signature="$stage/evidence/SUPPLY-CHAIN.sig"
supply_public_key="$stage/evidence/SUPPLY-CHAIN.pub"
routes_database_url=${ROUTES_DATABASE_URL:-}
render_expected_mode="base"
supply_chain_policy_args=()
release_validator_policy_args=()
if [[ "$successor" == "true" ]]; then
  render_expected_mode="successor"
  supply_chain_policy_args=(--successor-policy "$script_dir/successor-policy.json")
  release_validator_policy_args=(--successor-policy "$script_dir/successor-policy.json")
fi
require_root_control_file() {
  local file=$1
  [[ -f "$file" && ! -L "$file" && "$(stat -c '%u:%h' -- "$file")" == "0:1" ]] || \
    holdfast_die "release control file must be regular, single-link, and root-owned: $file"
}

require_canonical_root_directory() {
  local directory=$1
  [[ -d "$directory" && ! -L "$directory" && "$(readlink -f -- "$directory")" == "$directory" ]] || \
    holdfast_die "control directory must be canonical and non-symlink: $directory"
  [[ "$(stat -c '%u' -- "$directory")" == "0" ]] || \
    holdfast_die "control directory must be root-owned: $directory"
}

ensure_private_control_directory() {
  local directory=$1 parent
  if [[ -e "$directory" || -L "$directory" ]]; then
    require_canonical_root_directory "$directory"
  else
    parent=$(dirname -- "$directory")
    require_canonical_root_directory "$parent"
    [[ "$(readlink -m -- "$directory")" == "$directory" ]] || \
      holdfast_die "new control directory has a non-canonical path: $directory"
    mkdir -m 0700 -- "$directory"
    sync -f "$parent"
  fi
  chmod 0700 -- "$directory"
  require_canonical_root_directory "$directory"
}

release_control_files=(
  "$receipt"
  "$targets"
  "$stage/RELEASE-EVIDENCE.json"
  "$release_env"
  "$supply_evidence"
  "$supply_signature"
  "$supply_public_key"
  "$apply_preimages"
  "$apply_absent"
  "$render_inputs"
)
if [[ "$successor" == "true" ]]; then
  release_control_files+=("$successor_delta")
fi

verify_render_bindings() {
  [[ "$(holdfast_receipt_value "$receipt" apply_preimages_sha256)" == "$(holdfast_sha256 "$apply_preimages")" ]] || \
    holdfast_die "apply preimage manifest differs from the dry-run receipt"
  [[ "$(holdfast_receipt_value "$receipt" apply_absent_sha256)" == "$(holdfast_sha256 "$apply_absent")" ]] || \
    holdfast_die "apply absent manifest differs from the dry-run receipt"
  [[ "$(holdfast_receipt_value "$receipt" render_inputs_sha256)" == "$(holdfast_sha256 "$render_inputs")" ]] || \
    holdfast_die "render-input manifest differs from the dry-run receipt"
  python3 "$script_dir/render_input_binding.py" verify \
    --ops-root "$script_dir" --manifest "$render_inputs" \
    --stage-root "$stage" --release-evidence "$stage/RELEASE-EVIDENCE.json" \
    --expected-mode "$render_expected_mode" \
    --require-root-owner
}

bound_dry_receipt_sha=""
release_env_sha=""
verify_release_bindings() {
  local current_receipt_sha key receipt_key file successor_delta_sha tool_revision
  for file in "${release_control_files[@]}"; do
    require_root_control_file "$file"
  done
  current_receipt_sha=$(holdfast_sha256 "$receipt")
  if [[ -n "$bound_dry_receipt_sha" && "$current_receipt_sha" != "$bound_dry_receipt_sha" ]]; then
    holdfast_die "dry-run receipt changed during the apply ceremony"
  fi
  [[ "$(holdfast_receipt_value "$receipt" cargo_gate)" == "passed" ]] || \
    holdfast_die "production apply refuses a dry-run without the Rust gate"
  verify_render_bindings
  python3 "$script_dir/validate_release_evidence.py" \
    --evidence "$stage/RELEASE-EVIDENCE.json" \
    "${release_validator_policy_args[@]}"
  [[ "$(holdfast_receipt_value "$receipt" targets_sha256)" == "$(holdfast_sha256 "$targets")" ]] || \
    holdfast_die "dry-run target manifest changed"
  [[ "$(holdfast_receipt_value "$receipt" release_evidence_sha256)" == "$(holdfast_sha256 "$stage/RELEASE-EVIDENCE.json")" ]] || \
    holdfast_die "dry-run release evidence changed"
  release_env_sha=$(holdfast_sha256 "$release_env")
  [[ "$(holdfast_receipt_value "$receipt" release_env_sha256)" == "$release_env_sha" ]] || \
    holdfast_die "release env differs from the dry-run identity"
  [[ "$(jq -er '.release_env_sha256' "$stage/RELEASE-EVIDENCE.json")" == "$release_env_sha" ]] || \
    holdfast_die "release env differs from RELEASE-EVIDENCE"
  if [[ "$successor" == "true" ]]; then
    successor_delta_sha=$(holdfast_sha256 "$successor_delta")
    tool_revision=$(awk -F= '$1 == "HOLDFAST_RELEASE_TOOL_REVISION" {print $2}' "$release_env")
    [[ "$tool_revision" =~ ^[0-9a-f]{40}$ ]] || \
      holdfast_die "successor release env tool revision is invalid"
    [[ "$(holdfast_receipt_value "$receipt" release_mode)" == "successor" && \
      "$(jq -er '.release_mode' "$stage/RELEASE-EVIDENCE.json")" == "successor" ]] || \
      holdfast_die "successor dry-run release mode differs"
    [[ "$(holdfast_receipt_value "$receipt" predecessor_current_sha256)" == \
      "$predecessor_current_sha" && \
      "$(jq -er '.predecessor_binding.current_state_sha256' \
        "$stage/RELEASE-EVIDENCE.json")" == "$predecessor_current_sha" ]] || \
      holdfast_die "successor dry-run predecessor CURRENT differs"
    [[ "$(holdfast_receipt_value "$receipt" successor_delta_sha256)" == \
      "$successor_delta_sha" && \
      "$(jq -er '.successor_delta_sha256' "$stage/RELEASE-EVIDENCE.json")" == \
      "$successor_delta_sha" ]] || \
      holdfast_die "successor dry-run delta differs"
    [[ "$(holdfast_receipt_value "$receipt" holdfast_release_tool_revision)" == \
      "$tool_revision" && \
      "$(jq -er '.holdfast_release_tool_revision' "$stage/RELEASE-EVIDENCE.json")" == \
      "$tool_revision" ]] || \
      holdfast_die "successor dry-run release tool revision differs"
  fi
  python3 "$script_dir/supply_chain_evidence.py" \
    --release-env "$release_env" \
    --evidence "$supply_evidence" \
    --signature "$supply_signature" \
    --public-key "$supply_public_key" \
    --dockerfile "$script_dir/../../Dockerfile.analyzer" \
    --bridge-lock "$script_dir/../../bridge/package-lock.json" \
    --release-evidence "$stage/RELEASE-EVIDENCE.json" \
    "${supply_chain_policy_args[@]}"
  for key in evidence signature public_key; do
    receipt_key="supply_chain_${key}_sha256"
    case "$key" in
      evidence) file="$supply_evidence" ;;
      signature) file="$supply_signature" ;;
      public_key) file="$supply_public_key" ;;
    esac
    [[ "$(holdfast_receipt_value "$receipt" "$receipt_key")" == "$(holdfast_sha256 "$file")" ]] || \
      holdfast_die "supply-chain artifact differs from dry-run receipt: $key"
  done
  grep -q '"catalog_only": false' "$stage/RELEASE-EVIDENCE.json" || \
    holdfast_die "candidate-only rendering cannot be applied"
  if grep -q 'registry.invalid/' "$stage/RELEASE-EVIDENCE.json"; then
    holdfast_die "test-only image digests cannot be applied"
  fi
  (cd "$stage" && sha256sum --check TARGETS.sha256)
  docker compose --env-file "$stage/deploy/.env" -f "$stage/deploy/docker-compose.yml" config --quiet
  if [[ -z "$bound_dry_receipt_sha" ]]; then
    bound_dry_receipt_sha=$current_receipt_sha
  fi
}

commit_atomic_file() {
  local temporary=$1 target=$2 parent
  parent=$(dirname -- "$target")
  [[ -f "$temporary" && ! -L "$temporary" ]] || holdfast_die "atomic source is unsafe: $temporary"
  chmod 0600 -- "$temporary"
  sync -f "$temporary"
  mv -fT -- "$temporary" "$target"
  sync -f "$target"
  sync -f "$parent"
}

atomic_copy_authority() {
  local source=$1 target=$2 temporary
  [[ ! -e "$target" && ! -L "$target" ]] || holdfast_die "authority target already exists: $target"
  temporary="$(dirname -- "$target")/.authority-$(basename -- "$target").$$"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] || holdfast_die "authority temporary path already exists"
  install -o 0 -g 0 -m 0600 -- "$source" "$temporary"
  commit_atomic_file "$temporary" "$target"
  [[ "$(holdfast_sha256 "$source")" == "$(holdfast_sha256 "$target")" ]] || \
    holdfast_die "atomically persisted authority differs from source: $target"
}

archive_and_restore_predecessor_current() {
  local archive=$1 temporary
  require_root_control_file "$state_file"
  if [[ -e "$archive" || -L "$archive" ]]; then
    require_root_control_file "$archive"
    [[ "$(holdfast_sha256 "$archive")" == "$(holdfast_sha256 "$state_file")" ]] || \
      holdfast_die "successor CURRENT archive differs from the active pointer"
  else
    atomic_copy_authority "$state_file" "$archive"
  fi
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    "${HOLDFAST_TEST_SIGKILL_AFTER_SUCCESSOR_CURRENT_ARCHIVE:-0}" == "1" ]]; then
    kill -KILL "$$"
  fi
  temporary="$state_dir/.PREDECESSOR-CURRENT.$$"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] || \
    holdfast_die "predecessor CURRENT replacement temporary exists"
  install -o 0 -g 0 -m 0600 -- "$predecessor_current_file" "$temporary"
  commit_atomic_file "$temporary" "$state_file"
  [[ "$(holdfast_sha256 "$state_file")" == "$predecessor_current_sha" ]] || \
    holdfast_die "successor recovery did not atomically restore predecessor CURRENT"
}

successor_generation_authorities=()
persist_successor_generation_authority() {
  local authority_dir line digest relative source
  local -A seen=()
  [[ "$successor" == "true" ]] || return 0
  authority_dir="$backup/successor-authority"
  [[ ! -e "$authority_dir" && ! -L "$authority_dir" ]] || \
    holdfast_die "successor generation authority directory already exists"
  mkdir -m 0700 -- "$authority_dir"
  successor_generation_authorities=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]] || \
      holdfast_die "successor render-input authority contains an invalid line"
    digest=${BASH_REMATCH[1]}
    relative=${BASH_REMATCH[2]}
    [[ -z "${seen[$relative]+x}" ]] || \
      holdfast_die "successor render-input authority repeats a path"
    seen[$relative]=1
    source="$script_dir/$relative"
    require_root_control_file "$source"
    [[ "$(holdfast_sha256 "$source")" == "$digest" ]] || \
      holdfast_die "successor generation authority drifted before persistence: $relative"
    atomic_copy_authority "$source" "$authority_dir/$relative"
    successor_generation_authorities+=("$relative")
  done <"$render_inputs"
  ((${#successor_generation_authorities[@]} == 6)) || \
    holdfast_die "successor generation authority set is not exactly six files"
  mkdir -m 0700 -- "$authority_dir/assets"
  for relative in 20260823_rikune_root_up.sql 20260823_rikune_root_down.sql; do
    require_root_control_file "$script_dir/assets/$relative"
    atomic_copy_authority \
      "$script_dir/assets/$relative" "$authority_dir/assets/$relative"
  done
  require_root_control_file "$script_dir/../../Dockerfile.analyzer"
  atomic_copy_authority \
    "$script_dir/../../Dockerfile.analyzer" \
    "$authority_dir/Dockerfile.analyzer"
  require_root_control_file "$script_dir/../../bridge/package-lock.json"
  atomic_copy_authority \
    "$script_dir/../../bridge/package-lock.json" \
    "$authority_dir/bridge-package-lock.json"
}

persist_successor_authority() {
  local successor_tmp successor_state_tmp successor_armed_at
  [[ "$successor" == "true" ]] || return 0
  [[ "$(holdfast_sha256 "$state_file")" == "$predecessor_current_sha" ]] || \
    holdfast_die "predecessor CURRENT changed before successor authority persistence"
  predecessor_current_file="$backup/PREDECESSOR-CURRENT.json"
  atomic_copy_authority "$state_file" "$predecessor_current_file"
  [[ "$(holdfast_sha256 "$predecessor_current_file")" == "$predecessor_current_sha" ]] || \
    holdfast_die "persisted predecessor CURRENT differs"
  successor_armed_receipt="$backup/SUCCESSOR-ARMED.receipt"
  successor_tmp="$backup/.SUCCESSOR-ARMED.receipt.$$"
  successor_armed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  {
    printf 'schema_version=1\n'
    printf 'armed_at=%s\n' "$successor_armed_at"
    printf 'estate_root=%s\n' "$estate_root"
    printf 'successor_backup_dir=%s\n' "$backup"
    printf 'candidate_dry_run_receipt_sha256=%s\n' "$bound_dry_receipt_sha"
    printf 'candidate_release_evidence_sha256=%s\n' "$(holdfast_sha256 "$stage/RELEASE-EVIDENCE.json")"
    printf 'predecessor_current_file=PREDECESSOR-CURRENT.json\n'
    printf 'predecessor_current_sha256=%s\n' "$predecessor_current_sha"
    printf 'predecessor_backup_dir=%s\n' "$predecessor_backup"
    printf 'predecessor_control_sha256=%s\n' "$predecessor_control_sha"
    printf 'predecessor_apply_receipt_sha256=%s\n' "$predecessor_apply_sha"
    printf 'predecessor_release_evidence_sha256=%s\n' "$predecessor_release_sha"
    printf 'predecessor_runtime_backup_receipt_sha256=%s\n' "$predecessor_runtime_receipt_sha"
    printf 'predecessor_runtime_backup_manifest_sha256=%s\n' "$predecessor_runtime_manifest_sha"
    printf 'predecessor_release_generation=%s\n' "$predecessor_generation"
    printf 'release_generation=%s\n' "$release_generation"
    printf 'route_database_state=absent\n'
    printf 'public_ipv4_ipv6_closed_status=404\n'
    printf 'predecessor_runtime_verified=true\n'
    printf 'ingress_opened=false\n'
  } >"$successor_tmp"
  commit_atomic_file "$successor_tmp" "$successor_armed_receipt"
  successor_armed_sha=$(holdfast_sha256 "$successor_armed_receipt")

  successor_state_tmp="$state_dir/.CURRENT.json.$$"
  jq -n \
    --arg armed_at "$successor_armed_at" \
    --arg estate "$estate_root" \
    --arg backup "$backup" \
    --arg dry "$dry_run_dir" \
    --arg release_env_sha "$release_env_sha" \
    --arg release_evidence_sha "$(holdfast_sha256 "$stage/RELEASE-EVIDENCE.json")" \
    --arg dry_receipt_sha "$bound_dry_receipt_sha" \
    --arg successor_armed_sha "$successor_armed_sha" \
    --arg predecessor_current_sha "$predecessor_current_sha" \
    --arg predecessor_backup "$predecessor_backup" \
    --arg predecessor_control "$predecessor_control_sha" \
    --arg predecessor_apply "$predecessor_apply_sha" \
    --arg predecessor_release "$predecessor_release_sha" \
    --arg predecessor_runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg predecessor_runtime_manifest "$predecessor_runtime_manifest_sha" \
    --argjson predecessor_generation "$predecessor_generation" \
    --argjson generation "$release_generation" \
    '{schema_version:2,state:"successor_armed",successor_armed_at:$armed_at,
      estate_root:$estate,backup_dir:$backup,dry_run_dir:$dry,
      release_env_sha256:$release_env_sha,release_evidence_sha256:$release_evidence_sha,
      dry_run_receipt_sha256:$dry_receipt_sha,successor:true,
      successor_armed_receipt:"SUCCESSOR-ARMED.receipt",
      successor_armed_receipt_sha256:$successor_armed_sha,
      predecessor_current_file:"PREDECESSOR-CURRENT.json",
      predecessor_current_sha256:$predecessor_current_sha,
      predecessor_backup_dir:$predecessor_backup,
      predecessor_control_sha256:$predecessor_control,
      predecessor_apply_receipt_sha256:$predecessor_apply,
      predecessor_release_evidence_sha256:$predecessor_release,
      predecessor_runtime_backup_receipt_sha256:$predecessor_runtime_receipt,
      predecessor_runtime_backup_manifest_sha256:$predecessor_runtime_manifest,
      predecessor_release_generation:$predecessor_generation,
      release_generation:$generation,route_database_state:"absent",
      public_ipv4_ipv6_closed_status:404,predecessor_runtime_verified:true,
      ingress_opened:false}' >"$successor_state_tmp"
  commit_atomic_file "$successor_state_tmp" "$state_file"
  validate_persisted_successor_authority "$state_file"
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    "${HOLDFAST_TEST_SIGKILL_AFTER_SUCCESSOR_ARM:-0}" == "1" ]]; then
    kill -KILL "$$"
  fi
}

verify_database_absent() {
  local observed
  observed=$(PGAPPNAME=holdfast-rikune-apply-db-absent psql "$routes_database_url" -XAtq \
    -f "$script_dir/assets/verify_rikune_root_absent.sql") || return 1
  [[ "$observed" == "ok" ]] || {
    echo "holdfast: apply does not prove rikune-root/analyze root absence" >&2
    return 1
  }
}

verify_closed_bracket() {
  verify_database_absent
  "$script_dir/public-origin-verify.sh" --mode closed --url https://analyze.w33d.xyz/
  verify_database_absent
}

predecessor_current_file=""
predecessor_current_sha=""
predecessor_backup=""
predecessor_control_sha=""
predecessor_apply_sha=""
predecessor_release_sha=""
predecessor_runtime_receipt_sha=""
predecessor_runtime_manifest_sha=""
predecessor_generation=""
release_generation=""
successor_armed_receipt=""
successor_armed_sha=""

validate_predecessor_snapshot() {
  local snapshot=$1 expected key value predecessor_apply predecessor_file
  require_root_control_file "$snapshot"
  jq -e \
    --arg estate "$estate_root" \
    '.schema_version == 2 and .state == "applied_ingress_closed" and
     .estate_root == $estate and .route_database_state == "absent" and
     .public_ipv4_ipv6_closed_status == 404 and .runtime_verified == true and
     .services_activated == true and .ingress_opened == false' \
    "$snapshot" >/dev/null || \
    holdfast_die "successor requires an applied, runtime-verified, dual-stack-404 predecessor"

  predecessor_backup=$(jq -er '.backup_dir' "$snapshot")
  holdfast_require_absolute "$predecessor_backup"
  require_canonical_root_directory "$predecessor_backup"
  [[ -z "$(find "$predecessor_backup" -maxdepth 0 -perm /077 -print -quit)" ]] || \
    holdfast_die "predecessor backup must not be group/world accessible"
  [[ -z "$(find "$predecessor_backup" -xdev -type l -print -quit)" ]] || \
    holdfast_die "predecessor backup contains a symlink"
  [[ -z "$(find "$predecessor_backup" -xdev ! -user root -print -quit)" ]] || \
    holdfast_die "predecessor backup contains a non-root-owned entry"
  for predecessor_file in \
    "$predecessor_backup/CONTROL.sha256" "$predecessor_backup/APPLY.receipt" \
    "$predecessor_backup/RELEASE-EVIDENCE.json" "$predecessor_backup/release.env" \
    "$predecessor_backup/runtime/BACKUP.receipt" \
    "$predecessor_backup/runtime/SHA256SUMS"; do
    require_root_control_file "$predecessor_file"
  done
  (cd "$predecessor_backup" && sha256sum --check CONTROL.sha256)
  (cd "$predecessor_backup/runtime" && sha256sum --check SHA256SUMS)

  predecessor_control_sha=$(holdfast_sha256 "$predecessor_backup/CONTROL.sha256")
  predecessor_apply_sha=$(holdfast_sha256 "$predecessor_backup/APPLY.receipt")
  predecessor_release_sha=$(holdfast_sha256 "$predecessor_backup/RELEASE-EVIDENCE.json")
  predecessor_runtime_receipt_sha=$(holdfast_sha256 "$predecessor_backup/runtime/BACKUP.receipt")
  predecessor_runtime_manifest_sha=$(holdfast_sha256 "$predecessor_backup/runtime/SHA256SUMS")
  for value in "$predecessor_control_sha" "$predecessor_apply_sha" \
    "$predecessor_release_sha" "$predecessor_runtime_receipt_sha" \
    "$predecessor_runtime_manifest_sha"; do
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || holdfast_die "predecessor authority digest is invalid"
  done
  [[ "$(jq -er '.control_sha256' "$snapshot")" == "$predecessor_control_sha" ]] || \
    holdfast_die "predecessor CURRENT CONTROL hash differs"
  [[ "$(jq -er '.apply_receipt_sha256' "$snapshot")" == "$predecessor_apply_sha" ]] || \
    holdfast_die "predecessor CURRENT APPLY hash differs"
  [[ "$(jq -er '.release_evidence_sha256' "$snapshot")" == "$predecessor_release_sha" ]] || \
    holdfast_die "predecessor CURRENT RELEASE hash differs"
  if jq -e 'has("runtime_backup_receipt_sha256")' "$snapshot" >/dev/null; then
    [[ "$(jq -er '.runtime_backup_receipt_sha256' "$snapshot")" == \
      "$predecessor_runtime_receipt_sha" ]] || \
      holdfast_die "predecessor CURRENT runtime receipt hash differs"
  fi
  if jq -e 'has("runtime_backup_manifest_sha256")' "$snapshot" >/dev/null; then
    [[ "$(jq -er '.runtime_backup_manifest_sha256' "$snapshot")" == \
      "$predecessor_runtime_manifest_sha" ]] || \
      holdfast_die "predecessor CURRENT runtime manifest hash differs"
  fi

  predecessor_apply="$predecessor_backup/APPLY.receipt"
  for expected in \
    "schema_version=2" "completion_state=applied_ingress_closed" \
    "estate_root=$estate_root" "backup_dir=$predecessor_backup" \
    "control_sha256=$predecessor_control_sha" \
    "release_evidence_sha256=$predecessor_release_sha" \
    "runtime_backup=passed" "closed_bracket=passed" \
    "route_database_state=absent" "public_ipv4_ipv6_closed_status=404" \
    "services_activated=true" "runtime_verified=true" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$predecessor_apply" "$key")" == "$value" ]] || \
      holdfast_die "predecessor APPLY authority differs: $key"
  done
  [[ "$(holdfast_receipt_value "$predecessor_backup/runtime/BACKUP.receipt" schema_version)" == "2" ]] || \
    holdfast_die "predecessor runtime backup schema differs"
  [[ "$(holdfast_receipt_value "$predecessor_backup/runtime/BACKUP.receipt" isolated_restore_probe)" == "passed" ]] || \
    holdfast_die "predecessor runtime backup lacks an isolated restore proof"
  predecessor_generation=$(jq -er '.release_generation // 1' "$snapshot")
  [[ "$predecessor_generation" =~ ^[1-9][0-9]*$ ]] || \
    holdfast_die "predecessor release generation is invalid"
  release_generation=$((predecessor_generation + 1))
}

validate_live_predecessor_authority() {
  local predecessor_release_policy_args=() predecessor_policy
  predecessor_current_file="$state_file"
  validate_predecessor_snapshot "$predecessor_current_file"
  predecessor_current_sha=$(holdfast_sha256 "$predecessor_current_file")
  if jq -e '.schema_version == 2 and .release_mode == "successor"' \
    "$predecessor_backup/RELEASE-EVIDENCE.json" >/dev/null; then
    predecessor_policy="$predecessor_backup/successor-authority/successor-policy.json"
    require_root_control_file "$predecessor_policy"
    grep -Fqx "$(holdfast_sha256 "$predecessor_policy")  successor-authority/successor-policy.json" \
      "$predecessor_backup/CONTROL.sha256" || \
      holdfast_die "predecessor CONTROL omits its successor policy"
    predecessor_release_policy_args=(--successor-policy "$predecessor_policy")
  fi
  python3 "$script_dir/validate_release_evidence.py" \
    --evidence "$predecessor_backup/RELEASE-EVIDENCE.json" \
    "${predecessor_release_policy_args[@]}"
  jq -e \
    --arg current "$predecessor_current_sha" \
    --arg control "$predecessor_control_sha" \
    --arg apply "$predecessor_apply_sha" \
    --arg release "$predecessor_release_sha" \
    --arg runtime "$predecessor_runtime_manifest_sha" \
    '.schema_version == 2 and .release_mode == "successor" and
     .predecessor_binding.current_state_sha256 == $current and
     .predecessor_binding.control_sha256 == $control and
     .predecessor_binding.apply_receipt_sha256 == $apply and
     .predecessor_binding.release_evidence_sha256 == $release and
     .predecessor_binding.runtime_manifest_sha256 == $runtime' \
    "$stage/RELEASE-EVIDENCE.json" >/dev/null || \
    holdfast_die "successor RELEASE-EVIDENCE points to another predecessor"
  verify_closed_bracket
}

validate_persisted_successor_authority() {
  local pointer=$1 expected key value armed_predecessor_backup armed_generation
  local armed_predecessor_generation
  [[ "$(jq -er '(.successor // false) | tostring' "$pointer")" == "true" ]] || return 0
  predecessor_current_file="$backup/PREDECESSOR-CURRENT.json"
  successor_armed_receipt="$backup/SUCCESSOR-ARMED.receipt"
  require_root_control_file "$predecessor_current_file"
  require_root_control_file "$successor_armed_receipt"
  successor_armed_sha=$(holdfast_sha256 "$successor_armed_receipt")
  predecessor_current_sha=$(holdfast_sha256 "$predecessor_current_file")
  armed_predecessor_backup=$(holdfast_receipt_value "$successor_armed_receipt" predecessor_backup_dir)
  armed_predecessor_generation=$(holdfast_receipt_value "$successor_armed_receipt" predecessor_release_generation)
  armed_generation=$(holdfast_receipt_value "$successor_armed_receipt" release_generation)
  validate_predecessor_snapshot "$predecessor_current_file"
  [[ "$predecessor_backup" == "$armed_predecessor_backup" && \
    "$predecessor_generation" == "$armed_predecessor_generation" && \
    "$release_generation" == "$armed_generation" ]] || \
    holdfast_die "successor arm generation or predecessor backup differs"
  for expected in \
    "schema_version=1" "successor_backup_dir=$backup" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "predecessor_apply_receipt_sha256=$predecessor_apply_sha" \
    "predecessor_release_evidence_sha256=$predecessor_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_manifest_sha" \
    "predecessor_release_generation=$predecessor_generation" \
    "release_generation=$release_generation" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$successor_armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "persisted successor authority differs: $key"
  done
  jq -e \
    --arg successor_sha "$successor_armed_sha" \
    --arg predecessor_sha "$predecessor_current_sha" \
    --arg predecessor_backup "$predecessor_backup" \
    --arg predecessor_control "$predecessor_control_sha" \
    --arg predecessor_apply "$predecessor_apply_sha" \
    --arg predecessor_release "$predecessor_release_sha" \
    --arg predecessor_runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg predecessor_runtime_manifest "$predecessor_runtime_manifest_sha" \
    --argjson predecessor_generation "$predecessor_generation" \
    --argjson generation "$release_generation" \
    '(.successor // false) == true and
     .successor_armed_receipt == "SUCCESSOR-ARMED.receipt" and
     .successor_armed_receipt_sha256 == $successor_sha and
     .predecessor_current_file == "PREDECESSOR-CURRENT.json" and
     .predecessor_current_sha256 == $predecessor_sha and
     .predecessor_backup_dir == $predecessor_backup and
     .predecessor_control_sha256 == $predecessor_control and
     .predecessor_apply_receipt_sha256 == $predecessor_apply and
     .predecessor_release_evidence_sha256 == $predecessor_release and
     .predecessor_runtime_backup_receipt_sha256 == $predecessor_runtime_receipt and
     .predecessor_runtime_backup_manifest_sha256 == $predecessor_runtime_manifest and
     .predecessor_release_generation == $predecessor_generation and
     .release_generation == $generation' "$pointer" >/dev/null || \
    holdfast_die "successor CURRENT linkage differs from its immutable authority"
}

append_successor_receipt_fields() {
  [[ "$successor" == "true" ]] || return 0
  printf 'successor=true\n'
  printf 'successor_armed_receipt=SUCCESSOR-ARMED.receipt\n'
  printf 'successor_armed_receipt_sha256=%s\n' "$successor_armed_sha"
  printf 'predecessor_current_file=PREDECESSOR-CURRENT.json\n'
  printf 'predecessor_current_sha256=%s\n' "$predecessor_current_sha"
  printf 'predecessor_backup_dir=%s\n' "$predecessor_backup"
  printf 'predecessor_control_sha256=%s\n' "$predecessor_control_sha"
  printf 'predecessor_apply_receipt_sha256=%s\n' "$predecessor_apply_sha"
  printf 'predecessor_release_evidence_sha256=%s\n' "$predecessor_release_sha"
  printf 'predecessor_runtime_backup_receipt_sha256=%s\n' "$predecessor_runtime_receipt_sha"
  printf 'predecessor_runtime_backup_manifest_sha256=%s\n' "$predecessor_runtime_manifest_sha"
  printf 'predecessor_release_generation=%s\n' "$predecessor_generation"
  printf 'release_generation=%s\n' "$release_generation"
  if [[ -f "$backup/runtime/BACKUP.receipt" && -f "$backup/runtime/SHA256SUMS" ]]; then
    printf 'runtime_backup_receipt_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")"
    printf 'runtime_backup_manifest_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/SHA256SUMS")"
  fi
}

prior_running_services=()
runtime_product_was_running() {
  local wanted=$1 service
  for service in "${prior_running_services[@]}"; do
    [[ "$service" == "$wanted" ]] && return 0
  done
  return 1
}

validate_runtime_stop_authority() {
  local manifest=$1 arm="$backup/runtime/RUNTIME-BACKUP-ARMED.receipt"
  local key value compose_project init_prior_state
  require_root_control_file "$backup/runtime/compose-config.json"
  require_root_control_file "$manifest"
  require_root_control_file "$arm"
  compose_project=$(jq -er '.name' "$backup/runtime/compose-config.json") || \
    holdfast_die "runtime backup Compose project identity is absent"
  [[ "$compose_project" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || \
    holdfast_die "runtime backup Compose project identity is unsafe"
  for expected in \
    "schema_version=2" \
    "backup_dir=$backup/runtime" \
    "compose_project=$compose_project" \
    "compose_config_sha256=$(holdfast_sha256 "$backup/runtime/compose-config.json")" \
    "database_identity=postgres:5432/strad" \
    "prior_running_services_manifest=RUNNING-SERVICES.before" \
    "prior_running_services_sha256=$(holdfast_sha256 "$manifest")" \
    "runtime_writer_count=3" \
    "runtime_writers=strad,rikune-analyzer,rikune-volume-init" \
    "stop_authority=armed-before-writer-stop"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$arm" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup stop authority differs: $key"
  done
  init_prior_state=$(holdfast_receipt_value "$arm" volume_init_prior_state)
  [[ "$init_prior_state" == "absent" || "$init_prior_state" == "created" || \
    "$init_prior_state" == "exited" || "$init_prior_state" == "dead" ]] || \
    holdfast_die "runtime backup stop authority has an active volume initializer"
}

load_prior_running_services() {
  local manifest=$1 service index previous_index=-1 receipt_manifest receipt_sha
  local authority="$backup/runtime/RUNTIME-BACKUP-ARMED.receipt"
  prior_running_services=()
  if [[ ! -f "$manifest" || -L "$manifest" || "$(stat -c '%u:%h' -- "$manifest" 2>/dev/null || true)" != "0:1" ]]; then
    echo "holdfast: prior-running manifest is unsafe or absent" >&2
    return 1
  fi
  if [[ ! -f "$authority" || -L "$authority" || \
    "$(stat -c '%u:%h' -- "$authority" 2>/dev/null || true)" != "0:1" ]]; then
    echo "holdfast: runtime backup stop authority is unsafe or absent" >&2
    return 1
  fi
  receipt_manifest=$(holdfast_receipt_value "$authority" prior_running_services_manifest) || {
    echo "holdfast: runtime backup stop authority lacks the prior-running manifest identity" >&2
    return 1
  }
  receipt_sha=$(holdfast_receipt_value "$authority" prior_running_services_sha256) || {
    echo "holdfast: runtime backup stop authority lacks the prior-running manifest digest" >&2
    return 1
  }
  if [[ "$receipt_manifest" != "RUNNING-SERVICES.before" || "$receipt_sha" != "$(holdfast_sha256 "$manifest")" ]]; then
    echo "holdfast: runtime backup stop authority does not bind the prior-running manifest" >&2
    return 1
  fi
  while IFS= read -r service || [[ -n "$service" ]]; do
    if [[ -z "$service" ]]; then
      echo "holdfast: prior-running manifest contains a blank service" >&2
      return 1
    fi
    index=-1
    case "$service" in
      strad) index=0 ;;
      rikune-analyzer) index=1 ;;
      *)
        echo "holdfast: prior-running manifest contains an unknown service: $service" >&2
        return 1
        ;;
    esac
    if ((index <= previous_index)); then
      echo "holdfast: prior-running manifest is duplicated or out of order" >&2
      return 1
    fi
    previous_index=$index
    prior_running_services+=("$service")
  done <"$manifest"
}

validate_runtime_backup_authority() {
  local manifest=$1 arm="$backup/runtime/RUNTIME-BACKUP-ARMED.receipt"
  validate_runtime_stop_authority "$manifest"
  require_root_control_file "$backup/runtime/SHA256SUMS"
  require_root_control_file "$backup/runtime/BACKUP.receipt"
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" schema_version)" == "2" ]] || \
    holdfast_die "runtime backup receipt schema is not v2"
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" isolated_restore_probe)" == "passed" ]] || \
    holdfast_die "runtime backup lacks a passed isolated restore probe"
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" runtime_writers_stopped)" == "passed" ]] || \
    holdfast_die "runtime backup did not prove writer quiescence"
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" writers_left_quiesced)" == "passed" ]] || \
    holdfast_die "runtime backup did not leave writers quiesced for the estate transaction"
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" prior_running_services_manifest)" == "RUNNING-SERVICES.before" ]] || \
    holdfast_die "runtime backup points to another prior-running manifest"
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" prior_running_services_sha256)" == "$(holdfast_sha256 "$manifest")" ]] || \
    holdfast_die "runtime backup receipt does not bind the prior-running manifest"
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" runtime_backup_armed_receipt)" == \
    "RUNTIME-BACKUP-ARMED.receipt" ]] || \
    holdfast_die "runtime backup receipt points to another stop authority"
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" runtime_backup_armed_sha256)" == \
    "$(holdfast_sha256 "$arm")" ]] || \
    holdfast_die "runtime backup receipt does not bind the stop authority"
  grep -Fqx "$(holdfast_sha256 "$manifest")  RUNNING-SERVICES.before" \
    "$backup/runtime/SHA256SUMS" || holdfast_die "runtime backup does not bind the prior-running manifest"
  grep -Fqx "$(holdfast_sha256 "$arm")  RUNTIME-BACKUP-ARMED.receipt" \
    "$backup/runtime/SHA256SUMS" || holdfast_die "runtime backup checksums do not bind the stop authority"
  (cd "$backup/runtime" && sha256sum --check SHA256SUMS)
  load_prior_running_services "$manifest" || holdfast_die "runtime prior-running manifest validation failed"
}

verify_products_quiesced() {
  local service state container_output
  local container_ids=()
  for service in strad rikune-analyzer; do
    container_output=$(docker compose --env-file "$stage/deploy/.env" \
      -f "$stage/deploy/docker-compose.yml" ps -aq "$service") || \
      holdfast_die "could not confirm quiesced product service: $service"
    container_ids=()
    if [[ -n "$container_output" ]]; then mapfile -t container_ids <<<"$container_output"; fi
    ((${#container_ids[@]} <= 1)) || holdfast_die "multiple containers found for quiesced service: $service"
    if ((${#container_ids[@]} == 1)); then
      state=$(docker inspect -f '{{.State.Status}}' "${container_ids[0]}")
      [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
        holdfast_die "runtime backup did not leave product service quiesced: $service"
    fi
  done
}

resume_prior_running_products() {
  local service state health container_output all_ready
  local recovery_compose=(docker compose -f "$backup/runtime/compose-config.json")
  local container_ids=()
  local excluded_services=()
  require_root_control_file "$backup/runtime/compose-config.json"
  for service in strad rikune-analyzer; do
    if ! runtime_product_was_running "$service"; then excluded_services+=("$service"); fi
  done
  # Re-establish the exact pre-backup subset.  In particular, the one-shot
  # initializer and every excluded product remain inactive.
  "${recovery_compose[@]}" stop -t 120 rikune-volume-init "${excluded_services[@]}" >/dev/null || return 1
  if ((${#prior_running_services[@]})); then
    "${recovery_compose[@]}" start "${prior_running_services[@]}" >/dev/null || return 1
  fi
  all_ready="false"
  for _ in $(seq 1 60); do
    all_ready="true"
    for service in "${prior_running_services[@]}"; do
      container_output=$("${recovery_compose[@]}" ps -aq "$service") || return 1
      container_ids=()
      if [[ -n "$container_output" ]]; then mapfile -t container_ids <<<"$container_output"; fi
      if ((${#container_ids[@]} != 1)); then all_ready="false"; continue; fi
      state=$(docker inspect -f '{{.State.Status}}' "${container_ids[0]}") || return 1
      health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
        "${container_ids[0]}") || return 1
      if [[ "$state" != "running" || ("$health" != "none" && "$health" != "healthy") ]]; then
        all_ready="false"
      fi
    done
    [[ "$all_ready" == "true" ]] && break
    sleep 5
  done
  if [[ "$all_ready" != "true" ]]; then
    echo "holdfast: could not prove the prior-running product subset healthy" >&2
    return 1
  fi
  for service in "${excluded_services[@]}" rikune-volume-init; do
    container_output=$("${recovery_compose[@]}" ps -aq "$service") || return 1
    container_ids=()
    if [[ -n "$container_output" ]]; then mapfile -t container_ids <<<"$container_output"; fi
    ((${#container_ids[@]} <= 1)) || {
      echo "holdfast: multiple containers found for excluded runtime service: $service" >&2
      return 1
    }
    for container_id in "${container_ids[@]}"; do
      state=$(docker inspect -f '{{.State.Status}}' "$container_id") || return 1
      if [[ "$state" == "running" || "$state" == "restarting" || "$state" == "paused" ]]; then
        echo "holdfast: excluded runtime service remains active: $service=$state" >&2
        return 1
      fi
    done
  done
}

validate_runtime_backup_location() {
  local name
  [[ "$backup" = /* && "$(dirname -- "$backup")" == "$backup_root" ]] || {
    echo "holdfast: runtime backup state points outside the requested backup root" >&2
    return 1
  }
  name=$(basename -- "$backup")
  [[ "$name" =~ ^holdfast-rikune-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || {
    echo "holdfast: runtime backup state has an unsafe backup identity" >&2
    return 1
  }
  [[ -d "$backup" && ! -L "$backup" && "$(readlink -f -- "$backup")" == "$backup" && \
    "$(stat -c '%u' -- "$backup" 2>/dev/null || true)" == "0" ]] || {
    echo "holdfast: runtime backup state points to an unsafe backup directory" >&2
    return 1
  }
  [[ -z "$(find "$backup" -maxdepth 0 -perm /077 -print -quit)" ]] || {
    echo "holdfast: runtime backup state points to an accessible backup directory" >&2
    return 1
  }
}

validate_runtime_backup_caller_authority() {
  local require_current_inputs=${1:-false} expected key value caller_sha
  require_root_control_file "$state_file"
  require_root_control_file "$caller_armed_receipt"
  caller_sha=$(holdfast_sha256 "$caller_armed_receipt")
  jq -e \
    --arg estate "$estate_root" --arg backup "$backup" --arg dry "$dry_run_dir" \
    --arg runtime "$backup/runtime" --arg caller_sha "$caller_sha" \
    --arg release_sha "$(holdfast_receipt_value "$caller_armed_receipt" release_env_sha256)" \
    --arg evidence_sha "$(holdfast_receipt_value "$caller_armed_receipt" release_evidence_sha256)" \
    --arg dry_sha "$(holdfast_receipt_value "$caller_armed_receipt" dry_run_receipt_sha256)" \
    --arg targets_sha "$(holdfast_receipt_value "$caller_armed_receipt" targets_sha256)" \
    --arg preimages_sha "$(holdfast_receipt_value "$caller_armed_receipt" apply_preimages_sha256)" \
    --arg absent_sha "$(holdfast_receipt_value "$caller_armed_receipt" apply_absent_sha256)" \
    --arg render_sha "$(holdfast_receipt_value "$caller_armed_receipt" render_inputs_sha256)" \
    '.schema_version == 2 and .state == "runtime_backup_armed" and
     .estate_root == $estate and .backup_dir == $backup and .dry_run_dir == $dry and
     .runtime_backup_dir == $runtime and
     .runtime_backup_caller_armed_receipt == "RUNTIME-BACKUP-CALLER-ARMED.receipt" and
     .runtime_backup_caller_armed_receipt_sha256 == $caller_sha and
     .runtime_backup_armed_receipt == "runtime/RUNTIME-BACKUP-ARMED.receipt" and
     .release_env_sha256 == $release_sha and .release_evidence_sha256 == $evidence_sha and
     .dry_run_receipt_sha256 == $dry_sha and
     .targets_sha256 == $targets_sha and .apply_preimages_sha256 == $preimages_sha and
     .apply_absent_sha256 == $absent_sha and .render_inputs_sha256 == $render_sha and
     .stop_authority_contract == "absence-means-stop-not-started" and .ingress_opened == false' \
    "$state_file" >/dev/null || holdfast_die "runtime backup caller state differs from its receipt"
  if [[ "$(jq -er '(.successor // false) | tostring' "$state_file")" == "true" ]]; then
    validate_persisted_successor_authority "$state_file"
  fi
  for expected in \
    "schema_version=2" "estate_root=$estate_root" "dry_run_dir=$dry_run_dir" \
    "backup_dir=$backup" "runtime_backup_dir=$backup/runtime" \
    "runtime_backup_armed_receipt=runtime/RUNTIME-BACKUP-ARMED.receipt" \
    "stop_authority_contract=absence-means-stop-not-started" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$caller_armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup caller authority differs: $key"
  done
  if [[ "$require_current_inputs" == "true" ]]; then
    for expected in \
      "release_env_sha256=$release_env_sha" \
      "release_evidence_sha256=$(holdfast_sha256 "$stage/RELEASE-EVIDENCE.json")" \
      "dry_run_receipt_sha256=$bound_dry_receipt_sha" \
      "targets_sha256=$(holdfast_sha256 "$targets")" \
      "apply_preimages_sha256=$(holdfast_sha256 "$apply_preimages")" \
      "apply_absent_sha256=$(holdfast_sha256 "$apply_absent")" \
      "render_inputs_sha256=$(holdfast_sha256 "$render_inputs")"; do
      key=${expected%%=*}
      value=${expected#*=}
      [[ "$(holdfast_receipt_value "$caller_armed_receipt" "$key")" == "$value" ]] || \
        holdfast_die "runtime backup caller input binding differs: $key"
    done
  fi
}

record_runtime_backup_cleanup() {
  local reason=$1 arm_state=$2 arm_sha="not-created" manifest_sha="not-created"
  local restore_result="not-required" success_sha="not-created" receipt temporary expected key value
  receipt="$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt"
  if [[ "$arm_state" == "present" ]]; then
    arm_sha=$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")
    manifest_sha=$(holdfast_sha256 "$prior_running_manifest")
    restore_result="passed"
  fi
  if [[ -f "$backup/runtime/BACKUP.receipt" && ! -L "$backup/runtime/BACKUP.receipt" ]]; then
    success_sha=$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")
  fi
  if [[ -e "$receipt" || -L "$receipt" ]]; then
    require_root_control_file "$receipt"
  else
    temporary="$backup/.RUNTIME-BACKUP-CALLER-CLEANUP.receipt.$$"
    {
      printf 'schema_version=2\n'
      printf 'cleaned_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'cleanup_reason=%s\n' "$reason"
      printf 'runtime_backup_caller_armed_sha256=%s\n' "$(holdfast_sha256 "$caller_armed_receipt")"
      printf 'runtime_stop_authority=%s\n' "$arm_state"
      printf 'runtime_backup_armed_sha256=%s\n' "$arm_sha"
      printf 'prior_running_services_sha256=%s\n' "$manifest_sha"
      printf 'runtime_backup_success_receipt_sha256=%s\n' "$success_sha"
      printf 'prior_running_services_restored=%s\n' "$restore_result"
      printf 'excluded_runtime_services_inactive=%s\n' "$restore_result"
      printf 'volume_init_inactive=%s\n' "$restore_result"
      printf 'cleanup_status=passed\n'
      printf 'ingress_opened=false\n'
    } >"$temporary"
    commit_atomic_file "$temporary" "$receipt"
  fi
  for expected in \
    "schema_version=2" \
    "runtime_backup_caller_armed_sha256=$(holdfast_sha256 "$caller_armed_receipt")" \
    "runtime_stop_authority=$arm_state" "runtime_backup_armed_sha256=$arm_sha" \
    "prior_running_services_sha256=$manifest_sha" \
    "runtime_backup_success_receipt_sha256=$success_sha" \
    "prior_running_services_restored=$restore_result" \
    "excluded_runtime_services_inactive=$restore_result" \
    "volume_init_inactive=$restore_result" "cleanup_status=passed" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup caller cleanup authority differs: $key"
  done
}

archive_runtime_backup_state() {
  local archive was_successor="false"
  require_root_control_file "$state_file"
  if [[ "$(jq -er '(.successor // false) | tostring' "$state_file")" == "true" ]]; then
    was_successor="true"
    validate_persisted_successor_authority "$state_file"
  fi
  archive="$state_dir/RUNTIME-BACKUP-ABORTED-$(date -u +%Y%m%dT%H%M%SZ)-$$.json"
  if [[ "$was_successor" == "true" ]]; then
    archive_and_restore_predecessor_current "$archive"
  else
    [[ ! -e "$archive" && ! -L "$archive" ]] || holdfast_die "runtime backup state archive collision"
    mv -T -- "$state_file" "$archive"
    sync -f "$archive"
    sync -f "$state_dir"
  fi
}

recover_existing_successor_arm_state() {
  local archive candidate_backup caller
  require_root_control_file "$state_file"
  jq -e \
    --arg estate "$estate_root" \
    '.schema_version == 2 and .state == "successor_armed" and
     .successor == true and .estate_root == $estate and
     .route_database_state == "absent" and
     .public_ipv4_ipv6_closed_status == 404 and .ingress_opened == false' \
    "$state_file" >/dev/null || \
    holdfast_die "successor arm recovery state differs"
  candidate_backup=$(jq -er '.backup_dir' "$state_file")
  backup=$candidate_backup
  validate_runtime_backup_location || \
    holdfast_die "successor arm recovery path validation failed"
  validate_persisted_successor_authority "$state_file"
  [[ ! -e "$backup/runtime" && ! -L "$backup/runtime" ]] || \
    holdfast_die "successor arm recovery refuses a backup with runtime mutation state"
  caller="$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"
  if [[ -e "$caller" || -L "$caller" ]]; then
    require_root_control_file "$caller"
    [[ "$(holdfast_receipt_value "$caller" backup_dir)" == "$backup" && \
      "$(holdfast_receipt_value "$caller" estate_root)" == "$estate_root" ]] || \
      holdfast_die "successor arm caller authority points elsewhere"
  fi
  archive="$state_dir/SUCCESSOR-ARM-ABORTED-${successor_armed_sha:0:24}.json"
  archive_and_restore_predecessor_current "$archive"
  holdfast_die "interrupted successor arm was archived and its predecessor restored; rerun apply with a fresh ceremony"
}

record_caller_receipt_only_abort() {
  local receipt="$backup/RUNTIME-BACKUP-CALLER-ABORTED.receipt" temporary
  [[ ! -e "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" && \
    ! -L "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" && \
    ! -e "$backup/runtime/BACKUP.receipt" && ! -L "$backup/runtime/BACKUP.receipt" ]] || \
    holdfast_die "runtime stop authority appeared before caller state commit"
  if [[ -e "$receipt" || -L "$receipt" ]]; then require_root_control_file "$receipt"; return; fi
  temporary="$backup/.RUNTIME-BACKUP-CALLER-ABORTED.receipt.$$"
  {
    printf 'schema_version=2\n'
    printf 'aborted_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'runtime_backup_caller_armed_sha256=%s\n' "$(holdfast_sha256 "$caller_armed_receipt")"
    printf 'runtime_stop_authority=not-created\n'
    printf 'runtime_mutation_started=false\n'
    printf 'ingress_opened=false\n'
  } >"$temporary"
  commit_atomic_file "$temporary" "$receipt"
}

recover_runtime_backup_caller_arm() {
  local reason=$1 arm_state="not-created"
  if [[ ! -e "$state_file" && ! -L "$state_file" ]]; then
    if [[ -f "$caller_armed_receipt" && ! -L "$caller_armed_receipt" ]]; then
      record_caller_receipt_only_abort
    fi
    return 0
  fi
  (validate_runtime_backup_caller_authority false) || return 1
  if [[ -e "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" || \
    -L "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" ]]; then
    arm_state="present"
    (validate_runtime_stop_authority "$prior_running_manifest") || return 1
    load_prior_running_services "$prior_running_manifest" || return 1
    resume_prior_running_products || return 1
  else
    [[ ! -e "$backup/runtime/BACKUP.receipt" && ! -L "$backup/runtime/BACKUP.receipt" ]] || {
      echo "holdfast: runtime backup succeeded without its durable stop authority" >&2
      return 1
    }
  fi
  record_runtime_backup_cleanup "$reason" "$arm_state"
  archive_runtime_backup_state
}

recover_existing_runtime_backup_state() {
  local current candidate_backup
  require_root_control_file "$state_file"
  current=$(jq -er '.state' "$state_file")
  [[ "$current" == "runtime_backup_armed" ]] || \
    holdfast_die "an active Holdfast release state already exists: $current"
  candidate_backup=$(jq -er '.backup_dir' "$state_file")
  backup=$candidate_backup
  validate_runtime_backup_location || holdfast_die "runtime backup recovery path validation failed"
  caller_armed_receipt="$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"
  prior_running_manifest="$backup/runtime/RUNNING-SERVICES.before"
  # Recovery must remain possible after the mutable dry-run ceremony inputs
  # disappear or drift.  The durable CURRENT/caller/runtime authorities alone
  # govern this exact-subset cleanup; a fresh apply validates fresh inputs.
  validate_runtime_backup_caller_authority false
  recover_runtime_backup_caller_arm reentry || \
    holdfast_die "runtime backup caller recovery failed; durable state was retained"
  holdfast_die "interrupted runtime backup was cleaned up; rerun apply with a fresh ceremony"
}

prearm_cleanup_active="false"
prearm_exit_cleanup() {
  local status="$?" restore_status=0
  trap - EXIT HUP INT TERM
  if [[ "$prearm_cleanup_active" == "true" ]]; then
    set +e
    recover_runtime_backup_caller_arm prearm_failure
    restore_status=$?
    if [[ $restore_status -eq 0 ]]; then
      echo "holdfast: restored the exact prior-running product subset after a pre-arm failure" >&2
    else
      echo "holdfast: failed to restore the exact prior-running product subset after a pre-arm failure" >&2
    fi
    if [[ $status -eq 0 ]]; then status=1; fi
  fi
  exit "$status"
}

state_file="$state_dir/CURRENT.json"
# Restore a previously quiesced runtime before consulting mutable ceremony
# inputs.  This is the only state whose cleanup is safe without the dry-run
# package; all other active release states remain dedicated recovery work.
if [[ -e "$state_dir" || -L "$state_dir" ]]; then
  require_canonical_root_directory "$state_dir"
  [[ -z "$(find "$state_dir" -maxdepth 0 -perm /077 -print -quit)" ]] || \
    holdfast_die "state directory must be private before runtime recovery"
  if [[ -e "$state_file" || -L "$state_file" ]]; then
    require_canonical_root_directory "$backup_root"
    [[ -z "$(find "$backup_root" -maxdepth 0 -perm /077 -print -quit)" ]] || \
      holdfast_die "backup root must be private before runtime recovery"
    existing_state=$(jq -er '.state' "$state_file")
    if [[ "$existing_state" == "runtime_backup_armed" ]]; then
      recover_existing_runtime_backup_state
    elif [[ "$existing_state" == "successor_armed" ]]; then
      recover_existing_successor_arm_state
    fi
    [[ "$successor" == "true" ]] || \
      holdfast_die "an active Holdfast release state already exists: $existing_state"
  fi
elif [[ "$successor" == "true" ]]; then
  holdfast_die "successor apply requires an active predecessor CURRENT"
fi

[[ -n "$routes_database_url" ]] || holdfast_die "ROUTES_DATABASE_URL is required to prove closed ingress"
case "$routes_database_url" in
  postgres://*|postgresql://*) ;;
  *) holdfast_die "ROUTES_DATABASE_URL must be a PostgreSQL URI supplied by the secret authority" ;;
esac
if [[ "$routes_database_url" =~ [[:space:][:cntrl:]] ]]; then
  holdfast_die "ROUTES_DATABASE_URL contains unsafe whitespace or control characters"
fi
if [[ "$successor" == "true" ]]; then
  [[ -f "$state_file" && ! -L "$state_file" ]] || \
    holdfast_die "successor apply requires an active predecessor CURRENT"
  validate_live_predecessor_authority
fi
[[ -d "$estate_root/access-governance" && -d "$stage" && -f "$receipt" && ! -L "$receipt" ]] || \
  holdfast_die "estate or dry-run package is incomplete"
[[ -z "$(find "$dry_run_dir" -maxdepth 0 -perm /077 -print -quit)" ]] || \
  holdfast_die "dry-run directory must not be group/world accessible"
for directory in "$dry_run_dir" "$stage"; do
  [[ ! -L "$directory" && "$(readlink -f -- "$directory")" == "$directory" && \
    "$(stat -c '%u' -- "$directory")" == "0" ]] || \
    holdfast_die "dry-run package directories must be canonical and root-owned"
done

verify_release_bindings

# Complete the non-mutating transaction gate before any runtime backup side effect.
python3 "$script_dir/estate_transaction.py" preflight \
  --estate-root "$estate_root" \
  --stage-root "$stage" \
  --targets "$targets" \
  --preimages "$apply_preimages" \
  --absent "$apply_absent"

ensure_private_control_directory "$backup_root"
ensure_private_control_directory "$state_dir"
if [[ "$successor" == "true" ]]; then
  [[ -f "$state_file" && ! -L "$state_file" && \
    "$(holdfast_sha256 "$state_file")" == "$predecessor_current_sha" ]] || \
    holdfast_die "predecessor CURRENT changed during successor preflight"
else
  [[ ! -e "$state_file" && ! -L "$state_file" ]] || \
    holdfast_die "an active Holdfast release state appeared after recovery preflight"
fi
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
backup="$backup_root/holdfast-rikune-${timestamp}-$$"
[[ ! -e "$backup" && ! -L "$backup" ]] || holdfast_die "backup collision"
mkdir -m 0700 -- "$backup"
validate_runtime_backup_location || holdfast_die "new runtime backup path validation failed"
persist_successor_authority
persist_successor_generation_authority

# Persist caller authority before runtime-backup may stop a writer.  A lone
# caller receipt proves the runtime stop call has not begun; CURRENT is always
# committed before invoking runtime-backup.
caller_armed_receipt="$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"
caller_armed_tmp="$backup/.RUNTIME-BACKUP-CALLER-ARMED.receipt.$$"
prior_running_manifest="$backup/runtime/RUNNING-SERVICES.before"
prearm_cleanup_active="true"
trap prearm_exit_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
caller_armed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
{
  printf 'schema_version=2\n'
  printf 'armed_at=%s\n' "$caller_armed_at"
  printf 'estate_root=%s\n' "$estate_root"
  printf 'dry_run_dir=%s\n' "$dry_run_dir"
  printf 'backup_dir=%s\n' "$backup"
  printf 'runtime_backup_dir=%s\n' "$backup/runtime"
  printf 'release_env_sha256=%s\n' "$release_env_sha"
  printf 'release_evidence_sha256=%s\n' "$(holdfast_sha256 "$stage/RELEASE-EVIDENCE.json")"
  printf 'dry_run_receipt_sha256=%s\n' "$bound_dry_receipt_sha"
  printf 'targets_sha256=%s\n' "$(holdfast_sha256 "$targets")"
  printf 'apply_preimages_sha256=%s\n' "$(holdfast_sha256 "$apply_preimages")"
  printf 'apply_absent_sha256=%s\n' "$(holdfast_sha256 "$apply_absent")"
  printf 'render_inputs_sha256=%s\n' "$(holdfast_sha256 "$render_inputs")"
  printf 'runtime_backup_armed_receipt=runtime/RUNTIME-BACKUP-ARMED.receipt\n'
  printf 'stop_authority_contract=absence-means-stop-not-started\n'
  printf 'ingress_opened=false\n'
  append_successor_receipt_fields
} >"$caller_armed_tmp"
commit_atomic_file "$caller_armed_tmp" "$caller_armed_receipt"

state_tmp="$state_dir/.CURRENT.json.$$"
jq -n \
  --arg armed_at "$caller_armed_at" --arg estate "$estate_root" --arg backup "$backup" \
  --arg dry "$dry_run_dir" --arg runtime "$backup/runtime" \
  --arg caller_sha "$(holdfast_sha256 "$caller_armed_receipt")" \
  --arg release_sha "$release_env_sha" \
  --arg evidence_sha "$(holdfast_sha256 "$stage/RELEASE-EVIDENCE.json")" \
  --arg dry_sha "$bound_dry_receipt_sha" \
  --arg targets_sha "$(holdfast_sha256 "$targets")" \
  --arg preimages_sha "$(holdfast_sha256 "$apply_preimages")" \
  --arg absent_sha "$(holdfast_sha256 "$apply_absent")" \
  --arg render_sha "$(holdfast_sha256 "$render_inputs")" \
  --arg successor_armed_sha "$successor_armed_sha" \
  --arg predecessor_current_sha "$predecessor_current_sha" \
  --arg predecessor_backup "$predecessor_backup" \
  --arg predecessor_control "$predecessor_control_sha" \
  --arg predecessor_apply "$predecessor_apply_sha" \
  --arg predecessor_release "$predecessor_release_sha" \
  --arg predecessor_runtime_receipt "$predecessor_runtime_receipt_sha" \
  --arg predecessor_runtime_manifest "$predecessor_runtime_manifest_sha" \
  --argjson successor "$successor" \
  --argjson predecessor_generation "${predecessor_generation:-0}" \
  --argjson generation "${release_generation:-0}" \
  '{schema_version:2,state:"runtime_backup_armed",runtime_backup_armed_at:$armed_at,estate_root:$estate,backup_dir:$backup,dry_run_dir:$dry,runtime_backup_dir:$runtime,runtime_backup_caller_armed_receipt:"RUNTIME-BACKUP-CALLER-ARMED.receipt",runtime_backup_caller_armed_receipt_sha256:$caller_sha,runtime_backup_armed_receipt:"runtime/RUNTIME-BACKUP-ARMED.receipt",release_env_sha256:$release_sha,release_evidence_sha256:$evidence_sha,dry_run_receipt_sha256:$dry_sha,targets_sha256:$targets_sha,apply_preimages_sha256:$preimages_sha,apply_absent_sha256:$absent_sha,render_inputs_sha256:$render_sha,stop_authority_contract:"absence-means-stop-not-started",ingress_opened:false} +
   (if $successor then {successor:true,successor_armed_receipt:"SUCCESSOR-ARMED.receipt",successor_armed_receipt_sha256:$successor_armed_sha,predecessor_current_file:"PREDECESSOR-CURRENT.json",predecessor_current_sha256:$predecessor_current_sha,predecessor_backup_dir:$predecessor_backup,predecessor_control_sha256:$predecessor_control,predecessor_apply_receipt_sha256:$predecessor_apply,predecessor_release_evidence_sha256:$predecessor_release,predecessor_runtime_backup_receipt_sha256:$predecessor_runtime_receipt,predecessor_runtime_backup_manifest_sha256:$predecessor_runtime_manifest,predecessor_release_generation:$predecessor_generation,release_generation:$generation} else {} end)' \
  >"$state_tmp"
commit_atomic_file "$state_tmp" "$state_file"
if [[ "$successor" == "true" ]]; then
  validate_persisted_successor_authority "$state_file"
fi
if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
  "${HOLDFAST_TEST_SIGKILL_AFTER_RUNTIME_CALLER_ARM:-0}" == "1" ]]; then
  kill -KILL "$$"
fi

# Runtime backup plus isolated restore probes are mandatory before file mutation.
"$script_dir/runtime-backup.sh" --compose-root "$stage" --backup-dir "$backup/runtime"
# Rebind every receipt-reviewed authority after the long-running backup window.
verify_release_bindings
validate_runtime_backup_authority "$prior_running_manifest"
verify_products_quiesced
atomic_copy_authority "$stage/RELEASE-EVIDENCE.json" "$backup/RELEASE-EVIDENCE.json"
atomic_copy_authority "$release_env" "$backup/release.env"
atomic_copy_authority "$receipt" "$backup/DRY-RUN.receipt"
[[ "$(holdfast_sha256 "$backup/DRY-RUN.receipt")" == "$bound_dry_receipt_sha" ]] || \
  holdfast_die "persisted dry-run receipt differs from the ceremony-bound receipt"
atomic_copy_authority "$supply_evidence" "$backup/SUPPLY-CHAIN.json"
atomic_copy_authority "$supply_signature" "$backup/SUPPLY-CHAIN.sig"
atomic_copy_authority "$supply_public_key" "$backup/SUPPLY-CHAIN.pub"
atomic_copy_authority "$targets" "$backup/TARGETS.sha256"
atomic_copy_authority "$apply_preimages" "$backup/APPLY-PREIMAGES.sha256"
atomic_copy_authority "$apply_absent" "$backup/APPLY-ABSENT.paths"
atomic_copy_authority "$render_inputs" "$backup/RENDER-INPUTS.sha256"
if [[ "$successor" == "true" ]]; then
  atomic_copy_authority "$successor_delta" "$backup/SUCCESSOR-DELTA.sha256"
  [[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" successor_delta_sha256)" == \
    "$(holdfast_sha256 "$backup/SUCCESSOR-DELTA.sha256")" && \
    "$(jq -er '.successor_delta_sha256' "$backup/RELEASE-EVIDENCE.json")" == \
    "$(holdfast_sha256 "$backup/SUCCESSOR-DELTA.sha256")" ]] || \
    holdfast_die "persisted successor delta differs from its ceremony authority"
fi
rollback_image=$(jq -er '.release.ACCESS_GOVERNANCE_ROLLBACK_IMAGE' "$backup/RELEASE-EVIDENCE.json")
rollback_tmp="$backup/.rollback.override.yml.$$"
printf 'services:\n  access-governance:\n    image: %s\n' "$rollback_image" >"$rollback_tmp"
commit_atomic_file "$rollback_tmp" "$backup/rollback.override.yml"

# Validate the immutable copies and their byte-identical canonical staged
# identity. The transaction consumes CONTROL-bound manifests from this point.
[[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" cargo_gate)" == "passed" ]] || \
  holdfast_die "persisted dry-run receipt lacks the Rust gate"
[[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" targets_sha256)" == "$(holdfast_sha256 "$backup/TARGETS.sha256")" ]] || \
  holdfast_die "persisted targets differ from the dry-run receipt"
[[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" release_evidence_sha256)" == "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" ]] || \
  holdfast_die "persisted release evidence differs from the dry-run receipt"
[[ "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" == "$(holdfast_sha256 "$stage/RELEASE-EVIDENCE.json")" ]] || \
  holdfast_die "persisted release evidence differs from the canonical staged control file"
[[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" release_env_sha256)" == "$(holdfast_sha256 "$backup/release.env")" ]] || \
  holdfast_die "persisted release env differs from the dry-run receipt"
[[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" apply_preimages_sha256)" == "$(holdfast_sha256 "$backup/APPLY-PREIMAGES.sha256")" ]] || \
  holdfast_die "persisted preimages differ from the dry-run receipt"
[[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" apply_absent_sha256)" == "$(holdfast_sha256 "$backup/APPLY-ABSENT.paths")" ]] || \
  holdfast_die "persisted absent dispositions differ from the dry-run receipt"
[[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" render_inputs_sha256)" == "$(holdfast_sha256 "$backup/RENDER-INPUTS.sha256")" ]] || \
  holdfast_die "persisted render inputs differ from the dry-run receipt"
for key in evidence signature public_key; do
  case "$key" in
    evidence) file="$backup/SUPPLY-CHAIN.json" ;;
    signature) file="$backup/SUPPLY-CHAIN.sig" ;;
    public_key) file="$backup/SUPPLY-CHAIN.pub" ;;
  esac
  [[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" "supply_chain_${key}_sha256")" == "$(holdfast_sha256 "$file")" ]] || \
    holdfast_die "persisted supply-chain artifact differs from the dry-run receipt: $key"
done
[[ "$(jq -er '.release_env_sha256' "$backup/RELEASE-EVIDENCE.json")" == "$(holdfast_sha256 "$backup/release.env")" ]] || \
  holdfast_die "persisted release evidence points to another release env"
persisted_release_validator_policy_args=()
if [[ "$successor" == "true" ]]; then
  persisted_release_validator_policy_args=(
    --successor-policy "$backup/successor-authority/successor-policy.json"
  )
fi
python3 "$script_dir/validate_release_evidence.py" \
  --evidence "$backup/RELEASE-EVIDENCE.json" \
  "${persisted_release_validator_policy_args[@]}"
persisted_dockerfile="$script_dir/../../Dockerfile.analyzer"
persisted_bridge_lock="$script_dir/../../bridge/package-lock.json"
persisted_supply_chain_policy_args=()
if [[ "$successor" == "true" ]]; then
  persisted_dockerfile="$backup/successor-authority/Dockerfile.analyzer"
  persisted_bridge_lock="$backup/successor-authority/bridge-package-lock.json"
  persisted_supply_chain_policy_args=(
    --successor-policy "$backup/successor-authority/successor-policy.json"
  )
fi
python3 "$script_dir/supply_chain_evidence.py" \
  --release-env "$backup/release.env" \
  --evidence "$backup/SUPPLY-CHAIN.json" \
  --signature "$backup/SUPPLY-CHAIN.sig" \
  --public-key "$backup/SUPPLY-CHAIN.pub" \
  --dockerfile "$persisted_dockerfile" \
  --bridge-lock "$persisted_bridge_lock" \
  --release-evidence "$backup/RELEASE-EVIDENCE.json" \
  "${persisted_supply_chain_policy_args[@]}"
python3 "$script_dir/render_input_binding.py" verify \
  --ops-root "$script_dir" --manifest "$backup/RENDER-INPUTS.sha256" \
  --stage-root "$stage" --release-evidence "$stage/RELEASE-EVIDENCE.json" \
  --expected-mode "$render_expected_mode" \
  --require-root-owner
(cd "$stage" && sha256sum --check "$backup/TARGETS.sha256")

# Persist the exact recovery intent before estate_transaction.py can replace a
# single live target.  A SIGKILL from this point forward therefore leaves a
# durable pointer to the only backup/release identity recovery may accept.
armed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
armed_receipt="$backup/APPLY-ARMED.receipt"
armed_tmp="$backup/.APPLY-ARMED.receipt.$$"
{
  printf 'schema_version=1\n'
  printf 'armed_at=%s\n' "$armed_at"
  printf 'estate_root=%s\n' "$estate_root"
  printf 'backup_dir=%s\n' "$backup"
  printf 'dry_run_dir=%s\n' "$dry_run_dir"
  printf 'release_env_sha256=%s\n' "$release_env_sha"
  printf 'release_evidence_sha256=%s\n' "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")"
  printf 'dry_run_receipt_sha256=%s\n' "$(holdfast_sha256 "$backup/DRY-RUN.receipt")"
  printf 'targets_sha256=%s\n' "$(holdfast_sha256 "$backup/TARGETS.sha256")"
  printf 'apply_preimages_sha256=%s\n' "$(holdfast_sha256 "$backup/APPLY-PREIMAGES.sha256")"
  printf 'apply_absent_sha256=%s\n' "$(holdfast_sha256 "$backup/APPLY-ABSENT.paths")"
  printf 'render_inputs_sha256=%s\n' "$(holdfast_sha256 "$backup/RENDER-INPUTS.sha256")"
  printf 'runtime_backup_receipt_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")"
  printf 'runtime_backup_manifest_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/SHA256SUMS")"
  printf 'runtime_backup_caller_armed_sha256=%s\n' "$(holdfast_sha256 "$caller_armed_receipt")"
  printf 'runtime_backup_stop_authority_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")"
  printf 'ingress_opened=false\n'
  append_successor_receipt_fields
} >"$armed_tmp"
commit_atomic_file "$armed_tmp" "$armed_receipt"

# CONTROL is complete before estate_transaction.py can create a prepared state
# or replace one live target. Transaction outputs are validated against these
# immutable target/preimage/absent authorities during recovery.
control_file="$backup/CONTROL.sha256"
control_tmp="$backup/.CONTROL.sha256.$$"
(
  cd "$backup"
  sha256sum RELEASE-EVIDENCE.json release.env DRY-RUN.receipt SUPPLY-CHAIN.json \
    SUPPLY-CHAIN.sig SUPPLY-CHAIN.pub TARGETS.sha256 APPLY-PREIMAGES.sha256 \
    APPLY-ABSENT.paths RENDER-INPUTS.sha256 rollback.override.yml APPLY-ARMED.receipt \
    RUNTIME-BACKUP-CALLER-ARMED.receipt runtime/SHA256SUMS runtime/BACKUP.receipt \
    runtime/RUNTIME-BACKUP-ARMED.receipt runtime/RUNNING-SERVICES.before
  if [[ "$successor" == "true" ]]; then
    sha256sum PREDECESSOR-CURRENT.json SUCCESSOR-ARMED.receipt SUCCESSOR-DELTA.sha256 \
      successor-authority/Dockerfile.analyzer \
      successor-authority/bridge-package-lock.json \
      successor-authority/assets/20260823_rikune_root_up.sql \
      successor-authority/assets/20260823_rikune_root_down.sql
    for relative in "${successor_generation_authorities[@]}"; do
      sha256sum "successor-authority/$relative"
    done
  fi
) >"$control_tmp"
commit_atomic_file "$control_tmp" "$control_file"
(cd "$backup" && sha256sum --check CONTROL.sha256)
control_sha=$(holdfast_sha256 "$control_file")

state_tmp="$state_dir/.CURRENT.json.$$"
jq -n \
  --arg armed_at "$armed_at" \
  --arg estate "$estate_root" \
  --arg backup "$backup" \
  --arg armed_sha "$(holdfast_sha256 "$armed_receipt")" \
  --arg release_sha "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" \
  --arg dry_sha "$(holdfast_sha256 "$backup/DRY-RUN.receipt")" \
  --arg control_sha "$control_sha" \
  --arg caller_sha "$(holdfast_sha256 "$caller_armed_receipt")" \
  --arg runtime_arm_sha "$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" \
  --arg successor_armed_sha "$successor_armed_sha" \
  --arg predecessor_current_sha "$predecessor_current_sha" \
  --arg predecessor_backup "$predecessor_backup" \
  --arg predecessor_control "$predecessor_control_sha" \
  --arg predecessor_apply "$predecessor_apply_sha" \
  --arg predecessor_release "$predecessor_release_sha" \
  --arg predecessor_runtime_receipt "$predecessor_runtime_receipt_sha" \
  --arg predecessor_runtime_manifest "$predecessor_runtime_manifest_sha" \
  --argjson successor "$successor" \
  --argjson predecessor_generation "${predecessor_generation:-0}" \
  --argjson generation "${release_generation:-0}" \
  '{schema_version:2,state:"apply_armed",apply_armed_at:$armed_at,estate_root:$estate,backup_dir:$backup,apply_armed_receipt_sha256:$armed_sha,release_evidence_sha256:$release_sha,dry_run_receipt_sha256:$dry_sha,control_sha256:$control_sha,runtime_backup_caller_armed_sha256:$caller_sha,runtime_backup_stop_authority_sha256:$runtime_arm_sha,ingress_opened:false} +
   (if $successor then {successor:true,successor_armed_receipt:"SUCCESSOR-ARMED.receipt",successor_armed_receipt_sha256:$successor_armed_sha,predecessor_current_file:"PREDECESSOR-CURRENT.json",predecessor_current_sha256:$predecessor_current_sha,predecessor_backup_dir:$predecessor_backup,predecessor_control_sha256:$predecessor_control,predecessor_apply_receipt_sha256:$predecessor_apply,predecessor_release_evidence_sha256:$predecessor_release,predecessor_runtime_backup_receipt_sha256:$predecessor_runtime_receipt,predecessor_runtime_backup_manifest_sha256:$predecessor_runtime_manifest,predecessor_release_generation:$predecessor_generation,release_generation:$generation} else {} end)' \
  >"$state_tmp"
commit_atomic_file "$state_tmp" "$state_file"
if [[ "$successor" == "true" ]]; then
  validate_persisted_successor_authority "$state_file"
  grep -Fqx "$predecessor_current_sha  PREDECESSOR-CURRENT.json" "$control_file" || \
    holdfast_die "CONTROL does not bind predecessor CURRENT"
  grep -Fqx "$successor_armed_sha  SUCCESSOR-ARMED.receipt" "$control_file" || \
    holdfast_die "CONTROL does not bind successor arm"
fi
prearm_cleanup_active="false"
trap - EXIT HUP INT TERM

# Re-check live preimages and continuous product quiescence at the final
# non-mutating boundary after durable recovery authority exists.
python3 "$script_dir/estate_transaction.py" preflight \
  --estate-root "$estate_root" \
  --stage-root "$stage" \
  --targets "$backup/TARGETS.sha256" \
  --preimages "$backup/APPLY-PREIMAGES.sha256" \
  --absent "$backup/APPLY-ABSENT.paths"
verify_products_quiesced

set +e
python3 "$script_dir/estate_transaction.py" apply \
  --estate-root "$estate_root" \
  --stage-root "$stage" \
  --targets "$backup/TARGETS.sha256" \
  --preimages "$backup/APPLY-PREIMAGES.sha256" \
  --absent "$backup/APPLY-ABSENT.paths" \
  --backup-dir "$backup/estate"
estate_status=$?
set -e
if [[ $estate_status -ne 0 ]]; then
  transaction_file="$backup/estate/TRANSACTION.json"
  transaction_sha="unsafe-or-missing"
  if [[ -f "$transaction_file" && ! -L "$transaction_file" && \
    "$(stat -c '%u:%h' -- "$transaction_file" 2>/dev/null || true)" == "0:1" ]]; then
    transaction_sha=$(holdfast_sha256 "$transaction_file")
    transaction_state=$(jq -er '.state // "missing"' "$transaction_file" 2>/dev/null || printf 'missing')
  else
    transaction_state="missing"
  fi
  prior_running_restore="not-attempted"
  if [[ "$transaction_state" == "rolled_back_after_failure" ]]; then
    set +e
    resume_prior_running_products
    resume_status=$?
    set -e
    if [[ $resume_status -eq 0 ]]; then
      prior_running_restore="passed"
      failure_state="apply_estate_rolled_back"
    else
      prior_running_restore="failed"
      failure_state="apply_estate_recovery_required"
    fi
  else
    failure_state="apply_estate_recovery_required"
  fi
  failure_stamp=$(date -u +%Y%m%dT%H%M%SZ)
  failure_receipt="$state_dir/APPLY-ESTATE-FAILED-${failure_stamp}-$$.receipt"
  failure_tmp="$state_dir/.APPLY-ESTATE-FAILED.$$"
  {
    printf 'failed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'phase=estate_apply\n'
    printf 'status=%s\n' "$estate_status"
    printf 'transaction_state=%s\n' "$transaction_state"
    printf 'transaction_sha256=%s\n' "$transaction_sha"
    printf 'backup_dir=%s\n' "$backup"
    printf 'apply_armed_receipt_sha256=%s\n' "$(holdfast_sha256 "$armed_receipt")"
    printf 'control_sha256=%s\n' "$control_sha"
    printf 'targets_sha256=%s\n' "$(holdfast_sha256 "$backup/TARGETS.sha256")"
    printf 'runtime_backup_receipt_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")"
    printf 'runtime_backup_manifest_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/SHA256SUMS")"
    printf 'prior_running_manifest_sha256=%s\n' "$(holdfast_sha256 "$prior_running_manifest")"
    printf 'prior_running_restore=%s\n' "$prior_running_restore"
  } >"$failure_tmp"
  commit_atomic_file "$failure_tmp" "$failure_receipt"
  jq \
    --arg state "$failure_state" \
    --arg receipt "$(basename -- "$failure_receipt")" \
    --arg receipt_sha "$(holdfast_sha256 "$failure_receipt")" \
    --arg transaction_state "$transaction_state" \
    --arg transaction_sha "$transaction_sha" \
    --arg prior_manifest_sha "$(holdfast_sha256 "$prior_running_manifest")" \
    --arg prior_restore "$prior_running_restore" \
    '.state=$state | .apply_failure_receipt=$receipt | .apply_failure_receipt_sha256=$receipt_sha | .estate_transaction_state=$transaction_state | .estate_transaction_sha256=$transaction_sha | .prior_running_manifest_sha256=$prior_manifest_sha | .prior_running_restore=$prior_restore' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"
  if [[ "$failure_state" == "apply_estate_rolled_back" ]]; then
    rolled_back_state="$state_dir/APPLY-ESTATE-ROLLED-BACK-${failure_stamp}-$$.json"
    if [[ "$successor" == "true" ]]; then
      archive_and_restore_predecessor_current "$rolled_back_state"
    else
      mv -- "$state_file" "$rolled_back_state"
      sync -f "$state_dir"
    fi
  fi
  holdfast_die "estate apply failed with status $estate_status; transaction state is $transaction_state"
fi

for file in "$backup/estate/APPLIED-TARGETS.sha256" "$backup/estate/PREIMAGES.sha256" \
  "$backup/estate/ABSENT.before" "$backup/estate/TRANSACTION.json"; do
  require_root_control_file "$file"
done
cmp -s -- "$backup/TARGETS.sha256" "$backup/estate/APPLIED-TARGETS.sha256" || \
  holdfast_die "applied transaction targets differ from CONTROL authority"
cmp -s -- "$backup/APPLY-PREIMAGES.sha256" "$backup/estate/PREIMAGES.sha256" || \
  holdfast_die "applied transaction preimages differ from CONTROL authority"
cmp -s -- "$backup/APPLY-ABSENT.paths" "$backup/estate/ABSENT.before" || \
  holdfast_die "applied transaction absent dispositions differ from CONTROL authority"
target_count=$(wc -l <"$backup/TARGETS.sha256" | tr -d ' ')
[[ "$(jq -er '.schema_version == 1 and .state == "applied" and .target_count == $count' \
  --argjson count "$target_count" "$backup/estate/TRANSACTION.json")" == "true" ]] || \
  holdfast_die "estate transaction did not persist the exact applied state"
transaction_sha=$(holdfast_sha256 "$backup/estate/TRANSACTION.json")
applied_targets_sha=$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")
(cd "$estate_root" && sha256sum --check "$backup/TARGETS.sha256")
docker compose --env-file "$estate_root/deploy/.env" -f "$estate_root/deploy/docker-compose.yml" config --quiet
if [[ "$activate" == "true" ]]; then
  jq \
    --arg control_sha "$control_sha" \
    '.state="apply_activation_armed" | .control_sha256=$control_sha' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"

  activation_step="compose_up"
  set +e
  docker compose --env-file "$estate_root/deploy/.env" -f "$estate_root/deploy/docker-compose.yml" \
    up -d --no-build --wait --wait-timeout 300 \
    access-governance verdict newapi rikune-analyzer strad sluice sluice-internal
  activation_status=$?
  set -e
  if [[ $activation_status -eq 0 ]]; then
    activation_step="runtime_verify"
    set +e
    "$script_dir/runtime-verify.sh" --estate-root "$estate_root" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json"
    activation_status=$?
    set -e
  fi
  if [[ $activation_status -ne 0 ]]; then
    failure_stamp=$(date -u +%Y%m%dT%H%M%SZ)
    failure_receipt="$state_dir/APPLY-ACTIVATION-FAILED-${failure_stamp}-$$.receipt"
    failure_tmp="$state_dir/.APPLY-ACTIVATION-FAILED.$$"
    {
      printf 'failed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'phase=activation\n'
      printf 'activation_step=%s\n' "$activation_step"
      printf 'status=%s\n' "$activation_status"
      printf 'estate_root=%s\n' "$estate_root"
      printf 'backup_dir=%s\n' "$backup"
      printf 'apply_armed_receipt_sha256=%s\n' "$(holdfast_sha256 "$armed_receipt")"
      printf 'control_sha256=%s\n' "$control_sha"
      printf 'transaction_sha256=%s\n' "$transaction_sha"
      printf 'ingress_opened=false\n'
    } >"$failure_tmp"
    commit_atomic_file "$failure_tmp" "$failure_receipt"
    jq \
      --arg receipt "$(basename -- "$failure_receipt")" \
      --arg receipt_sha "$(holdfast_sha256 "$failure_receipt")" \
      '.state="apply_activation_failed" | .apply_failure_receipt=$receipt | .apply_failure_receipt_sha256=$receipt_sha' \
      "$state_file" >"$state_tmp"
    commit_atomic_file "$state_tmp" "$state_file"
    holdfast_die "service activation failed at $activation_step with status $activation_status; recovery is required"
  fi
fi

# A successful file/runtime apply is not publishable authority until the route
# database and the public IPv4/IPv6 edge prove the same closed state in one
# DB -> public -> DB bracket. This check never executes route-up or route-down.
require_root_control_file "$control_file"
require_root_control_file "$backup/estate/TRANSACTION.json"
require_root_control_file "$backup/estate/APPLIED-TARGETS.sha256"
[[ "$(holdfast_sha256 "$control_file")" == "$control_sha" ]] || \
  holdfast_die "CONTROL changed after the apply was armed"
[[ "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" == "$transaction_sha" ]] || \
  holdfast_die "estate transaction changed after validation"
[[ "$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")" == "$applied_targets_sha" ]] || \
  holdfast_die "applied targets changed after validation"
(cd "$backup" && sha256sum --check CONTROL.sha256)
verify_closed_bracket
closed_verified_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

apply_receipt="$backup/APPLY.receipt"
pending_apply_receipt="$backup/APPLY-PENDING.receipt"
apply_receipt_tmp="$backup/.APPLY.receipt.$$"
[[ ! -e "$apply_receipt" && ! -L "$apply_receipt" && \
  ! -e "$pending_apply_receipt" && ! -L "$pending_apply_receipt" ]] || \
  holdfast_die "apply finalization receipt already exists"
{
  printf 'schema_version=2\n'
  printf 'completion_state=applied_ingress_closed\n'
  printf 'applied_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'closed_verified_at=%s\n' "$closed_verified_at"
  printf 'estate_root=%s\n' "$estate_root"
  printf 'backup_dir=%s\n' "$backup"
  printf 'release_env_sha256=%s\n' "$release_env_sha"
  printf 'release_evidence_sha256=%s\n' "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")"
  printf 'render_inputs_sha256=%s\n' "$(holdfast_sha256 "$backup/RENDER-INPUTS.sha256")"
  printf 'apply_armed_receipt_sha256=%s\n' "$(holdfast_sha256 "$armed_receipt")"
  printf 'control_sha256=%s\n' "$control_sha"
  printf 'transaction_sha256=%s\n' "$transaction_sha"
  printf 'applied_targets_sha256=%s\n' "$applied_targets_sha"
  printf 'cargo_gate=passed\n'
  printf 'runtime_backup=passed\n'
  printf 'closed_bracket=passed\n'
  printf 'route_database_state=absent\n'
  printf 'public_ipv4_ipv6_closed_status=404\n'
  printf 'ingress_opened=false\n'
  printf 'services_activated=%s\n' "$activate"
  printf 'runtime_verified=%s\n' "$activate"
  append_successor_receipt_fields
} >"$apply_receipt_tmp"
commit_atomic_file "$apply_receipt_tmp" "$pending_apply_receipt"
pending_apply_sha=$(holdfast_sha256 "$pending_apply_receipt")

# This durable intermediate state makes both finalization boundaries
# recoverable: recovery can distinguish a missing APPLY.receipt from the exact
# receipt installed immediately after this state, then re-run the closed
# bracket before completing finalization.
jq -n \
  --arg estate "$estate_root" \
  --arg backup "$backup" \
  --arg pending_apply_sha "$pending_apply_sha" \
  --arg release_sha "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" \
  --arg armed_sha "$(holdfast_sha256 "$armed_receipt")" \
  --arg control_sha "$control_sha" \
  --arg transaction_sha "$transaction_sha" \
  --arg applied_targets_sha "$applied_targets_sha" \
  --arg closed_at "$closed_verified_at" \
  --arg successor_armed_sha "$successor_armed_sha" \
  --arg predecessor_current_sha "$predecessor_current_sha" \
  --arg predecessor_backup "$predecessor_backup" \
  --arg predecessor_control "$predecessor_control_sha" \
  --arg predecessor_apply "$predecessor_apply_sha" \
  --arg predecessor_release "$predecessor_release_sha" \
  --arg predecessor_runtime_receipt "$predecessor_runtime_receipt_sha" \
  --arg predecessor_runtime_manifest "$predecessor_runtime_manifest_sha" \
  --arg runtime_receipt_sha "$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")" \
  --arg runtime_manifest_sha "$(holdfast_sha256 "$backup/runtime/SHA256SUMS")" \
  --argjson successor "$successor" \
  --argjson predecessor_generation "${predecessor_generation:-0}" \
  --argjson generation "${release_generation:-0}" \
  --argjson activated "$activate" \
  '{schema_version:2,state:"apply_finalizing_ingress_closed",estate_root:$estate,backup_dir:$backup,pending_apply_receipt:"APPLY-PENDING.receipt",pending_apply_receipt_sha256:$pending_apply_sha,apply_armed_receipt_sha256:$armed_sha,control_sha256:$control_sha,release_evidence_sha256:$release_sha,transaction_sha256:$transaction_sha,applied_targets_sha256:$applied_targets_sha,closed_verified_at:$closed_at,route_database_state:"absent",public_ipv4_ipv6_closed_status:404,services_activated:$activated,runtime_verified:$activated,ingress_opened:false} +
   (if $successor then {successor:true,successor_armed_receipt:"SUCCESSOR-ARMED.receipt",successor_armed_receipt_sha256:$successor_armed_sha,predecessor_current_file:"PREDECESSOR-CURRENT.json",predecessor_current_sha256:$predecessor_current_sha,predecessor_backup_dir:$predecessor_backup,predecessor_control_sha256:$predecessor_control,predecessor_apply_receipt_sha256:$predecessor_apply,predecessor_release_evidence_sha256:$predecessor_release,predecessor_runtime_backup_receipt_sha256:$predecessor_runtime_receipt,predecessor_runtime_backup_manifest_sha256:$predecessor_runtime_manifest,predecessor_release_generation:$predecessor_generation,release_generation:$generation,runtime_backup_receipt_sha256:$runtime_receipt_sha,runtime_backup_manifest_sha256:$runtime_manifest_sha} else {} end)' \
  >"$state_tmp"
commit_atomic_file "$state_tmp" "$state_file"
[[ ! -e "$apply_receipt" && ! -L "$apply_receipt" ]] || \
  holdfast_die "final APPLY.receipt appeared during finalization"
commit_atomic_file "$pending_apply_receipt" "$apply_receipt"
[[ ! -e "$pending_apply_receipt" && ! -L "$pending_apply_receipt" ]] || \
  holdfast_die "pending apply receipt remains after finalization"
[[ "$(holdfast_sha256 "$apply_receipt")" == "$pending_apply_sha" ]] || \
  holdfast_die "final APPLY.receipt differs from the pending authority"
jq -n \
  --arg estate "$estate_root" \
  --arg backup "$backup" \
  --arg apply_sha "$(holdfast_sha256 "$apply_receipt")" \
  --arg release_sha "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" \
  --arg armed_sha "$(holdfast_sha256 "$armed_receipt")" \
  --arg control_sha "$control_sha" \
  --arg transaction_sha "$transaction_sha" \
  --arg applied_targets_sha "$applied_targets_sha" \
  --arg closed_at "$closed_verified_at" \
  --arg successor_armed_sha "$successor_armed_sha" \
  --arg predecessor_current_sha "$predecessor_current_sha" \
  --arg predecessor_backup "$predecessor_backup" \
  --arg predecessor_control "$predecessor_control_sha" \
  --arg predecessor_apply "$predecessor_apply_sha" \
  --arg predecessor_release "$predecessor_release_sha" \
  --arg predecessor_runtime_receipt "$predecessor_runtime_receipt_sha" \
  --arg predecessor_runtime_manifest "$predecessor_runtime_manifest_sha" \
  --arg runtime_receipt_sha "$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")" \
  --arg runtime_manifest_sha "$(holdfast_sha256 "$backup/runtime/SHA256SUMS")" \
  --argjson successor "$successor" \
  --argjson predecessor_generation "${predecessor_generation:-0}" \
  --argjson generation "${release_generation:-0}" \
  --argjson activated "$activate" \
  '{schema_version:2,state:"applied_ingress_closed",estate_root:$estate,backup_dir:$backup,apply_receipt_sha256:$apply_sha,apply_armed_receipt_sha256:$armed_sha,control_sha256:$control_sha,release_evidence_sha256:$release_sha,transaction_sha256:$transaction_sha,applied_targets_sha256:$applied_targets_sha,closed_verified_at:$closed_at,route_database_state:"absent",public_ipv4_ipv6_closed_status:404,services_activated:$activated,runtime_verified:$activated,ingress_opened:false} +
   (if $successor then {successor:true,successor_armed_receipt:"SUCCESSOR-ARMED.receipt",successor_armed_receipt_sha256:$successor_armed_sha,predecessor_current_file:"PREDECESSOR-CURRENT.json",predecessor_current_sha256:$predecessor_current_sha,predecessor_backup_dir:$predecessor_backup,predecessor_control_sha256:$predecessor_control,predecessor_apply_receipt_sha256:$predecessor_apply,predecessor_release_evidence_sha256:$predecessor_release,predecessor_runtime_backup_receipt_sha256:$predecessor_runtime_receipt,predecessor_runtime_backup_manifest_sha256:$predecessor_runtime_manifest,predecessor_release_generation:$predecessor_generation,release_generation:$generation,runtime_backup_receipt_sha256:$runtime_receipt_sha,runtime_backup_manifest_sha256:$runtime_manifest_sha} else {} end)' \
  >"$state_tmp"
commit_atomic_file "$state_tmp" "$state_dir/CURRENT.json"
echo "estate transaction applied with runtime backup; ingress remains closed"
echo "rollback backup: $backup"
