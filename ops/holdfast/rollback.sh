#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --execute --phase close-route|execute --estate-root PATH --backup-dir PATH --open-evidence FILE --open-signature FILE --authority-public-key FILE [--revocation-evidence FILE --revocation-signature FILE --edge-rollback-evidence FILE --edge-rollback-signature FILE --open-edge-evidence FILE] [--state-dir PATH] [--activate-services]" >&2
  exit 2
}

execute="false"
phase=""
activate="false"
estate_root=""
backup=""
open_evidence=""
open_signature=""
authority_public_key=""
revocation_evidence=""
revocation_signature=""
edge_rollback_evidence=""
edge_rollback_signature=""
open_edge_evidence=""
state_dir="/var/lib/holdfast-rikune"
while (($#)); do
  case "$1" in
    --execute) execute="true"; shift ;;
    --phase) [[ $# -ge 2 ]] || usage; phase=$2; shift 2 ;;
    --activate-services) activate="true"; shift ;;
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --backup-dir) [[ $# -ge 2 ]] || usage; backup=$2; shift 2 ;;
    --open-evidence) [[ $# -ge 2 ]] || usage; open_evidence=$2; shift 2 ;;
    --open-signature) [[ $# -ge 2 ]] || usage; open_signature=$2; shift 2 ;;
    --authority-public-key) [[ $# -ge 2 ]] || usage; authority_public_key=$2; shift 2 ;;
    --revocation-evidence) [[ $# -ge 2 ]] || usage; revocation_evidence=$2; shift 2 ;;
    --revocation-signature) [[ $# -ge 2 ]] || usage; revocation_signature=$2; shift 2 ;;
    --edge-rollback-evidence) [[ $# -ge 2 ]] || usage; edge_rollback_evidence=$2; shift 2 ;;
    --edge-rollback-signature) [[ $# -ge 2 ]] || usage; edge_rollback_signature=$2; shift 2 ;;
    --open-edge-evidence) [[ $# -ge 2 ]] || usage; open_edge_evidence=$2; shift 2 ;;
    --state-dir) [[ $# -ge 2 ]] || usage; state_dir=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$execute" == "true" && ( "$phase" == "close-route" || "$phase" == "execute" ) ]] || usage
[[ -n "$estate_root" && -n "$backup" && -n "$open_evidence" && -n "$open_signature" && -n "$authority_public_key" ]] || usage
if [[ "$phase" == "execute" ]]; then
  [[ -n "$revocation_evidence" && -n "$revocation_signature" ]] || usage
fi
[[ $EUID -eq 0 ]] || { echo "rollback requires root" >&2; exit 1; }
[[ -n "${ROUTES_DATABASE_URL:-}" ]] || { echo "ROUTES_DATABASE_URL is required" >&2; exit 1; }
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
# shellcheck disable=SC1091
source "$script_dir/common.sh"
for path in "$estate_root" "$backup" "$open_evidence" "$open_signature" "$authority_public_key" "$state_dir"; do
  holdfast_require_absolute "$path"
done
holdfast_acquire_lock

test_override() {
  local variable=$1 fallback=$2
  local value=${!variable:-}
  if [[ -n "$value" ]]; then
    [[ "${HOLDFAST_TEST_MODE:-0}" == "1" ]] || holdfast_die "$variable override is test-only"
    printf '%s\n' "$value"
  else
    printf '%s\n' "$fallback"
  fi
}

run_python_tool() {
  local tool=$1 default=$2
  shift 2
  if [[ "$tool" == "$default" ]]; then
    python3 "$tool" "$@"
  else
    "$tool" "$@"
  fi
}

require_canonical_root_dir() {
  local path=$1
  [[ -d "$path" && ! -L "$path" && "$(readlink -f -- "$path")" == "$path" ]] || \
    holdfast_die "directory must be canonical and non-symlink: $path"
  [[ "$(stat -c '%u' -- "$path")" == "0" ]] || holdfast_die "directory must be root-owned: $path"
}

require_root_file() {
  local path=$1
  [[ -f "$path" && ! -L "$path" ]] || holdfast_die "required file is unsafe or absent: $path"
  [[ "$(stat -c '%u:%h' -- "$path")" == "0:1" ]] || \
    holdfast_die "required file must be root-owned with one link: $path"
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
  require_root_file "$source"
  [[ ! -e "$target" && ! -L "$target" ]] || holdfast_die "frozen rollback authority already exists: $target"
  temporary="$state_dir/.frozen-$(basename -- "$target").$$"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] || holdfast_die "frozen rollback temporary path exists"
  install -o 0 -g 0 -m 0600 -- "$source" "$temporary"
  commit_atomic_file "$temporary" "$target"
  [[ "$(holdfast_sha256 "$source")" == "$(holdfast_sha256 "$target")" ]] || \
    holdfast_die "frozen rollback authority differs from its source"
}

validate_successor_completion_namespace() {
  local authority_dir=$1 policy schema relative count
  local -a completion_names=(
    RECOVERY-COMPLETION-ATTESTATION.json
    RECOVERY-COMPLETION-ATTESTATION.sig
    RECOVERY-COMPLETION-ATTESTATION.pub
  )
  policy="$authority_dir/successor-policy.json"
  require_root_file "$policy"
  schema=$(jq -er \
    '.schema_version | select(type == "number" and floor == .)' "$policy") || \
    holdfast_die "successor policy schema is invalid"
  case "$schema" in
    1|2)
      for relative in "${completion_names[@]}"; do
        [[ ! -e "$backup/$relative" && ! -L "$backup/$relative" ]] || \
          holdfast_die "legacy successor backup contains recovery completion authority: $relative"
      done
      count=$(grep -Ec \
        '[[:space:]][[:space:]]RECOVERY-COMPLETION-ATTESTATION\.(json|sig|pub)$' \
        "$backup/CONTROL.sha256" || true)
      [[ "$count" == "0" ]] || \
        holdfast_die "legacy successor CONTROL contains recovery completion authority"
      ;;
    3)
      for relative in "${completion_names[@]}"; do
        require_root_file "$backup/$relative"
        count=$(grep -Fxc \
          "$(holdfast_sha256 "$backup/$relative")  $relative" \
          "$backup/CONTROL.sha256" || true)
        [[ "$count" == "1" ]] || \
          holdfast_die "schema-v3 successor CONTROL does not exactly bind $relative"
      done
      count=$(grep -Ec \
        '[[:space:]][[:space:]]RECOVERY-COMPLETION-ATTESTATION\.(json|sig|pub)$' \
        "$backup/CONTROL.sha256" || true)
      [[ "$count" == "3" ]] || \
        holdfast_die "schema-v3 successor CONTROL recovery completion set is not exact"
      ;;
    4)
      for relative in "${completion_names[@]}"; do
        [[ ! -e "$backup/$relative" && ! -L "$backup/$relative" ]] || \
          holdfast_die "schema-v4 successor backup contains predecessor completion authority: $relative"
      done
      count=$(grep -Ec \
        '[[:space:]][[:space:]]RECOVERY-COMPLETION-ATTESTATION\.(json|sig|pub)$' \
        "$backup/CONTROL.sha256" || true)
      [[ "$count" == "0" ]] || \
        holdfast_die "schema-v4 successor CONTROL contains predecessor completion authority"
      ;;
    5)
      load_v5_recovery_completion_authority "$policy"
      for relative in "${completion_names[@]}"; do
        [[ ! -e "$backup/$relative" && ! -L "$backup/$relative" ]] || \
          holdfast_die "schema-v5 successor backup contains signed completion authority: $relative"
      done
      count=$(grep -Ec \
        '[[:space:]][[:space:]]RECOVERY-COMPLETION-ATTESTATION\.(json|sig|pub)$' \
        "$backup/CONTROL.sha256" || true)
      [[ "$count" == "0" ]] || \
        holdfast_die "schema-v5 successor CONTROL contains signed completion authority"
      while IFS=$'\t' read -r relative expected; do
        require_root_file "$backup/$relative"
        [[ "$(holdfast_sha256 "$backup/$relative")" == "$expected" ]] || \
          holdfast_die "schema-v5 recovery completion artifact differs: $relative"
        count=$(grep -Fxc "$expected  $relative" "$backup/CONTROL.sha256" || true)
        [[ "$count" == "1" ]] || \
          holdfast_die "schema-v5 successor CONTROL does not exactly bind $relative"
      done <<EOF
$predecessor_recovery_completion_archive	$predecessor_recovery_completion_archive_sha
$predecessor_recovery_completion_receipt	$predecessor_recovery_completion_receipt_sha
$predecessor_recovery_completion_armed_receipt	$predecessor_recovery_completion_armed_receipt_sha
$predecessor_recovery_completion_failure_receipt	$predecessor_recovery_completion_failure_receipt_sha
EOF
      ;;
    *) holdfast_die "successor policy schema is unsupported" ;;
  esac
}

validate_successor_authority_namespace() {
  local authority_dir=$1 entry name
  require_canonical_root_dir "$authority_dir"
  require_canonical_root_dir "$authority_dir/assets"
  while IFS= read -r -d '' entry; do
    name=$(basename -- "$entry")
    if [[ "$name" == "assets" ]]; then
      require_canonical_root_dir "$entry"
    else
      require_root_file "$entry"
    fi
  done < <(find "$authority_dir" -mindepth 1 -maxdepth 1 -print0)
  [[ "$(find "$authority_dir" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == "9" && \
    "$(find "$authority_dir" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "8" ]] || \
    holdfast_die "successor authority directory entry set is not exact"
  while IFS= read -r -d '' entry; do require_root_file "$entry"; done \
    < <(find "$authority_dir/assets" -mindepth 1 -maxdepth 1 -print0)
  [[ "$(find "$authority_dir/assets" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == "2" && \
    "$(find "$authority_dir/assets" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "2" ]] || \
    holdfast_die "successor route authority entry set is not exact"
}

derive_backup_successor_mode() {
  local line relative schema release_mode digest authority_dir authority_count=0
  local -A expected_authorities=()
  require_root_file "$backup/CONTROL.sha256"
  require_root_file "$backup/RELEASE-EVIDENCE.json"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]([A-Za-z0-9._/-]+)$ ]] || \
      holdfast_die "CONTROL contains an invalid checksum line"
    relative=${BASH_REMATCH[1]}
    [[ "$relative" != /* && "$relative" != ".." && "$relative" != *"../"* ]] || \
      holdfast_die "CONTROL contains an unsafe path"
  done <"$backup/CONTROL.sha256"
  (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
  grep -Fqx "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")  RELEASE-EVIDENCE.json" \
    "$backup/CONTROL.sha256" || holdfast_die "CONTROL omits RELEASE-EVIDENCE"
  schema=$(jq -er '.schema_version' "$backup/RELEASE-EVIDENCE.json")
  release_mode=$(jq -er '.release_mode // "base"' "$backup/RELEASE-EVIDENCE.json")
  if [[ "$schema" == "1" && "$release_mode" == "base" ]]; then
    for relative in PREDECESSOR-CURRENT.json SUCCESSOR-ARMED.receipt \
      SUCCESSOR-DELTA.sha256 successor-authority; do
      [[ ! -e "$backup/$relative" && ! -L "$backup/$relative" ]] || \
        holdfast_die "base backup contains mixed successor authority: $relative"
    done
    grep -Eq '[[:space:]][[:space:]](PREDECESSOR-CURRENT.json|SUCCESSOR-ARMED.receipt|SUCCESSOR-DELTA.sha256|successor-authority/)' \
      "$backup/CONTROL.sha256" && holdfast_die "base CONTROL contains successor authority"
    printf 'false\n'
    return
  fi
  [[ "$schema" == "2" && "$release_mode" == "successor" ]] || \
    holdfast_die "backup release mode is unsupported or mixed"
  for relative in PREDECESSOR-CURRENT.json SUCCESSOR-ARMED.receipt \
    SUCCESSOR-DELTA.sha256 RENDER-INPUTS.sha256; do
    require_root_file "$backup/$relative"
    grep -Fqx "$(holdfast_sha256 "$backup/$relative")  $relative" \
      "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits $relative"
  done
  authority_dir="$backup/successor-authority"
  require_canonical_root_dir "$authority_dir"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]] || \
      holdfast_die "successor render-input authority contains an invalid line"
    digest=${BASH_REMATCH[1]}
    relative=${BASH_REMATCH[2]}
    [[ -z "${expected_authorities[$relative]+x}" ]] || \
      holdfast_die "successor render-input authority repeats a path"
    expected_authorities[$relative]=1
    require_root_file "$authority_dir/$relative"
    [[ "$(holdfast_sha256 "$authority_dir/$relative")" == "$digest" ]] || \
      holdfast_die "successor generation authority differs: $relative"
    grep -Fqx "$digest  successor-authority/$relative" "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits generation authority: $relative"
    authority_count=$((authority_count + 1))
  done <"$backup/RENDER-INPUTS.sha256"
  ((authority_count == 6)) || holdfast_die "successor generation authority set is not exact"
  for relative in Dockerfile.analyzer bridge-package-lock.json; do
    expected_authorities[$relative]=1
    require_root_file "$authority_dir/$relative"
    grep -Fqx "$(holdfast_sha256 "$authority_dir/$relative")  successor-authority/$relative" \
      "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits generation authority: $relative"
  done
  require_canonical_root_dir "$authority_dir/assets"
  for relative in 20260823_rikune_root_up.sql 20260823_rikune_root_down.sql; do
    require_root_file "$authority_dir/assets/$relative"
    grep -Fqx "$(holdfast_sha256 "$authority_dir/assets/$relative")  successor-authority/assets/$relative" \
      "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits route authority: $relative"
  done
  while IFS= read -r relative; do
    [[ -n "${expected_authorities[$relative]+x}" ]] || \
      holdfast_die "successor authority directory contains an unbound generation file: $relative"
  done < <(find "$authority_dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)
  validate_successor_authority_namespace "$authority_dir"
  validate_successor_completion_namespace "$authority_dir"
  printf 'true\n'
}

successor_rollback="false"
backup_expected_successor=""
backup_successor_policy_version=""
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
successor_policy_version=""
predecessor_completion_kind=""
predecessor_completion_attestation_sha=""
predecessor_completion_signature_sha=""
predecessor_completion_public_key_sha=""
predecessor_recovery_completion_kind=""
predecessor_recovery_completion_archive=""
predecessor_recovery_completion_archive_sha=""
predecessor_recovery_completion_receipt=""
predecessor_recovery_completion_receipt_sha=""
predecessor_recovery_completion_armed_receipt=""
predecessor_recovery_completion_armed_receipt_sha=""
predecessor_recovery_completion_failure_receipt=""
predecessor_recovery_completion_failure_receipt_sha=""
predecessor_recovery_completion_json='{}'
state_dir_identity=""

validate_v3_state_dir_identity() {
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  require_canonical_root_dir "$state_dir"
  [[ -n "$state_dir_identity" && \
    "$(stat -c '%d:%i:%u:%f' -- "$state_dir")" == "$state_dir_identity" ]] || \
    holdfast_die "schema-v3 rollback state directory changed during external validation"
}

validate_v3_completion_receipt_namespace() {
  local receipt=$1 observed
  observed=$(awk -F= '
    $1 ~ /^predecessor_completion_/ { print $1 }
  ' "$receipt" | sort)
  [[ "$observed" == $'predecessor_completion_attestation_sha256\npredecessor_completion_kind\npredecessor_completion_public_key_sha256\npredecessor_completion_signature_sha256' ]] || \
    holdfast_die "schema-v3 successor rollback completion receipt namespace differs"
}

validate_no_predecessor_completion_namespace() {
  local artifact=$1
  require_root_file "$artifact"
  ! grep -Eq 'predecessor_completion_[A-Za-z0-9_]+' "$artifact" || \
    holdfast_die "schema-v4 artifact contains predecessor completion authority: $artifact"
}

load_v5_recovery_completion_authority() {
  local policy=$1 values value
  values=$(jq -er '
    .predecessor.recovery_completion |
    select(keys == ["archive","archive_sha256","armed_receipt","armed_receipt_sha256","failure_receipt","failure_receipt_sha256","kind","receipt","receipt_sha256"]) |
    [.kind,.archive,.archive_sha256,.receipt,.receipt_sha256,
     .armed_receipt,.armed_receipt_sha256,.failure_receipt,
     .failure_receipt_sha256] | @tsv
  ' "$policy") || holdfast_die "schema-v5 policy lacks exact recovery completion authority"
  IFS=$'\t' read -r predecessor_recovery_completion_kind \
    predecessor_recovery_completion_archive \
    predecessor_recovery_completion_archive_sha \
    predecessor_recovery_completion_receipt \
    predecessor_recovery_completion_receipt_sha \
    predecessor_recovery_completion_armed_receipt \
    predecessor_recovery_completion_armed_receipt_sha \
    predecessor_recovery_completion_failure_receipt \
    predecessor_recovery_completion_failure_receipt_sha <<<"$values"
  [[ "$predecessor_recovery_completion_kind" == \
    "holdfast-rikune-recovery-resume-completion-v1" ]] || \
    holdfast_die "schema-v5 recovery completion kind differs"
  for value in "$predecessor_recovery_completion_archive" \
    "$predecessor_recovery_completion_receipt" \
    "$predecessor_recovery_completion_armed_receipt" \
    "$predecessor_recovery_completion_failure_receipt"; do
    [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]] || \
      holdfast_die "schema-v5 recovery completion filename is unsafe"
  done
  for value in "$predecessor_recovery_completion_archive_sha" \
    "$predecessor_recovery_completion_receipt_sha" \
    "$predecessor_recovery_completion_armed_receipt_sha" \
    "$predecessor_recovery_completion_failure_receipt_sha"; do
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || \
      holdfast_die "schema-v5 recovery completion digest is invalid"
  done
  predecessor_recovery_completion_json=$(jq -cn \
    --arg kind "$predecessor_recovery_completion_kind" \
    --arg archive "$predecessor_recovery_completion_archive" \
    --arg archive_sha "$predecessor_recovery_completion_archive_sha" \
    --arg receipt "$predecessor_recovery_completion_receipt" \
    --arg receipt_sha "$predecessor_recovery_completion_receipt_sha" \
    --arg armed "$predecessor_recovery_completion_armed_receipt" \
    --arg armed_sha "$predecessor_recovery_completion_armed_receipt_sha" \
    --arg failure "$predecessor_recovery_completion_failure_receipt" \
    --arg failure_sha "$predecessor_recovery_completion_failure_receipt_sha" '
    {
      predecessor_recovery_completion_kind:$kind,
      predecessor_recovery_completion_archive:$archive,
      predecessor_recovery_completion_archive_sha256:$archive_sha,
      predecessor_recovery_completion_receipt:$receipt,
      predecessor_recovery_completion_receipt_sha256:$receipt_sha,
      predecessor_recovery_completion_armed_receipt:$armed,
      predecessor_recovery_completion_armed_receipt_sha256:$armed_sha,
      predecessor_recovery_completion_failure_receipt:$failure,
      predecessor_recovery_completion_failure_receipt_sha256:$failure_sha
    }
  ')
}

append_v5_recovery_completion_lineage() {
  [[ "$successor_rollback" == "true" && "$successor_policy_version" == "5" ]] || return 0
  jq -r 'to_entries[] | "\(.key)=\(.value)"' \
    <<<"$predecessor_recovery_completion_json"
}

validate_v5_recovery_completion_lineage() {
  local artifact=$1 observed expected key value
  require_root_file "$artifact"
  observed=$(awk -F= '
    $1 ~ /^predecessor_recovery_completion_/ { print $1 }
  ' "$artifact" | sort)
  expected=$(jq -r 'keys[]' <<<"$predecessor_recovery_completion_json" | sort)
  [[ "$observed" == "$expected" ]] || \
    holdfast_die "schema-v5 recovery completion namespace differs: $artifact"
  while IFS= read -r expected; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$artifact" "$key")" == "$value" ]] || \
      holdfast_die "schema-v5 recovery completion lineage differs: $key"
  done < <(append_v5_recovery_completion_lineage)
  ! grep -Eq '^predecessor_apply_receipt_sha256=' "$artifact" || \
    holdfast_die "schema-v5 lineage contains ordinary APPLY authority"
  ! grep -Eq '^predecessor_completion_' "$artifact" || \
    holdfast_die "schema-v5 lineage contains signed completion authority"
}

validate_v5_recovery_completion_artifacts() {
  local root=$1 relative expected
  while IFS=$'\t' read -r relative expected; do
    require_root_file "$root/$relative"
    [[ "$(holdfast_sha256 "$root/$relative")" == "$expected" ]] || \
      holdfast_die "schema-v5 recovery completion artifact differs: $relative"
  done <<EOF
$predecessor_recovery_completion_archive	$predecessor_recovery_completion_archive_sha
$predecessor_recovery_completion_receipt	$predecessor_recovery_completion_receipt_sha
$predecessor_recovery_completion_armed_receipt	$predecessor_recovery_completion_armed_receipt_sha
$predecessor_recovery_completion_failure_receipt	$predecessor_recovery_completion_failure_receipt_sha
EOF
}

validate_exact_receipt_keys() {
  local receipt=$1 label=$2 index=0 key
  local -a actual=()
  shift 2
  require_root_file "$receipt"
  mapfile -t actual < <(cut -d= -f1 -- "$receipt")
  ((${#actual[@]} == $#)) || holdfast_die "$label field set is not exact"
  for key in "$@"; do
    [[ "${actual[$index]}" == "$key" ]] || holdfast_die "$label field set is not exact"
    index=$((index + 1))
  done
}

validate_exact_json_keys() {
  local document=$1 label=$2 key
  local -a actual=()
  local -A expected_keys=()
  shift 2
  require_root_file "$document"
  for key in "$@"; do expected_keys[$key]=1; done
  mapfile -t actual < <(jq -r 'keys_unsorted[]' "$document")
  ((${#actual[@]} == ${#expected_keys[@]})) || holdfast_die "$label field set is not exact"
  for key in "${actual[@]}"; do
    [[ -n "${expected_keys[$key]+x}" ]] || holdfast_die "$label field set is not exact"
  done
}

validate_recovered_successor_authority() {
  local pointer=$1 authority_dir="$backup/successor-authority"
  local policy="$authority_dir/successor-policy.json"
  local attestation="$backup/RECOVERY-COMPLETION-ATTESTATION.json"
  local signature="$backup/RECOVERY-COMPLETION-ATTESTATION.sig"
  local public_key="$backup/RECOVERY-COMPLETION-ATTESTATION.pub"
  local attestation_sha signature_sha public_key_sha observed expected key value
  local successor_delta_sha

  require_root_file "$policy"
  for observed in "$attestation" "$signature" "$public_key"; do
    require_root_file "$observed"
    [[ "$(stat -c '%a' -- "$observed")" == "600" ]] || \
      holdfast_die "schema-v3 recovery completion artifact must have mode 0600"
  done
  jq -e '
    keys == ["ceremony","overlay","predecessor","schema_version","successor"] and
    .schema_version == 3 and .ceremony == "holdfast-rikune-successor-v3" and
    (.predecessor | keys) == [
      "access_build_input_schema","access_build_input_sha256","access_image",
      "candidate_evidence_sha256","candidate_targets_sha256","completion",
      "control_sha256","current_state_sha256","package_catalog_sha256",
      "permission_catalog_sha256","release_evidence_sha256","runtime_manifest_sha256"
    ] and
    (.predecessor.completion | keys) == [
      "attestation_sha256","kind","public_key_sha256","signature_sha256"
    ] and
    .predecessor.completion.kind == "recovery-completion-attestation-v1" and
    (.predecessor | has("apply_receipt_sha256") | not)' \
    "$policy" >/dev/null || \
    holdfast_die "schema-v3 successor policy recovery completion binding differs"

  predecessor_completion_kind=$(jq -er '.predecessor.completion.kind' "$policy")
  predecessor_completion_attestation_sha=$(jq -er \
    '.predecessor.completion.attestation_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$policy") || holdfast_die "schema-v3 attestation digest is invalid"
  predecessor_completion_signature_sha=$(jq -er \
    '.predecessor.completion.signature_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$policy") || holdfast_die "schema-v3 signature digest is invalid"
  predecessor_completion_public_key_sha=$(jq -er \
    '.predecessor.completion.public_key_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$policy") || holdfast_die "schema-v3 public-key digest is invalid"
  attestation_sha=$(holdfast_sha256 "$attestation")
  signature_sha=$(holdfast_sha256 "$signature")
  public_key_sha=$(holdfast_sha256 "$public_key")
  [[ "$attestation_sha" == "$predecessor_completion_attestation_sha" && \
    "$signature_sha" == "$predecessor_completion_signature_sha" && \
    "$public_key_sha" == "$predecessor_completion_public_key_sha" ]] || \
    holdfast_die "schema-v3 recovery completion artifact differs from policy"
  run_python_tool "$completion_attestation_tool" \
    "$script_dir/recovery_completion_attestation.py" verify \
    --attestation "$attestation" --signature "$signature" \
    --public-key "$public_key" \
    --public-key-sha256 "$predecessor_completion_public_key_sha" >/dev/null

  predecessor_control_sha=$(jq -er '.predecessor.control_sha256' "$policy")
  predecessor_release_sha=$(jq -er '.predecessor.release_evidence_sha256' "$policy")
  predecessor_runtime_manifest_sha=$(jq -er '.predecessor.runtime_manifest_sha256' "$policy")
  predecessor_backup=$(jq -er '.backup_dir | select(type == "string")' \
    "$predecessor_current_file") || \
    holdfast_die "schema-v3 predecessor CURRENT backup identity is invalid"
  holdfast_require_absolute "$predecessor_backup"
  predecessor_runtime_receipt_sha=$(jq -er \
    '.runtime_receipt_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$attestation") || holdfast_die "schema-v3 predecessor runtime receipt digest is invalid"
  predecessor_generation=$(jq -er '.release_generation' "$attestation")
  release_generation=$(holdfast_receipt_value "$successor_armed_receipt" release_generation)
  predecessor_apply_sha=""

  jq -e \
    --arg estate "$estate_root" --arg predecessor_backup "$predecessor_backup" \
    --arg current "$predecessor_current_sha" --arg control "$predecessor_control_sha" \
    --arg release "$predecessor_release_sha" \
    --arg runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg runtime_manifest "$predecessor_runtime_manifest_sha" '
    .schema_version == 1 and .kind == "recovery-completion-attestation-v1" and
    .mode == "resume" and .successor == true and .recovery_schema_version == 2 and
    .estate_root == $estate and .backup_dir == $predecessor_backup and
    .current_file == "CURRENT.json" and .current_sha256 == $current and
    .control_file == "CONTROL.sha256" and .control_sha256 == $control and
    .release_evidence_file == "RELEASE-EVIDENCE.json" and
    .release_evidence_sha256 == $release and
    .runtime_receipt_file == "runtime/BACKUP.receipt" and
    .runtime_receipt_sha256 == $runtime_receipt and
    .runtime_manifest_file == "runtime/SHA256SUMS" and
    .runtime_manifest_sha256 == $runtime_manifest and
    .predecessor_release_generation == 2 and .release_generation == 3 and
    .services_activated == true and .runtime_verified == true and
    .route_database_state == "absent" and .public_ipv4_ipv6_closed_status == 404 and
    .db_public_db_bracket == "absent-404-absent" and .ingress_opened == false and
    .apply_receipt_created == false' "$attestation" >/dev/null || \
    holdfast_die "schema-v3 recovery completion attestation lineage differs"
  jq -e \
    --arg estate "$estate_root" --arg backup "$predecessor_backup" \
    --arg control "$predecessor_control_sha" --arg release "$predecessor_release_sha" \
    --arg runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg runtime_manifest "$predecessor_runtime_manifest_sha" '
    .schema_version == 2 and .state == "applied_ingress_closed" and
    .estate_root == $estate and .backup_dir == $backup and
    .control_sha256 == $control and .release_evidence_sha256 == $release and
    ((has("runtime_backup_receipt_sha256") | not) or
      .runtime_backup_receipt_sha256 == $runtime_receipt) and
    ((has("runtime_backup_manifest_sha256") | not) or
      .runtime_backup_manifest_sha256 == $runtime_manifest) and
    (has("apply_receipt_sha256") | not) and
    (has("route_database_state") | not) and
    (has("public_ipv4_ipv6_closed_status") | not) and
    .services_activated == true and .runtime_verified == true and
    .ingress_opened == false and .successor == true and
    .predecessor_release_generation == 2 and .release_generation == 3' \
    "$predecessor_current_file" >/dev/null || \
    holdfast_die "schema-v3 recovered predecessor CURRENT differs"
  [[ "$predecessor_generation" == "3" && "$release_generation" == "4" ]] || \
    holdfast_die "schema-v3 successor rollback generation linkage is invalid"

  for expected in \
    "schema_version=1" "successor_backup_dir=$backup" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "successor_policy_sha256=$(holdfast_sha256 "$policy")" \
    "predecessor_completion_kind=$predecessor_completion_kind" \
    "predecessor_completion_attestation_sha256=$predecessor_completion_attestation_sha" \
    "predecessor_completion_signature_sha256=$predecessor_completion_signature_sha" \
    "predecessor_completion_public_key_sha256=$predecessor_completion_public_key_sha" \
    "predecessor_release_evidence_sha256=$predecessor_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_manifest_sha" \
    "predecessor_release_generation=$predecessor_generation" \
    "release_generation=$release_generation" "route_database_state=absent" \
    "public_ipv4_ipv6_closed_status=404" "predecessor_runtime_verified=true" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$successor_armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "schema-v3 successor rollback arm differs: $key"
  done
  validate_v3_completion_receipt_namespace "$successor_armed_receipt"
  ! grep -Eq '^predecessor_apply_receipt_sha256=' "$successor_armed_receipt" || \
    holdfast_die "schema-v3 successor rollback arm contains legacy APPLY authority"

  jq -e \
    --arg successor_sha "$successor_armed_sha" \
    --arg predecessor_sha "$predecessor_current_sha" \
    --arg predecessor_backup "$predecessor_backup" \
    --arg predecessor_control "$predecessor_control_sha" \
    --arg completion_kind "$predecessor_completion_kind" \
    --arg completion_attestation "$predecessor_completion_attestation_sha" \
    --arg completion_signature "$predecessor_completion_signature_sha" \
    --arg completion_key "$predecessor_completion_public_key_sha" \
    --arg predecessor_release "$predecessor_release_sha" \
    --arg predecessor_runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg predecessor_runtime_manifest "$predecessor_runtime_manifest_sha" \
    --argjson predecessor_generation "$predecessor_generation" \
    --argjson generation "$release_generation" '
    .successor == true and .successor_armed_receipt == "SUCCESSOR-ARMED.receipt" and
    .successor_armed_receipt_sha256 == $successor_sha and
    .predecessor_current_file == "PREDECESSOR-CURRENT.json" and
    .predecessor_current_sha256 == $predecessor_sha and
    .predecessor_backup_dir == $predecessor_backup and
    .predecessor_control_sha256 == $predecessor_control and
    (has("predecessor_apply_receipt_sha256") | not) and
    .predecessor_completion_kind == $completion_kind and
    .predecessor_completion_attestation_sha256 == $completion_attestation and
    .predecessor_completion_signature_sha256 == $completion_signature and
    .predecessor_completion_public_key_sha256 == $completion_key and
    ([keys[] | select(startswith("predecessor_completion_"))] | sort) == [
      "predecessor_completion_attestation_sha256",
      "predecessor_completion_kind",
      "predecessor_completion_public_key_sha256",
      "predecessor_completion_signature_sha256"
    ] and
    .predecessor_release_evidence_sha256 == $predecessor_release and
    .predecessor_runtime_backup_receipt_sha256 == $predecessor_runtime_receipt and
    .predecessor_runtime_backup_manifest_sha256 == $predecessor_runtime_manifest and
    .predecessor_release_generation == $predecessor_generation and
    .release_generation == $generation' "$pointer" >/dev/null || \
    holdfast_die "schema-v3 successor rollback CURRENT linkage differs"
  jq -e \
    --arg current "$predecessor_current_sha" --arg control "$predecessor_control_sha" \
    --arg release "$predecessor_release_sha" --arg runtime "$predecessor_runtime_manifest_sha" \
    --arg kind "$predecessor_completion_kind" \
    --arg attestation "$predecessor_completion_attestation_sha" \
    --arg signature "$predecessor_completion_signature_sha" \
    --arg public_key "$predecessor_completion_public_key_sha" '
    .schema_version == 2 and .release_mode == "successor" and
    .predecessor_binding.current_state_sha256 == $current and
    .predecessor_binding.control_sha256 == $control and
    (.predecessor_binding | has("apply_receipt_sha256") | not) and
    .predecessor_binding.release_evidence_sha256 == $release and
    .predecessor_binding.runtime_manifest_sha256 == $runtime and
    .predecessor_binding.completion == {
      kind: $kind, attestation_sha256: $attestation,
      signature_sha256: $signature, public_key_sha256: $public_key
    }' "$backup/RELEASE-EVIDENCE.json" >/dev/null || \
    holdfast_die "schema-v3 successor rollback RELEASE-EVIDENCE lineage differs"

  successor_delta_sha=$(holdfast_sha256 "$backup/SUCCESSOR-DELTA.sha256")
  for expected in \
    "release_evidence_sha256=$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" \
    "render_inputs_sha256=$(holdfast_sha256 "$backup/RENDER-INPUTS.sha256")" \
    "successor_delta_sha256=$successor_delta_sha" \
    "predecessor_completion_kind=$predecessor_completion_kind" \
    "predecessor_completion_attestation_sha256=$predecessor_completion_attestation_sha" \
    "predecessor_completion_signature_sha256=$predecessor_completion_signature_sha" \
    "predecessor_completion_public_key_sha256=$predecessor_completion_public_key_sha" \
    "supply_chain_evidence_sha256=$(holdfast_sha256 "$backup/SUPPLY-CHAIN.json")" \
    "supply_chain_signature_sha256=$(holdfast_sha256 "$backup/SUPPLY-CHAIN.sig")" \
    "supply_chain_public_key_sha256=$(holdfast_sha256 "$backup/SUPPLY-CHAIN.pub")"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" "$key")" == "$value" ]] || \
      holdfast_die "schema-v3 successor rollback dry-run authority differs: $key"
  done
  validate_v3_completion_receipt_namespace "$backup/DRY-RUN.receipt"
  ! grep -Eq '^predecessor_apply_receipt_sha256=' "$backup/DRY-RUN.receipt" || \
    holdfast_die "schema-v3 dry-run authority contains legacy predecessor APPLY authority"
  [[ "$attestation_sha" == "$(holdfast_sha256 "$attestation")" && \
    "$signature_sha" == "$(holdfast_sha256 "$signature")" && \
    "$public_key_sha" == "$(holdfast_sha256 "$public_key")" ]] || \
    holdfast_die "schema-v3 recovery completion authority changed during validation"
  (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
}

load_recovered_successor_v5_authority() {
  local pointer=$1 policy=$2 expected key value pointer_sha
  pointer_sha=$(holdfast_sha256 "$pointer")
  load_v5_recovery_completion_authority "$policy"
  predecessor_backup=$(jq -er '.backup_dir' "$predecessor_current_file")
  holdfast_require_absolute "$predecessor_backup"
  require_canonical_root_dir "$predecessor_backup"
  [[ ! -e "$predecessor_backup/APPLY.receipt" && \
    ! -L "$predecessor_backup/APPLY.receipt" ]] || \
    holdfast_die "schema-v5 recovered predecessor contains ordinary APPLY.receipt"
  validate_v5_recovery_completion_artifacts "$backup"
  python3 "$script_dir/successor_binding.py" \
    --validate-gen5-lineage \
    --policy "$policy" \
    --current-state "$predecessor_current_file" \
    --estate-root "$estate_root" \
    --recovery-completion-root "$backup" || \
    holdfast_die "schema-v5 predecessor recovery lineage differs"
  [[ "$predecessor_backup" != "$backup" ]] || \
    holdfast_die "schema-v5 successor rollback cannot point to its own backup"
  predecessor_control_sha=$(holdfast_sha256 "$predecessor_backup/CONTROL.sha256")
  predecessor_apply_sha=""
  predecessor_release_sha=$(holdfast_sha256 "$predecessor_backup/RELEASE-EVIDENCE.json")
  predecessor_runtime_receipt_sha=$(holdfast_sha256 "$predecessor_backup/runtime/BACKUP.receipt")
  predecessor_runtime_manifest_sha=$(holdfast_sha256 "$predecessor_backup/runtime/SHA256SUMS")
  predecessor_generation=$(jq -er '.release_generation' "$predecessor_current_file")
  release_generation=$(holdfast_receipt_value "$successor_armed_receipt" release_generation)
  [[ "$predecessor_generation" == "5" && "$release_generation" == "6" ]] || \
    holdfast_die "schema-v5 successor rollback generation linkage is not exact 5 -> 6"
  [[ "$(holdfast_receipt_value "$successor_armed_receipt" successor_policy_sha256)" == \
    "$(holdfast_sha256 "$policy")" ]] || \
    holdfast_die "schema-v5 successor rollback arm points to another policy"
  for expected in \
    "schema_version=1" "successor_backup_dir=$backup" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "predecessor_release_evidence_sha256=$predecessor_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_manifest_sha" \
    "predecessor_release_generation=5" "release_generation=6" \
    "route_database_state=absent" "public_ipv4_ipv6_closed_status=404" \
    "predecessor_runtime_verified=true" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$successor_armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "schema-v5 successor rollback arm differs: $key"
  done
  validate_v5_recovery_completion_lineage "$successor_armed_receipt"
  validate_v5_recovery_completion_lineage "$backup/DRY-RUN.receipt"
  validate_v5_recovery_completion_lineage \
    "$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"
  validate_v5_recovery_completion_lineage "$backup/APPLY-ARMED.receipt"
  jq -e \
    --arg current "$predecessor_current_sha" \
    --arg control "$predecessor_control_sha" \
    --arg release "$predecessor_release_sha" \
    --arg runtime "$predecessor_runtime_manifest_sha" \
    --arg kind "$predecessor_recovery_completion_kind" \
    --arg archive "$predecessor_recovery_completion_archive" \
    --arg archive_sha "$predecessor_recovery_completion_archive_sha" \
    --arg receipt "$predecessor_recovery_completion_receipt" \
    --arg receipt_sha "$predecessor_recovery_completion_receipt_sha" \
    --arg armed "$predecessor_recovery_completion_armed_receipt" \
    --arg armed_sha "$predecessor_recovery_completion_armed_receipt_sha" \
    --arg failure "$predecessor_recovery_completion_failure_receipt" \
    --arg failure_sha "$predecessor_recovery_completion_failure_receipt_sha" '
    .schema_version == 2 and .release_mode == "successor" and
    .predecessor_binding.current_state_sha256 == $current and
    .predecessor_binding.control_sha256 == $control and
    .predecessor_binding.release_evidence_sha256 == $release and
    .predecessor_binding.runtime_manifest_sha256 == $runtime and
    .predecessor_binding.recovery_completion == {
      kind:$kind,archive:$archive,archive_sha256:$archive_sha,
      receipt:$receipt,receipt_sha256:$receipt_sha,
      armed_receipt:$armed,armed_receipt_sha256:$armed_sha,
      failure_receipt:$failure,failure_receipt_sha256:$failure_sha
    } and
    (.predecessor_binding | has("apply_receipt_sha256") | not) and
    (.predecessor_binding | has("completion") | not)
  ' "$backup/RELEASE-EVIDENCE.json" >/dev/null || \
    holdfast_die "schema-v5 successor rollback RELEASE-EVIDENCE differs"
  jq -e \
    --arg successor_sha "$successor_armed_sha" \
    --arg predecessor_sha "$predecessor_current_sha" \
    --arg predecessor_backup "$predecessor_backup" \
    --arg predecessor_control "$predecessor_control_sha" \
    --arg predecessor_release "$predecessor_release_sha" \
    --arg predecessor_runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg predecessor_runtime_manifest "$predecessor_runtime_manifest_sha" \
    --argjson lineage "$predecessor_recovery_completion_json" '
    .successor == true and
    .successor_armed_receipt == "SUCCESSOR-ARMED.receipt" and
    .successor_armed_receipt_sha256 == $successor_sha and
    .predecessor_current_file == "PREDECESSOR-CURRENT.json" and
    .predecessor_current_sha256 == $predecessor_sha and
    .predecessor_backup_dir == $predecessor_backup and
    .predecessor_control_sha256 == $predecessor_control and
    .predecessor_release_evidence_sha256 == $predecessor_release and
    .predecessor_runtime_backup_receipt_sha256 == $predecessor_runtime_receipt and
    .predecessor_runtime_backup_manifest_sha256 == $predecessor_runtime_manifest and
    .predecessor_release_generation == 5 and .release_generation == 6 and
    (. * $lineage) == . and
    ([keys[] | select(startswith("predecessor_recovery_completion_"))] | sort) ==
      ($lineage | keys | sort) and
    (has("predecessor_apply_receipt_sha256") | not) and
    ([keys[] | select(startswith("predecessor_completion_"))] | length) == 0
  ' "$pointer" >/dev/null || \
    holdfast_die "schema-v5 successor rollback CURRENT linkage differs"
  validate_successor_completion_namespace "$backup/successor-authority"
  [[ "$(holdfast_sha256 "$pointer")" == "$pointer_sha" ]] || \
    holdfast_die "schema-v5 successor rollback pointer changed during validation"
}

load_successor_authority() {
  local pointer=$1 expected key value predecessor_apply predecessor_file pointer_successor
  local successor_delta_sha authority_dir relative line digest pointer_sha authority_count=0
  local policy="$backup/successor-authority/successor-policy.json"
  local -A seen_authorities=()
  local -a v4_predecessor_apply_keys=(
    schema_version completion_state applied_at closed_verified_at estate_root
    backup_dir release_env_sha256 release_evidence_sha256 render_inputs_sha256
    apply_armed_receipt_sha256 control_sha256 transaction_sha256
    applied_targets_sha256 cargo_gate runtime_backup closed_bracket
    route_database_state public_ipv4_ipv6_closed_status ingress_opened
    services_activated runtime_verified successor successor_armed_receipt
    successor_armed_receipt_sha256 predecessor_current_file
    predecessor_current_sha256 predecessor_backup_dir predecessor_control_sha256
    predecessor_completion_kind predecessor_completion_attestation_sha256
    predecessor_completion_signature_sha256 predecessor_completion_public_key_sha256
    predecessor_release_evidence_sha256 predecessor_runtime_backup_receipt_sha256
    predecessor_runtime_backup_manifest_sha256 predecessor_release_generation
    release_generation runtime_backup_receipt_sha256 runtime_backup_manifest_sha256
  )
  pointer_successor=$(jq -er 'if has("successor") then (.successor | tostring) else "absent" end' "$pointer")
  if [[ "$backup_expected_successor" == "false" ]]; then
    [[ "$pointer_successor" == "false" || "$pointer_successor" == "absent" ]] || \
      holdfast_die "base backup CURRENT successor mode differs"
    successor_rollback="false"
    return 0
  fi
  [[ "$backup_expected_successor" == "true" && "$pointer_successor" == "true" ]] || \
    holdfast_die "successor backup CURRENT mode is missing or downgraded"
  successor_rollback="true"
  predecessor_current_file="$backup/PREDECESSOR-CURRENT.json"
  successor_armed_receipt="$backup/SUCCESSOR-ARMED.receipt"
  require_root_file "$predecessor_current_file"
  require_root_file "$successor_armed_receipt"
  predecessor_current_sha=$(holdfast_sha256 "$predecessor_current_file")
  successor_armed_sha=$(holdfast_sha256 "$successor_armed_receipt")
  successor_policy_version=$(jq -er '.schema_version' "$policy")
  if [[ "$successor_policy_version" == "3" ]]; then
    require_root_file "$pointer"
    pointer_sha=$(holdfast_sha256 "$pointer")
    validate_recovered_successor_authority "$pointer"
    validate_successor_persisted_supply_chain
    [[ "$(holdfast_sha256 "$pointer")" == "$pointer_sha" ]] || \
      holdfast_die "schema-v3 successor rollback pointer changed during validation"
    return 0
  fi
  if [[ "$successor_policy_version" == "5" ]]; then
    load_recovered_successor_v5_authority "$pointer" "$policy"
    validate_successor_persisted_supply_chain
    return 0
  fi
  [[ "$successor_policy_version" == "1" || "$successor_policy_version" == "2" || \
    "$successor_policy_version" == "4" ]] || \
    holdfast_die "successor rollback policy schema is unsupported"
  if [[ "$successor_policy_version" == "4" ]]; then
    jq -e '
      keys == ["ceremony","overlay","predecessor","schema_version","successor"] and
      .schema_version == 4 and .ceremony == "holdfast-rikune-successor-v4" and
      (.predecessor | keys) == [
        "access_build_input_schema","access_build_input_sha256",
        "access_image","apply_receipt_sha256",
        "candidate_evidence_sha256","candidate_targets_sha256","control_sha256",
        "current_state_sha256","package_catalog_sha256","permission_catalog_sha256",
        "release_evidence_sha256","runtime_manifest_sha256"
      ] and (.predecessor | has("completion") | not)' "$policy" >/dev/null || \
      holdfast_die "schema-v4 successor policy authority differs"
    for predecessor_file in "$policy" "$successor_armed_receipt" "$pointer" \
      "$backup/DRY-RUN.receipt" "$backup/RELEASE-EVIDENCE.json" \
      "$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"; do
      validate_no_predecessor_completion_namespace "$predecessor_file"
    done
    if [[ -f "$backup/APPLY-ARMED.receipt" && ! -L "$backup/APPLY-ARMED.receipt" ]]; then
      validate_no_predecessor_completion_namespace "$backup/APPLY-ARMED.receipt"
    fi
  fi
  jq -e \
    --arg estate "$estate_root" \
    '.schema_version == 2 and .state == "applied_ingress_closed" and
     .estate_root == $estate and .route_database_state == "absent" and
     .public_ipv4_ipv6_closed_status == 404 and .runtime_verified == true and
     .services_activated == true and .ingress_opened == false' \
    "$predecessor_current_file" >/dev/null || \
    holdfast_die "successor rollback predecessor CURRENT is not eligible"
  predecessor_backup=$(jq -er '.backup_dir' "$predecessor_current_file")
  holdfast_require_absolute "$predecessor_backup"
  require_canonical_root_dir "$predecessor_backup"
  [[ "$predecessor_backup" != "$backup" ]] || \
    holdfast_die "successor rollback cannot point to its own backup as predecessor"
  [[ -z "$(find "$predecessor_backup" -maxdepth 0 -perm /077 -print -quit)" ]] || \
    holdfast_die "successor rollback predecessor backup is not private"
  [[ -z "$(find "$predecessor_backup" -xdev -type l -print -quit)" ]] || \
    holdfast_die "successor rollback predecessor backup contains a symlink"
  [[ -z "$(find "$predecessor_backup" -xdev ! -user root -print -quit)" ]] || \
    holdfast_die "successor rollback predecessor backup contains a non-root-owned entry"
  for predecessor_file in \
    "$predecessor_backup/CONTROL.sha256" "$predecessor_backup/APPLY.receipt" \
    "$predecessor_backup/RELEASE-EVIDENCE.json" \
    "$predecessor_backup/runtime/BACKUP.receipt" \
    "$predecessor_backup/runtime/SHA256SUMS"; do
    require_root_file "$predecessor_file"
  done
  (cd "$predecessor_backup" && sha256sum --check CONTROL.sha256)
  (cd "$predecessor_backup/runtime" && sha256sum --check SHA256SUMS)
  predecessor_control_sha=$(holdfast_sha256 "$predecessor_backup/CONTROL.sha256")
  predecessor_apply_sha=$(holdfast_sha256 "$predecessor_backup/APPLY.receipt")
  predecessor_release_sha=$(holdfast_sha256 "$predecessor_backup/RELEASE-EVIDENCE.json")
  predecessor_runtime_receipt_sha=$(holdfast_sha256 "$predecessor_backup/runtime/BACKUP.receipt")
  predecessor_runtime_manifest_sha=$(holdfast_sha256 "$predecessor_backup/runtime/SHA256SUMS")
  if [[ "$successor_policy_version" == "4" ]]; then
    jq -e \
      --arg current "$predecessor_current_sha" --arg control "$predecessor_control_sha" \
      --arg apply "$predecessor_apply_sha" --arg release "$predecessor_release_sha" \
      --arg runtime "$predecessor_runtime_manifest_sha" '
      .predecessor.current_state_sha256 == $current and
      .predecessor.control_sha256 == $control and
      .predecessor.apply_receipt_sha256 == $apply and
      .predecessor.release_evidence_sha256 == $release and
      .predecessor.runtime_manifest_sha256 == $runtime' "$policy" >/dev/null || \
      holdfast_die "schema-v4 successor policy points to another predecessor authority"
  fi
  [[ "$(jq -er '.control_sha256' "$predecessor_current_file")" == "$predecessor_control_sha" && \
    "$(jq -er '.apply_receipt_sha256' "$predecessor_current_file")" == "$predecessor_apply_sha" && \
    "$(jq -er '.release_evidence_sha256' "$predecessor_current_file")" == "$predecessor_release_sha" ]] || \
    holdfast_die "successor rollback predecessor CURRENT authority differs"
  if jq -e 'has("runtime_backup_receipt_sha256")' "$predecessor_current_file" >/dev/null; then
    [[ "$(jq -er '.runtime_backup_receipt_sha256' "$predecessor_current_file")" == \
      "$predecessor_runtime_receipt_sha" ]] || \
      holdfast_die "successor rollback predecessor runtime receipt differs"
  fi
  if jq -e 'has("runtime_backup_manifest_sha256")' "$predecessor_current_file" >/dev/null; then
    [[ "$(jq -er '.runtime_backup_manifest_sha256' "$predecessor_current_file")" == \
      "$predecessor_runtime_manifest_sha" ]] || \
      holdfast_die "successor rollback predecessor runtime manifest differs"
  fi
  predecessor_apply="$predecessor_backup/APPLY.receipt"
  if [[ "$successor_policy_version" == "4" ]]; then
    python3 "$script_dir/successor_binding.py" \
      --validate-gen4-lineage --current-state "$predecessor_current_file" \
      --estate-root "$estate_root" || \
      holdfast_die "schema-v4 predecessor CURRENT/APPLY lineage differs"
    validate_exact_receipt_keys "$predecessor_apply" \
      "schema-v4 predecessor APPLY" "${v4_predecessor_apply_keys[@]}"
    jq -e '
      .successor == true and .predecessor_release_generation == 3 and
      .release_generation == 4 and
      ([keys[] | select(startswith("predecessor_completion_"))] | sort) == [
        "predecessor_completion_attestation_sha256",
        "predecessor_completion_kind",
        "predecessor_completion_public_key_sha256",
        "predecessor_completion_signature_sha256"
      ] and (has("predecessor_apply_receipt_sha256") | not)' \
      "$predecessor_current_file" >/dev/null || \
      holdfast_die "schema-v4 predecessor CURRENT is not exact generation 3 -> 4 authority"
    [[ "$(holdfast_receipt_value "$predecessor_apply" successor)" == "true" && \
      "$(holdfast_receipt_value "$predecessor_apply" predecessor_release_generation)" == "3" && \
      "$(holdfast_receipt_value "$predecessor_apply" release_generation)" == "4" ]] || \
      holdfast_die "schema-v4 predecessor APPLY is not exact generation 3 -> 4 authority"
    validate_v3_completion_receipt_namespace "$predecessor_apply"
  fi
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
      holdfast_die "successor rollback predecessor APPLY differs: $key"
  done
  [[ "$(holdfast_receipt_value "$predecessor_backup/runtime/BACKUP.receipt" schema_version)" == "2" && \
    "$(holdfast_receipt_value "$predecessor_backup/runtime/BACKUP.receipt" isolated_restore_probe)" == "passed" ]] || \
    holdfast_die "successor rollback predecessor runtime authority differs"
  predecessor_generation=$(jq -er '.release_generation // 1' "$predecessor_current_file")
  release_generation=$(holdfast_receipt_value "$successor_armed_receipt" release_generation)
  [[ "$predecessor_generation" =~ ^[1-9][0-9]*$ && \
    "$release_generation" =~ ^[1-9][0-9]*$ && \
    "$release_generation" -eq $((predecessor_generation + 1)) ]] || \
    holdfast_die "successor rollback generation linkage is invalid"
  if [[ "$successor_policy_version" == "4" ]]; then
    [[ "$predecessor_generation" == "4" && "$release_generation" == "5" ]] || \
      holdfast_die "schema-v4 successor rollback generation linkage is not exact 4 -> 5"
    [[ "$(holdfast_receipt_value "$successor_armed_receipt" successor_policy_sha256)" == \
      "$(holdfast_sha256 "$policy")" ]] || \
      holdfast_die "schema-v4 successor rollback arm points to another policy"
  fi
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
    "release_generation=$release_generation" "route_database_state=absent" \
    "public_ipv4_ipv6_closed_status=404" "predecessor_runtime_verified=true" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$successor_armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "successor rollback arm differs: $key"
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
    '.successor == true and .successor_armed_receipt == "SUCCESSOR-ARMED.receipt" and
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
    holdfast_die "successor rollback CURRENT linkage differs"
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
    "$backup/RELEASE-EVIDENCE.json" >/dev/null || \
    holdfast_die "successor rollback RELEASE-EVIDENCE points to another predecessor"
  require_root_file "$backup/SUCCESSOR-DELTA.sha256"
  successor_delta_sha=$(holdfast_sha256 "$backup/SUCCESSOR-DELTA.sha256")
  [[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" successor_delta_sha256)" == \
    "$successor_delta_sha" && \
    "$(jq -er '.successor_delta_sha256' "$backup/RELEASE-EVIDENCE.json")" == \
    "$successor_delta_sha" ]] || \
    holdfast_die "successor rollback delta authority differs"
  grep -Fqx "$successor_delta_sha  SUCCESSOR-DELTA.sha256" \
    "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits the successor delta"
  grep -Fqx "$predecessor_current_sha  PREDECESSOR-CURRENT.json" \
    "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits predecessor CURRENT"
  grep -Fqx "$successor_armed_sha  SUCCESSOR-ARMED.receipt" \
    "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits successor arm"
  for relative in SUPPLY-CHAIN.json SUPPLY-CHAIN.sig SUPPLY-CHAIN.pub; do
    require_root_file "$backup/$relative"
    grep -Fqx "$(holdfast_sha256 "$backup/$relative")  $relative" \
      "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits supply-chain authority: $relative"
  done
  authority_dir="$backup/successor-authority"
  require_canonical_root_dir "$authority_dir"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]] || \
      holdfast_die "successor render-input authority contains an invalid line"
    digest=${BASH_REMATCH[1]}
    relative=${BASH_REMATCH[2]}
    [[ -z "${seen_authorities[$relative]+x}" ]] || \
      holdfast_die "successor render-input authority repeats a path"
    seen_authorities[$relative]=1
    require_root_file "$authority_dir/$relative"
    [[ "$(holdfast_sha256 "$authority_dir/$relative")" == "$digest" ]] || \
      holdfast_die "successor generation authority differs from render inputs: $relative"
    grep -Fqx "$digest  successor-authority/$relative" \
      "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits generation authority: $relative"
    authority_count=$((authority_count + 1))
  done <"$backup/RENDER-INPUTS.sha256"
  ((authority_count == 6)) || \
    holdfast_die "successor generation authority set is not exactly six files"
  for relative in Dockerfile.analyzer bridge-package-lock.json; do
    require_root_file "$authority_dir/$relative"
    grep -Fqx "$(holdfast_sha256 "$authority_dir/$relative")  successor-authority/$relative" \
      "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits generation authority: $relative"
  done
  require_canonical_root_dir "$authority_dir/assets"
  for relative in 20260823_rikune_root_up.sql 20260823_rikune_root_down.sql; do
    require_root_file "$authority_dir/assets/$relative"
    grep -Fqx "$(holdfast_sha256 "$authority_dir/assets/$relative")  successor-authority/assets/$relative" \
      "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits route authority: $relative"
  done
  validate_successor_authority_namespace "$authority_dir"
  run_python_tool "$supply_validator" "$script_dir/supply_chain_evidence.py" \
    --release-env "$backup/release.env" \
    --evidence "$backup/SUPPLY-CHAIN.json" \
    --signature "$backup/SUPPLY-CHAIN.sig" \
    --public-key "$backup/SUPPLY-CHAIN.pub" \
    --dockerfile "$authority_dir/Dockerfile.analyzer" \
    --bridge-lock "$authority_dir/bridge-package-lock.json" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" \
    --successor-policy "$authority_dir/successor-policy.json"
  validate_successor_authority_namespace "$authority_dir"
}

validate_successor_persisted_supply_chain() {
  local delta_sha relative authority_dir line digest authority_count=0 file
  local -A seen_authorities=() v3_anchor_hashes=() v3_anchor_identities=()
  local -a v3_anchor_files=()
  [[ "$successor_rollback" == "true" ]] || return 0
  authority_dir="$backup/successor-authority"
  require_canonical_root_dir "$authority_dir"
  if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" || "$successor_policy_version" == "5" ]]; then
    v3_anchor_files=(
      "$backup/CONTROL.sha256"
      "$authority_dir/successor-policy.json"
      "$authority_dir/Dockerfile.analyzer"
      "$authority_dir/bridge-package-lock.json"
      "$authority_dir/assets/20260823_rikune_root_up.sql"
      "$authority_dir/assets/20260823_rikune_root_down.sql"
      "$backup/PREDECESSOR-CURRENT.json"
      "$backup/SUCCESSOR-ARMED.receipt"
      "$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"
      "$backup/RELEASE-EVIDENCE.json"
      "$backup/release.env"
      "$backup/DRY-RUN.receipt"
      "$backup/SUPPLY-CHAIN.json"
      "$backup/SUPPLY-CHAIN.sig"
      "$backup/SUPPLY-CHAIN.pub"
      "$backup/RENDER-INPUTS.sha256"
      "$backup/SUCCESSOR-DELTA.sha256"
    )
    if [[ "$successor_policy_version" == "3" ]]; then
      v3_anchor_files+=(
        "$backup/RECOVERY-COMPLETION-ATTESTATION.json"
        "$backup/RECOVERY-COMPLETION-ATTESTATION.sig"
        "$backup/RECOVERY-COMPLETION-ATTESTATION.pub"
      )
    elif [[ "$successor_policy_version" == "5" ]]; then
      v3_anchor_files+=(
        "$backup/$predecessor_recovery_completion_archive"
        "$backup/$predecessor_recovery_completion_receipt"
        "$backup/$predecessor_recovery_completion_armed_receipt"
        "$backup/$predecessor_recovery_completion_failure_receipt"
      )
    fi
    for file in "${v3_anchor_files[@]}"; do
      require_root_file "$file"
      v3_anchor_hashes["$file"]=$(holdfast_sha256 "$file")
      v3_anchor_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
    done
    if [[ -n "$v3_control_sha" && -n "$v3_control_identity" ]]; then
      [[ "${v3_anchor_hashes["$backup/CONTROL.sha256"]}" == "$v3_control_sha" && \
        "${v3_anchor_identities["$backup/CONTROL.sha256"]}" == "$v3_control_identity" ]] || \
        holdfast_die "schema-v3 rollback CONTROL differs from its frozen authority"
    fi
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]] || \
      holdfast_die "successor render-input authority contains an invalid line"
    digest=${BASH_REMATCH[1]}
    relative=${BASH_REMATCH[2]}
    [[ -z "${seen_authorities[$relative]+x}" ]] || \
      holdfast_die "successor render-input authority repeats a path"
    seen_authorities[$relative]=1
    require_root_file "$authority_dir/$relative"
    if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" || "$successor_policy_version" == "5" ]]; then
      v3_anchor_hashes["$authority_dir/$relative"]=$(holdfast_sha256 "$authority_dir/$relative")
      v3_anchor_identities["$authority_dir/$relative"]=$(stat -c '%d:%i:%u:%h:%f' -- \
        "$authority_dir/$relative")
    fi
    [[ "$(holdfast_sha256 "$authority_dir/$relative")" == "$digest" ]] || \
      holdfast_die "successor generation authority differs from render inputs: $relative"
    grep -Fqx "$digest  successor-authority/$relative" \
      "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits generation authority: $relative"
    authority_count=$((authority_count + 1))
  done <"$backup/RENDER-INPUTS.sha256"
  ((authority_count == 6)) || \
    holdfast_die "successor generation authority set is not exactly six files"
  for relative in Dockerfile.analyzer bridge-package-lock.json; do
    require_root_file "$authority_dir/$relative"
    grep -Fqx "$(holdfast_sha256 "$authority_dir/$relative")  successor-authority/$relative" \
      "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits generation authority: $relative"
  done
  require_canonical_root_dir "$authority_dir/assets"
  for relative in 20260823_rikune_root_up.sql 20260823_rikune_root_down.sql; do
    require_root_file "$authority_dir/assets/$relative"
    grep -Fqx "$(holdfast_sha256 "$authority_dir/assets/$relative")  successor-authority/assets/$relative" \
      "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits route authority: $relative"
  done
  validate_successor_authority_namespace "$authority_dir"
  require_root_file "$backup/SUCCESSOR-DELTA.sha256"
  delta_sha=$(holdfast_sha256 "$backup/SUCCESSOR-DELTA.sha256")
  [[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" successor_delta_sha256)" == \
    "$delta_sha" && \
    "$(jq -er '.successor_delta_sha256' "$backup/RELEASE-EVIDENCE.json")" == \
    "$delta_sha" ]] || \
    holdfast_die "successor rollback delta authority differs"
  grep -Fqx "$delta_sha  SUCCESSOR-DELTA.sha256" "$backup/CONTROL.sha256" || \
    holdfast_die "successor CONTROL omits the successor delta"
  run_python_tool "$supply_validator" "$script_dir/supply_chain_evidence.py" \
    --release-env "$backup/release.env" \
    --evidence "$backup/SUPPLY-CHAIN.json" \
    --signature "$backup/SUPPLY-CHAIN.sig" \
    --public-key "$backup/SUPPLY-CHAIN.pub" \
    --dockerfile "$authority_dir/Dockerfile.analyzer" \
    --bridge-lock "$authority_dir/bridge-package-lock.json" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" \
    --successor-policy "$authority_dir/successor-policy.json"
  validate_successor_authority_namespace "$authority_dir"
  (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
  if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" || "$successor_policy_version" == "5" ]]; then
    for file in "${!v3_anchor_hashes[@]}"; do
      require_root_file "$file"
      [[ "$(holdfast_sha256 "$file")" == "${v3_anchor_hashes[$file]}" && \
        "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
          "${v3_anchor_identities[$file]}" ]] || \
        holdfast_die "schema-v3 rollback signed authority changed during validation: $file"
    done
  fi
}

validate_v3_cached_control_authority() {
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  require_root_file "$backup/CONTROL.sha256"
  [[ "$(holdfast_sha256 "$backup/CONTROL.sha256")" == "$v3_control_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$backup/CONTROL.sha256")" == \
      "$v3_control_identity" ]] || \
    holdfast_die "schema-v3 rollback CONTROL changed before mutation"
}

revalidate_v3_successor_authority() {
  local pointer=$1 pointer_sha expected_policy_version=$backup_successor_policy_version
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  validate_v3_state_dir_identity
  validate_v3_cached_control_authority
  require_root_file "$pointer"
  pointer_sha=$(holdfast_sha256 "$pointer")
  load_successor_authority "$pointer"
  [[ "$successor_policy_version" == "$expected_policy_version" && \
    ( "$successor_policy_version" == "3" || "$successor_policy_version" == "4" || "$successor_policy_version" == "5" ) ]] || \
    holdfast_die "frozen successor rollback authority schema changed"
  [[ "$(holdfast_sha256 "$pointer")" == "$pointer_sha" ]] || \
    holdfast_die "schema-v3 successor rollback pointer changed during revalidation"
  validate_v3_cached_control_authority
  validate_v3_state_dir_identity
}

append_successor_lineage_receipt_fields() {
  [[ "$successor_rollback" == "true" ]] || return 0
  printf 'successor=true\n'
  printf 'successor_armed_receipt_sha256=%s\n' "$successor_armed_sha"
  printf 'predecessor_current_sha256=%s\n' "$predecessor_current_sha"
  printf 'predecessor_backup_dir=%s\n' "$predecessor_backup"
  printf 'predecessor_control_sha256=%s\n' "$predecessor_control_sha"
  if [[ "$successor_policy_version" == "3" ]]; then
    printf 'predecessor_completion_kind=%s\n' "$predecessor_completion_kind"
    printf 'predecessor_completion_attestation_sha256=%s\n' "$predecessor_completion_attestation_sha"
    printf 'predecessor_completion_signature_sha256=%s\n' "$predecessor_completion_signature_sha"
    printf 'predecessor_completion_public_key_sha256=%s\n' "$predecessor_completion_public_key_sha"
  elif [[ "$successor_policy_version" == "5" ]]; then
    append_v5_recovery_completion_lineage
  else
    printf 'predecessor_apply_receipt_sha256=%s\n' "$predecessor_apply_sha"
  fi
  printf 'predecessor_release_evidence_sha256=%s\n' "$predecessor_release_sha"
  printf 'predecessor_runtime_backup_receipt_sha256=%s\n' "$predecessor_runtime_receipt_sha"
  printf 'predecessor_runtime_backup_manifest_sha256=%s\n' "$predecessor_runtime_manifest_sha"
  printf 'predecessor_release_generation=%s\n' "$predecessor_generation"
  printf 'release_generation=%s\n' "$release_generation"
}

validate_successor_lineage_receipt() {
  local receipt=$1 expected key value
  local -a lineage_authority
  [[ "$successor_rollback" == "true" ]] || return 0
  require_root_file "$receipt"
  if [[ "$successor_policy_version" == "3" ]]; then
    lineage_authority=(
      "predecessor_completion_kind=$predecessor_completion_kind"
      "predecessor_completion_attestation_sha256=$predecessor_completion_attestation_sha"
      "predecessor_completion_signature_sha256=$predecessor_completion_signature_sha"
      "predecessor_completion_public_key_sha256=$predecessor_completion_public_key_sha"
    )
    validate_v3_completion_receipt_namespace "$receipt"
    ! grep -Eq '^predecessor_apply_receipt_sha256=' "$receipt" || \
      holdfast_die "schema-v3 successor rollback receipt contains legacy APPLY authority"
  elif [[ "$successor_policy_version" == "5" ]]; then
    mapfile -t lineage_authority < <(append_v5_recovery_completion_lineage)
    validate_v5_recovery_completion_lineage "$receipt"
  else
    lineage_authority=("predecessor_apply_receipt_sha256=$predecessor_apply_sha")
    if [[ "$successor_policy_version" == "4" ]]; then
      validate_no_predecessor_completion_namespace "$receipt"
    fi
  fi
  for expected in \
    "successor=true" "successor_armed_receipt_sha256=$successor_armed_sha" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "${lineage_authority[@]}" \
    "predecessor_release_evidence_sha256=$predecessor_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_manifest_sha" \
    "predecessor_release_generation=$predecessor_generation" \
    "release_generation=$release_generation"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "successor rollback receipt lineage differs: $key"
  done
}

restore_immediate_predecessor_current() {
  local temporary
  [[ "$successor_rollback" == "true" ]] || return 0
  if [[ -e "$state_file" || -L "$state_file" ]]; then
    require_root_file "$state_file"
    jq -e \
      --arg backup "$backup" \
      --arg predecessor_sha "$predecessor_current_sha" \
      '.state == "rolled_back" and .backup_dir == $backup and
       .successor == true and .predecessor_current_sha256 == $predecessor_sha' \
      "$state_file" >/dev/null || \
      holdfast_die "successor rollback refuses to replace a non-completed CURRENT"
  fi
  temporary="$state_dir/.PREDECESSOR-CURRENT.$$"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] || \
    holdfast_die "successor rollback predecessor CURRENT temporary path exists"
  install -o 0 -g 0 -m 0600 -- "$predecessor_current_file" "$temporary"
  commit_atomic_file "$temporary" "$state_file"
  [[ "$(holdfast_sha256 "$state_file")" == "$predecessor_current_sha" ]] || \
    holdfast_die "successor rollback did not restore the immediate predecessor CURRENT"
}

load_frozen_rollback_authorities() {
  local attempt armed_name armed_receipt armed_sha expected key value file_name
  attempt=$(jq -er '.rollback_attempt_id' "$state_file")
  [[ "$attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || \
    holdfast_die "rollback frozen-authority attempt identity is unsafe"
  armed_name=$(jq -er '.rollback_armed_receipt' "$state_file")
  [[ "$armed_name" == "ROLLBACK-EXECUTE-ARMED-${attempt}.receipt" ]] || \
    holdfast_die "rollback state points to another frozen authority"
  armed_receipt="$state_dir/$armed_name"
  require_root_file "$armed_receipt"
  armed_sha=$(holdfast_sha256 "$armed_receipt")
  [[ "$(jq -er '.rollback_armed_receipt_sha256' "$state_file")" == "$armed_sha" ]] || \
    holdfast_die "rollback frozen authority receipt was replaced"

  frozen_open_evidence_name="ROLLBACK-OPEN-EVIDENCE-${attempt}.json"
  frozen_open_signature_name="ROLLBACK-OPEN-SIGNATURE-${attempt}.sig"
  frozen_public_key_name="ROLLBACK-AUTHORITY-PUBLIC-KEY-${attempt}.pub"
  frozen_revocation_evidence_name="ROLLBACK-REVOCATION-EVIDENCE-${attempt}.json"
  frozen_revocation_signature_name="ROLLBACK-REVOCATION-SIGNATURE-${attempt}.sig"
  frozen_edge_evidence_name="none"
  frozen_edge_signature_name="none"
  frozen_open_edge_name="none"
  if [[ "$(holdfast_receipt_value "$route_receipt" was_public_open)" == "true" ]]; then
    frozen_edge_evidence_name="ROLLBACK-EDGE-EVIDENCE-${attempt}.json"
    frozen_edge_signature_name="ROLLBACK-EDGE-SIGNATURE-${attempt}.sig"
    frozen_open_edge_name="ROLLBACK-OPEN-EDGE-EVIDENCE-${attempt}.json"
  fi
  for expected in \
    "open_evidence_file=$frozen_open_evidence_name" \
    "open_signature_file=$frozen_open_signature_name" \
    "authority_public_key_file=$frozen_public_key_name" \
    "revocation_evidence_file=$frozen_revocation_evidence_name" \
    "revocation_signature_file=$frozen_revocation_signature_name" \
    "edge_rollback_evidence_file=$frozen_edge_evidence_name" \
    "edge_rollback_signature_file=$frozen_edge_signature_name" \
    "open_edge_evidence_file=$frozen_open_edge_name"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "rollback frozen authority identity differs: $key"
  done
  for file_name in "$frozen_open_evidence_name" "$frozen_open_signature_name" \
    "$frozen_public_key_name" "$frozen_revocation_evidence_name" \
    "$frozen_revocation_signature_name" "$frozen_edge_evidence_name" \
    "$frozen_edge_signature_name" "$frozen_open_edge_name"; do
    [[ "$file_name" == "none" ]] && continue
    require_root_file "$state_dir/$file_name"
  done
  open_evidence="$state_dir/$frozen_open_evidence_name"
  open_signature="$state_dir/$frozen_open_signature_name"
  authority_public_key="$state_dir/$frozen_public_key_name"
  revocation_evidence="$state_dir/$frozen_revocation_evidence_name"
  revocation_signature="$state_dir/$frozen_revocation_signature_name"
  if [[ "$frozen_edge_evidence_name" != "none" ]]; then
    edge_rollback_evidence="$state_dir/$frozen_edge_evidence_name"
    edge_rollback_signature="$state_dir/$frozen_edge_signature_name"
    open_edge_evidence="$state_dir/$frozen_open_edge_name"
  fi
  for expected in \
    "open_evidence_sha256=$(holdfast_sha256 "$open_evidence")" \
    "open_signature_sha256=$(holdfast_sha256 "$open_signature")" \
    "authority_public_key_sha256=$(holdfast_sha256 "$authority_public_key")" \
    "revocation_evidence_sha256=$(holdfast_sha256 "$revocation_evidence")" \
    "revocation_signature_sha256=$(holdfast_sha256 "$revocation_signature")"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "rollback frozen authority digest differs: $key"
  done
}

psql_bin=$(test_override HOLDFAST_PSQL_BIN psql)
public_verify=$(test_override HOLDFAST_PUBLIC_VERIFY_BIN "$script_dir/public-origin-verify.sh")
release_validator=$(test_override HOLDFAST_RELEASE_VALIDATOR_BIN "$script_dir/validate_release_evidence.py")
supply_validator=$(test_override HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN "$script_dir/supply_chain_evidence.py")
authority_tool=$(test_override HOLDFAST_AUTHORITY_EVIDENCE_BIN "$script_dir/authority_evidence.py")
edge_tool=$(test_override HOLDFAST_EDGE_EVIDENCE_BIN "$script_dir/edge_evidence.py")
docker_bin=$(test_override HOLDFAST_DOCKER_BIN docker)
runtime_restore=$(test_override HOLDFAST_RUNTIME_RESTORE_BIN "$script_dir/runtime-restore.sh")
estate_transaction=$(test_override HOLDFAST_ESTATE_TRANSACTION_BIN "$script_dir/estate_transaction.py")
completion_attestation_tool=$(test_override \
  HOLDFAST_RECOVERY_COMPLETION_ATTESTATION_BIN \
  "$script_dir/recovery_completion_attestation.py")

state_file="$state_dir/CURRENT.json"
require_canonical_root_dir "$state_dir"
state_dir_identity=$(stat -c '%d:%i:%u:%f' -- "$state_dir")
require_canonical_root_dir "$backup"
require_canonical_root_dir "$estate_root"
require_root_file "$state_file"
backup_expected_successor=$(derive_backup_successor_mode)
edge_policy_args=()
if [[ "$backup_expected_successor" == "true" ]]; then
  backup_successor_policy_version=$(jq -er '.schema_version' \
    "$backup/successor-authority/successor-policy.json")
  edge_policy_args=(
    --successor-policy "$backup/successor-authority/successor-policy.json"
  )
fi
validate_v3_state_dir_identity
route_generation_identity=$(holdfast_sha256 "$backup/CONTROL.sha256")
v3_control_sha=""
v3_control_identity=""
if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
  if [[ "$(holdfast_sha256 "$state_file")" == \
    "$(holdfast_sha256 "$backup/PREDECESSOR-CURRENT.json")" ]]; then
    # A completed successor rollback has already restored the predecessor
    # CURRENT.  Its own control hash is intentionally from the prior
    # generation; the immutable completion archive below must still prove the
    # current generation before terminal adoption is accepted.
    v3_control_sha=$route_generation_identity
  else
    v3_control_sha=$(jq -er '.control_sha256' "$state_file")
    [[ "$v3_control_sha" == "$route_generation_identity" ]] || \
      holdfast_die "schema-v3 rollback CURRENT differs from its CONTROL"
  fi
  v3_control_identity=$(stat -c '%d:%i:%u:%h:%f' -- "$backup/CONTROL.sha256")
fi
route_receipt_name="ROUTE-CLOSE-${route_generation_identity}.receipt"
route_preimage_name="ROUTE-CLOSE-PREIMAGE-${route_generation_identity}.jsonl"
route_receipt="$state_dir/$route_receipt_name"
route_preimage="$state_dir/$route_preimage_name"
route_preimage_pending="$state_dir/.${route_preimage_name}.pending"
route_down_authority="$script_dir/assets/20260823_rikune_root_down.sql"
if [[ "$backup_expected_successor" == "true" ]]; then
  route_down_authority="$backup/successor-authority/assets/20260823_rikune_root_down.sql"
fi

verify_database_absent() {
  local observed
  observed=$(PGAPPNAME=holdfast-rikune-rollback-db-absent "$psql_bin" "$ROUTES_DATABASE_URL" -XAtq \
    -f "$script_dir/assets/verify_rikune_root_absent.sql") || return 1
  [[ "$observed" == "ok" ]] || {
    echo "holdfast: rollback does not prove rikune-root/analyze root absence" >&2
    return 1
  }
}

verify_closed_bracket() {
  verify_database_absent
  "$public_verify" --mode closed --url https://rikune.w33d.xyz/
  "$public_verify" --mode closed --url https://analyze.w33d.xyz/
  verify_database_absent
}

validate_route_down_authority_for_execution() {
  local expected_route_down
  require_root_file "$backup/RELEASE-EVIDENCE.json"
  require_root_file "$route_down_authority"
  expected_route_down=$(jq -er \
    '.route_down_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$backup/RELEASE-EVIDENCE.json") || \
    holdfast_die "release evidence lacks a valid route-down authority"
  [[ "$expected_route_down" == "$(holdfast_sha256 "$route_down_authority")" ]] || \
    holdfast_die "route-down SQL differs from release evidence"
}

validate_route_preimage_evidence() {
  local path=$1
  require_root_file "$path"
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    jq -se '
      length >= 1 and
      (.[0] |
        type == "object" and
        keys == ["event", "row_count", "schema_version"] and
        .schema_version == 1 and
        .event == "rikune-root-rollback-predelete-summary" and
        (.row_count | type == "number" and floor == . and . >= 0)) and
      (.[0].row_count == (length - 1)) and
      all(.[1:][];
        type == "object" and
        keys == ["event", "route", "schema_version"] and
        .schema_version == 1 and
        .event == "rikune-root-rollback-predelete-row" and
        (.route | type == "object"))
    ' "$path" >/dev/null || \
      holdfast_die "schema-v3 canonical route-close preimage is incomplete or malformed"
  fi
}

execute_frozen_route_down() {
  local target status
  validate_route_down_authority_for_execution
  if [[ -e "$route_preimage" || -L "$route_preimage" ]]; then
    [[ ! -e "$route_preimage_pending" && ! -L "$route_preimage_pending" ]] || \
      holdfast_die "canonical and pending route-close preimages coexist"
    validate_route_preimage_evidence "$route_preimage"
    route_down_execution_evidence_sha=$(holdfast_sha256 "$route_preimage")
    return 0
  fi
  if [[ -e "$route_preimage_pending" || -L "$route_preimage_pending" ]]; then
    validate_route_preimage_evidence "$route_preimage_pending"
  else
    if PGAPPNAME=holdfast-rikune-close "$psql_bin" "$ROUTES_DATABASE_URL" -XAtq \
      -f "$route_down_authority" >"$route_preimage_pending" 2>&1; then
      status=0
    else
      status=$?
    fi
    chmod 0600 "$route_preimage_pending"
    if [[ $status -ne 0 ]]; then
      target="$state_dir/ROUTE-CLOSE-DOWN-FAILED-${route_generation_identity}-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
      mv -- "$route_preimage_pending" "$target"
      echo "frozen route-down failed; exact output preserved at $target" >&2
      return "$status"
    fi
    if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
      "${HOLDFAST_TEST_SIGKILL_AFTER_ROUTE_DOWN_SQL_SUCCESS:-0}" == "1" ]]; then
      kill -KILL "$$"
    fi
    validate_route_preimage_evidence "$route_preimage_pending"
  fi
  [[ ! -e "$route_preimage" && ! -L "$route_preimage" ]] || \
    holdfast_die "canonical route-close preimage appeared before durable commit"
  commit_atomic_file "$route_preimage_pending" "$route_preimage"
  validate_route_preimage_evidence "$route_preimage"
  route_down_execution_evidence_sha=$(holdfast_sha256 "$route_preimage")
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    "${HOLDFAST_TEST_SIGKILL_AFTER_ROUTE_PREIMAGE_DURABLE:-0}" == "1" ]]; then
    kill -KILL "$$"
  fi
}

validate_route_close_receipt_keys() {
  local receipt=$1 index schema
  local -a v2_expected=(
    schema_version
    route_closed_at
    source_state
    estate_root
    backup_dir
    control_sha256
    state_before_sha256
    route_down_sha256
    route_down_execution_evidence_sha256
    route_preimage_sha256
    route_conflict_cleanup
    open_evidence_sha256
    source_grant_id
    was_public_open
    preopen_edge_evidence_sha256
    route_state
    public_host
    edge_owner
    public_ipv4_ipv6_closed_status
    db_public_db_bracket
    external_edge_mutation
  )
  local -a v3_expected=(
    schema_version
    route_closed_at
    source_state
    estate_root
    backup_dir
    control_sha256
    state_before_sha256
    route_down_sha256
    route_down_execution_evidence_sha256
    open_evidence_sha256
    source_grant_id
    was_public_open
    preopen_edge_evidence_sha256
    route_preimage_sha256
    route_conflict_cleanup
    route_state
    public_host
    legacy_public_host
    legacy_route_state
    legacy_public_ipv4_ipv6_closed_status
    edge_owner
    public_ipv4_ipv6_closed_status
    db_public_db_bracket
    external_edge_mutation
  )
  local -a actual=() expected=()
  schema=$(holdfast_receipt_value "$receipt" schema_version)
  if [[ "$backup_successor_policy_version" == "4" || \
    "$backup_successor_policy_version" == "5" ]]; then
    [[ "$schema" == "3" ]] || \
      holdfast_die "advanced successor requires a schema-v3 route-close receipt"
  else
    [[ "$schema" == "2" ]] || \
      holdfast_die "legacy release requires a schema-v2 route-close receipt"
  fi
  case "$schema" in
    2) expected=("${v2_expected[@]}") ;;
    3) expected=("${v3_expected[@]}") ;;
    *) holdfast_die "route-close receipt schema is unsupported" ;;
  esac
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == *=* ]] || holdfast_die "route-close receipt contains a malformed line"
    actual+=("${line%%=*}")
  done <"$receipt"
  ((${#actual[@]} == ${#expected[@]})) || \
    holdfast_die "route-close receipt namespace differs for schema v$schema"
  for index in "${!expected[@]}"; do
    [[ "${actual[$index]}" == "${expected[$index]}" ]] || \
      holdfast_die "route-close receipt namespace differs for schema v$schema"
  done
}

v3_close_probe_files=()
declare -A v3_close_probe_hashes=() v3_close_probe_identities=()
snapshot_v3_close_route_probe_authority() {
  local file open_receipt="$state_dir/OPEN.receipt"
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  validate_v3_state_dir_identity
  v3_close_probe_files=(
    "$state_file"
    "$backup/CONTROL.sha256"
    "$route_down_authority"
    "$open_evidence"
    "$open_signature"
    "$authority_public_key"
  )
  if [[ -e "$route_receipt" || -L "$route_receipt" ]]; then
    v3_close_probe_files+=("$route_receipt")
  fi
  if [[ -e "$route_preimage" || -L "$route_preimage" ]]; then
    v3_close_probe_files+=("$route_preimage")
  fi
  if [[ -e "$open_receipt" || -L "$open_receipt" ]]; then
    v3_close_probe_files+=("$open_receipt")
  fi
  v3_close_probe_hashes=()
  v3_close_probe_identities=()
  for file in "${v3_close_probe_files[@]}"; do
    require_root_file "$file"
    v3_close_probe_hashes["$file"]=$(holdfast_sha256 "$file")
    v3_close_probe_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
  done
}

append_v3_close_route_probe_file() {
  local file=$1
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  require_root_file "$file"
  v3_close_probe_files+=("$file")
  v3_close_probe_hashes["$file"]=$(holdfast_sha256 "$file")
  v3_close_probe_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
}

validate_v3_close_route_probe_authority() {
  local file
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  validate_v3_state_dir_identity
  for file in "${v3_close_probe_files[@]}"; do
    require_root_file "$file"
    [[ "$(holdfast_sha256 "$file")" == "${v3_close_probe_hashes[$file]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
        "${v3_close_probe_identities[$file]}" ]] || \
      holdfast_die "schema-v3 close-route authority changed during external verification: $file"
  done
}

validate_route_close_receipt_for_adoption() {
  local source_state=$1 expected_public="false" expected_preopen="none" open_receipt expected
  local key value receipt_schema
  require_root_file "$route_receipt"
  require_root_file "$backup/CONTROL.sha256"
  require_root_file "$backup/RELEASE-EVIDENCE.json"
  require_root_file "$route_preimage"
  (cd "$backup" && sha256sum --check CONTROL.sha256)
  [[ "$(jq -er '.backup_dir' "$state_file")" == "$backup" ]] || \
    holdfast_die "route-close source state points to another backup"
  expected_route_down=$(jq -er '.route_down_sha256' "$backup/RELEASE-EVIDENCE.json")
  [[ "$expected_route_down" == "$(holdfast_sha256 "$route_down_authority")" ]] || \
    holdfast_die "route-down SQL differs from release evidence"
  if [[ "$source_state" == "ingress_open" ]]; then
    expected_public="true"
    open_receipt="$state_dir/OPEN.receipt"
    require_root_file "$open_receipt"
    [[ "$(jq -er '.open_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$open_receipt")" ]] || \
      holdfast_die "route-close source open receipt was replaced"
    expected_preopen=$(holdfast_receipt_value "$open_receipt" edge_evidence_sha256)
  elif [[ "$source_state" == "finalizing_route_armed" || \
    "$source_state" == "ingress_compensation_unverified" ]]; then
    expected_public="true"
    expected_preopen=$(jq -er '.open_armed_edge_evidence_sha256' "$state_file")
  fi
  receipt_schema=$(holdfast_receipt_value "$route_receipt" schema_version)
  validate_route_close_receipt_keys "$route_receipt"
  for expected in \
    "source_state=$source_state" "estate_root=$estate_root" \
    "backup_dir=$backup" "control_sha256=$(holdfast_sha256 "$backup/CONTROL.sha256")" \
    "state_before_sha256=$(holdfast_sha256 "$state_file")" \
    "route_down_sha256=$expected_route_down" \
    "route_preimage_sha256=$(holdfast_sha256 "$route_preimage")" \
    "was_public_open=$expected_public" "preopen_edge_evidence_sha256=$expected_preopen" \
    "route_state=absent" "public_ipv4_ipv6_closed_status=404" \
    "db_public_db_bracket=absent-404-absent" "external_edge_mutation=none"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$route_receipt" "$key")" == "$value" ]] || \
      holdfast_die "route-close adoption receipt differs: $key"
  done
  case "$receipt_schema" in
    2)
      for expected in \
        "route_conflict_cleanup=same-name-or-analyze-root" \
        "public_host=analyze.w33d.xyz"; do
        key=${expected%%=*}
        value=${expected#*=}
        [[ "$(holdfast_receipt_value "$route_receipt" "$key")" == "$value" ]] || \
          holdfast_die "schema-v2 route-close adoption receipt differs: $key"
      done
      ;;
    3)
      for expected in \
        "route_conflict_cleanup=same-name-or-rikune-root-or-analyze-host" \
        "public_host=rikune.w33d.xyz" \
        "legacy_public_host=analyze.w33d.xyz" \
        "legacy_route_state=absent" \
        "legacy_public_ipv4_ipv6_closed_status=404"; do
        key=${expected%%=*}
        value=${expected#*=}
        [[ "$(holdfast_receipt_value "$route_receipt" "$key")" == "$value" ]] || \
          holdfast_die "schema-v3 route-close adoption receipt differs: $key"
      done
      ;;
  esac
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    [[ "$(holdfast_receipt_value "$route_receipt" route_down_execution_evidence_sha256)" == \
      "$(holdfast_sha256 "$route_preimage")" ]] || \
      holdfast_die "schema-v3 route-close execution evidence differs from its preimage"
  else
    [[ "$(holdfast_receipt_value "$route_receipt" route_down_execution_evidence_sha256)" \
      =~ ^[0-9a-f]{64}$ ]] || holdfast_die "route-close execution evidence identity is invalid"
  fi
  load_successor_authority "$state_file"
}

commit_route_closed_state() {
  local state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg close "$route_receipt_name" \
    --arg close_sha "$(holdfast_sha256 "$route_receipt")" \
    --arg preimage "$route_preimage_name" \
    --arg preimage_sha "$(holdfast_sha256 "$route_preimage")" \
    '.state="route_closed_awaiting_revocation" |
     .route_close_receipt=$close | .route_close_receipt_sha256=$close_sha |
     .route_close_preimage=$preimage | .route_close_preimage_sha256=$preimage_sha |
     .ingress_opened=false' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"
}

validate_backup_and_open_authority() {
  local release_validator_args=(--evidence "$backup/RELEASE-EVIDENCE.json")
  local rollback_successor_policy
  [[ "$(jq -er '.backup_dir' "$state_file")" == "$backup" ]] || holdfast_die "state points to another backup"
  require_canonical_root_dir "$backup/estate"
  require_canonical_root_dir "$backup/estate/tree"
  require_canonical_root_dir "$backup/runtime"
  for file in "$backup/CONTROL.sha256" "$backup/RELEASE-EVIDENCE.json" "$backup/release.env" \
    "$backup/DRY-RUN.receipt" "$backup/rollback.override.yml" \
    "$backup/TARGETS.sha256" "$backup/APPLY-PREIMAGES.sha256" "$backup/APPLY-ABSENT.paths" \
    "$backup/estate/APPLIED-TARGETS.sha256" "$backup/estate/PREIMAGES.sha256" \
    "$backup/estate/ABSENT.before" "$backup/estate/TRANSACTION.json" \
    "$backup/runtime/BACKUP.receipt" "$backup/runtime/SHA256SUMS" \
    "$backup/runtime/compose-config.json" "$backup/runtime/RUNNING-SERVICES.before"; do
    require_root_file "$file"
  done
  [[ -z "$(find "$backup" -xdev -type l -print -quit)" ]] || holdfast_die "backup contains a symlink"
  [[ -z "$(find "$backup" -xdev ! -user root -print -quit)" ]] || holdfast_die "backup contains a non-root-owned entry"
  (cd "$backup" && sha256sum --check CONTROL.sha256)
  if jq -e '.schema_version == 2 and .release_mode == "successor"' \
    "$backup/RELEASE-EVIDENCE.json" >/dev/null; then
    rollback_successor_policy="$backup/successor-authority/successor-policy.json"
    require_root_file "$rollback_successor_policy"
    grep -Fqx "$(holdfast_sha256 "$rollback_successor_policy")  successor-authority/successor-policy.json" \
      "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits its frozen release policy"
    release_validator_args+=(--successor-policy "$rollback_successor_policy")
  fi
  run_python_tool "$release_validator" "$script_dir/validate_release_evidence.py" \
    "${release_validator_args[@]}"
  expected_route_down=$(jq -er '.route_down_sha256' "$backup/RELEASE-EVIDENCE.json")
  [[ "$expected_route_down" == "$(holdfast_sha256 "$route_down_authority")" ]] || \
    holdfast_die "route-down SQL differs from release evidence"
  run_python_tool "$authority_tool" "$script_dir/authority_evidence.py" --mode open \
    --evidence "$open_evidence" --signature "$open_signature" --public-key "$authority_public_key" \
    --release-env "$backup/release.env" --release-evidence "$backup/RELEASE-EVIDENCE.json" \
    --dry-run-receipt "$backup/DRY-RUN.receipt"
  load_successor_authority "$state_file"
}

release_services=(
  access-governance verdict newapi rikune-analyzer strad sluice sluice-internal
)
runtime_prior_services=()
rollback_running_services=()
restart_services=()

service_release_index() {
  case "$1" in
    access-governance) printf '0\n' ;;
    verdict) printf '1\n' ;;
    newapi) printf '2\n' ;;
    rikune-analyzer) printf '3\n' ;;
    strad) printf '4\n' ;;
    sluice) printf '5\n' ;;
    sluice-internal) printf '6\n' ;;
    *) return 1 ;;
  esac
}

validate_runtime_prior_services() {
  local manifest="$backup/runtime/RUNNING-SERVICES.before"
  local checksum_line checksum_file service index previous=-1
  runtime_prior_services=()
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" schema_version)" == "2" ]] || \
    holdfast_die "rollback requires a schema-v2 runtime backup"
  for expected in \
    "postgres_database=strad" "database_identity=postgres:5432/strad" \
    "runtime_writers=strad,rikune-analyzer,rikune-volume-init" \
    "runtime_writers_stopped=passed" \
    "prior_running_services_manifest=RUNNING-SERVICES.before"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup contract differs: $key"
  done
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" prior_running_services_sha256)" == \
    "$(holdfast_sha256 "$manifest")" ]] || holdfast_die "runtime prior-running manifest was replaced"
  while IFS= read -r checksum_line; do
    [[ "$checksum_line" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]] || \
      holdfast_die "runtime SHA256SUMS contains an invalid line"
    checksum_file=${BASH_REMATCH[1]}
    [[ "$checksum_file" != "RUNNING-SERVICES.before" || \
      "$checksum_line" == "$(holdfast_sha256 "$manifest")  RUNNING-SERVICES.before" ]] || \
      holdfast_die "runtime SHA256SUMS does not bind the prior-running manifest"
  done <"$backup/runtime/SHA256SUMS"
  grep -Fqx "$(holdfast_sha256 "$manifest")  RUNNING-SERVICES.before" \
    "$backup/runtime/SHA256SUMS" || holdfast_die "runtime SHA256SUMS omits the prior-running manifest"
  (cd "$backup/runtime" && sha256sum --check SHA256SUMS)
  while IFS= read -r service || [[ -n "$service" ]]; do
    [[ -n "$service" ]] || holdfast_die "runtime prior-running manifest contains a blank service"
    index=-1
    case "$service" in
      strad) index=0 ;;
      rikune-analyzer) index=1 ;;
      *) holdfast_die "runtime prior-running manifest contains an unknown service: $service" ;;
    esac
    ((index > previous)) || holdfast_die "runtime prior-running manifest is duplicated or out of order"
    previous=$index
    runtime_prior_services+=("$service")
  done <"$manifest"
}

service_container_ids() {
  local service=$1
  "$docker_bin" ps -aq \
    --filter "label=com.docker.compose.project=$compose_project" \
    --filter "label=com.docker.compose.service=$service"
}

validate_rollback_running_manifest() {
  local manifest=$1 service index previous=-1
  rollback_running_services=()
  require_root_file "$manifest"
  while IFS= read -r service || [[ -n "$service" ]]; do
    [[ -n "$service" ]] || holdfast_die "rollback running-service manifest contains a blank service"
    index=$(service_release_index "$service") || \
      holdfast_die "rollback running-service manifest contains an unknown service: $service"
    ((index > previous)) || holdfast_die "rollback running-service manifest is duplicated or out of order"
    previous=$index
    rollback_running_services+=("$service")
  done <"$manifest"
}

capture_rollback_running_manifest() {
  local target=$1 temporary=$2 service output state
  local ids=()
  [[ ! -e "$target" && ! -L "$target" && ! -e "$temporary" && ! -L "$temporary" ]] || \
    holdfast_die "rollback running-service manifest path already exists"
  : >"$temporary"
  for service in "${release_services[@]}"; do
    output=$(service_container_ids "$service") || \
      holdfast_die "could not inspect release service before rollback: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple containers exist for release service: $service"
    if ((${#ids[@]} == 0)); then continue; fi
    state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}")
    case "$state" in
      running) printf '%s\n' "$service" >>"$temporary" ;;
      created|exited|dead) ;;
      *) holdfast_die "release service has an unstable pre-rollback state: $service=$state" ;;
    esac
  done
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    chmod 0600 "$temporary"
    validate_rollback_running_manifest "$temporary"
  else
    commit_atomic_file "$temporary" "$target"
    validate_rollback_running_manifest "$target"
  fi
}

rollback_service_was_running() {
  local wanted=$1 service
  for service in "${rollback_running_services[@]}"; do
    [[ "$service" == "$wanted" ]] && return 0
  done
  return 1
}

runtime_service_was_running() {
  local wanted=$1 service
  for service in "${runtime_prior_services[@]}"; do
    [[ "$service" == "$wanted" ]] && return 0
  done
  return 1
}

quiesce_release_services() {
  local service output state
  local ids=()
  for service in "${release_services[@]}"; do
    output=$(service_container_ids "$service") || holdfast_die "could not inspect release service before stop: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple containers exist before release-service stop: $service"
    if ((${#ids[@]})); then "$docker_bin" stop -t 120 "${ids[0]}" >/dev/null; fi
  done
  for service in "${release_services[@]}"; do
    output=$(service_container_ids "$service") || holdfast_die "could not inspect release service after stop: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple containers exist after release-service stop: $service"
    for container_id in "${ids[@]}"; do
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
      [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
        holdfast_die "release service remains active after rollback quiesce: $service"
    done
  done
}

validate_runtime_restore_receipt() {
  local receipt="$backup/runtime/RESTORE.receipt"
  require_root_file "$receipt"
  for expected in \
    "schema_version=2" "restore_mode=schema-v2" \
    "database_identity=postgres:5432/strad" "database_restore=restored" \
    "runtime_writers_removed=passed" "volume_mount_release=passed" "volume_count=6"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime restore receipt differs: $key"
  done
}

validate_estate_restore_manifests() {
  cmp -s -- "$backup/TARGETS.sha256" "$backup/estate/APPLIED-TARGETS.sha256" || \
    holdfast_die "estate applied-target authority differs from CONTROL targets"
  cmp -s -- "$backup/APPLY-PREIMAGES.sha256" "$backup/estate/PREIMAGES.sha256" || \
    holdfast_die "estate preimage authority differs from CONTROL preimages"
  cmp -s -- "$backup/APPLY-ABSENT.paths" "$backup/estate/ABSENT.before" || \
    holdfast_die "estate absent authority differs from CONTROL absent dispositions"
}

verify_estate_disposition() {
  local mode=$1
  python3 - "$mode" "$estate_root" "$backup/TARGETS.sha256" \
    "$backup/APPLY-PREIMAGES.sha256" "$backup/APPLY-ABSENT.paths" \
    "$backup/estate/tree" <<'PY'
import hashlib
import re
import stat
import sys
from pathlib import Path

mode, estate_arg, targets_arg, preimages_arg, absent_arg, tree_arg = sys.argv[1:]
estate = Path(estate_arg)
tree = Path(tree_arg)
manifest_re = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$")
path_re = re.compile(r"^[A-Za-z0-9._/-]+$")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def safe_relative(value: str) -> bool:
    parts = Path(value).parts
    return bool(value) and not value.startswith("/") and ".." not in parts


def parse_manifest(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = manifest_re.fullmatch(line)
        if match is None or not safe_relative(match.group(2)):
            raise RuntimeError(f"unsafe rollback manifest line: {path}")
        relative = match.group(2)
        if relative in result:
            raise RuntimeError(f"duplicate rollback manifest path: {relative}")
        result[relative] = match.group(1)
    return result


def parse_absent(path: Path) -> set[str]:
    result: set[str] = set()
    for relative in path.read_text(encoding="utf-8").splitlines():
        if not path_re.fullmatch(relative) or not safe_relative(relative) or relative in result:
            raise RuntimeError(f"unsafe rollback absent path: {relative}")
        result.add(relative)
    return result


def regular_digest(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1 or info.st_uid != 0:
        raise RuntimeError(f"unsafe rollback file: {path}")
    return digest(path)


def validate_parent_chain(relative: str) -> None:
    current = estate
    for component in Path(relative).parts[:-1]:
        current /= component
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or current.is_symlink() or info.st_uid != 0:
            raise RuntimeError(f"unsafe rollback target parent: {relative}")


targets = parse_manifest(Path(targets_arg))
preimages = parse_manifest(Path(preimages_arg))
absent = parse_absent(Path(absent_arg))
if set(targets) != set(preimages) | absent or set(preimages) & absent:
    raise RuntimeError("rollback dispositions do not exactly cover CONTROL targets")
for relative, expected in preimages.items():
    if regular_digest(tree / relative) != expected:
        raise RuntimeError(f"rollback tree checksum mismatch: {relative}")
for relative, applied_digest in targets.items():
    validate_parent_chain(relative)
    observed = regular_digest(estate / relative)
    if mode == "applied":
        allowed = {applied_digest}
    elif mode == "mixed":
        allowed = {applied_digest, preimages.get(relative)} if relative in preimages else {applied_digest, None}
    elif mode == "preimage":
        allowed = {preimages[relative]} if relative in preimages else {None}
    else:
        raise RuntimeError(f"unknown rollback disposition mode: {mode}")
    if observed not in allowed:
        raise RuntimeError(f"live rollback disposition drift: {relative}")
PY
}

validate_v3_rollback_prearm_mutation_authority() {
  local file
  local -a fence_files=()
  local -A fence_hashes=() fence_identities=()
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  validate_v3_cached_control_authority
  fence_files=(
    "$state_file"
    "$backup/CONTROL.sha256"
    "$route_receipt"
    "$route_preimage"
    "$backup/estate/TRANSACTION.json"
    "$backup/estate/APPLIED-TARGETS.sha256"
    "$backup/estate/PREIMAGES.sha256"
    "$backup/estate/ABSENT.before"
    "$backup/runtime/BACKUP.receipt"
    "$backup/runtime/SHA256SUMS"
    "$backup/runtime/RUNNING-SERVICES.before"
    "$backup/runtime/compose-config.json"
  )
  for file in "${fence_files[@]}"; do
    require_root_file "$file"
    fence_hashes["$file"]=$(holdfast_sha256 "$file")
    fence_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
  done
  validate_runtime_prior_services
  validate_estate_restore_manifests
  require_root_file "$backup/estate/TRANSACTION.json"
  [[ "$(holdfast_sha256 "$backup/CONTROL.sha256")" == "$control_sha" && \
    "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" == "$original_transaction_sha" && \
    "$(jq -er '.schema_version == 1 and .state == "applied"' \
      "$backup/estate/TRANSACTION.json")" == "true" && \
    "$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")" == \
      "$applied_targets_sha" ]] || \
    holdfast_die "schema-v3 rollback nested authority changed before arm mutation"
  verify_estate_disposition applied
  for file in "${fence_files[@]}"; do
    require_root_file "$file"
    [[ "$(holdfast_sha256 "$file")" == "${fence_hashes[$file]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
        "${fence_identities[$file]}" ]] || \
      holdfast_die "schema-v3 rollback authority changed during pre-arm validation: $file"
  done
  validate_v3_cached_control_authority
}

v3_execute_entry_files=()
declare -A v3_execute_entry_hashes=() v3_execute_entry_identities=()
snapshot_v3_execute_entry_authority() {
  local file
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  validate_v3_state_dir_identity
  v3_execute_entry_files=(
    "$state_file"
    "$backup/CONTROL.sha256"
    "$route_receipt"
    "$route_preimage"
  )
  v3_execute_entry_hashes=()
  v3_execute_entry_identities=()
  for file in "${v3_execute_entry_files[@]}"; do
    require_root_file "$file"
    v3_execute_entry_hashes["$file"]=$(holdfast_sha256 "$file")
    v3_execute_entry_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
  done
}

validate_v3_execute_entry_authority() {
  local file
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  validate_v3_state_dir_identity
  for file in "${v3_execute_entry_files[@]}"; do
    require_root_file "$file"
    [[ "$(holdfast_sha256 "$file")" == "${v3_execute_entry_hashes[$file]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
        "${v3_execute_entry_identities[$file]}" ]] || \
      holdfast_die "schema-v3 rollback execute authority changed during external verification: $file"
  done
  validate_v3_cached_control_authority
}

v3_rollback_prearm_files=()
declare -A v3_rollback_prearm_hashes=() v3_rollback_prearm_identities=()
v3_frozen_rollback_authority_files=()
declare -A v3_frozen_rollback_authority_hashes=() \
  v3_frozen_rollback_authority_identities=()

snapshot_v3_frozen_rollback_authorities() {
  local file
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  v3_frozen_rollback_authority_files=(
    "$open_evidence"
    "$open_signature"
    "$authority_public_key"
    "$revocation_evidence"
    "$revocation_signature"
  )
  if [[ "$frozen_edge_evidence_name" != "none" ]]; then
    v3_frozen_rollback_authority_files+=(
      "$edge_rollback_evidence"
      "$edge_rollback_signature"
      "$open_edge_evidence"
    )
  fi
  v3_frozen_rollback_authority_hashes=()
  v3_frozen_rollback_authority_identities=()
  for file in "${v3_frozen_rollback_authority_files[@]}"; do
    require_root_file "$file"
    v3_frozen_rollback_authority_hashes["$file"]=$(holdfast_sha256 "$file")
    v3_frozen_rollback_authority_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- \
      "$file")
  done
}

validate_v3_frozen_rollback_authorities() {
  local file
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  for file in "${v3_frozen_rollback_authority_files[@]}"; do
    require_root_file "$file"
    [[ "$(holdfast_sha256 "$file")" == \
        "${v3_frozen_rollback_authority_hashes[$file]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
        "${v3_frozen_rollback_authority_identities[$file]}" ]] || \
      holdfast_die "schema-v3 frozen rollback authority changed during external validation: $file"
  done
}

snapshot_v3_rollback_prearm_files() {
  local file
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  v3_rollback_prearm_files=(
    "$route_receipt"
    "$route_preimage"
    "$rollback_manifest"
    "$open_evidence"
    "$open_signature"
    "$authority_public_key"
    "$revocation_evidence"
    "$revocation_signature"
  )
  if [[ "$frozen_edge_evidence_name" != "none" ]]; then
    v3_rollback_prearm_files+=(
      "$edge_rollback_evidence"
      "$edge_rollback_signature"
      "$open_edge_evidence"
    )
  fi
  v3_rollback_prearm_hashes=()
  v3_rollback_prearm_identities=()
  for file in "${v3_rollback_prearm_files[@]}"; do
    require_root_file "$file"
    v3_rollback_prearm_hashes["$file"]=$(holdfast_sha256 "$file")
    v3_rollback_prearm_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
  done
}

validate_v3_rollback_prearm_files() {
  local file
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  for file in "${v3_rollback_prearm_files[@]}"; do
    require_root_file "$file"
    [[ "$(holdfast_sha256 "$file")" == "${v3_rollback_prearm_hashes[$file]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
        "${v3_rollback_prearm_identities[$file]}" ]] || \
      holdfast_die "schema-v3 rollback pre-arm authority changed during validation: $file"
  done
}

v3_phase_fence_files=()
declare -A v3_phase_fence_hashes=() v3_phase_fence_identities=()
snapshot_v3_phase_fence() {
  local file phase_receipt
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  validate_v3_state_dir_identity
  v3_phase_fence_files=(
    "$state_file"
    "$backup/CONTROL.sha256"
    "$rollback_armed_receipt"
    "$rollback_manifest"
    "$route_receipt"
    "$route_preimage"
    "$open_evidence"
    "$open_signature"
    "$authority_public_key"
    "$revocation_evidence"
    "$revocation_signature"
  )
  if [[ "$frozen_edge_evidence_name" != "none" ]]; then
    v3_phase_fence_files+=(
      "$edge_rollback_evidence"
      "$edge_rollback_signature"
      "$open_edge_evidence"
    )
  fi
  for phase_receipt in "${runtime_phase_name:-}" "${estate_phase_name:-}" \
    "${services_phase_name:-}"; do
    [[ -n "$phase_receipt" ]] || continue
    file="$state_dir/$phase_receipt"
    if [[ -e "$file" || -L "$file" ]]; then v3_phase_fence_files+=("$file"); fi
  done
  if [[ -e "$backup/runtime/RESTORE.receipt" || -L "$backup/runtime/RESTORE.receipt" ]]; then
    v3_phase_fence_files+=("$backup/runtime/RESTORE.receipt")
  fi
  v3_phase_fence_hashes=()
  v3_phase_fence_identities=()
  for file in "${v3_phase_fence_files[@]}"; do
    require_root_file "$file"
    v3_phase_fence_hashes["$file"]=$(holdfast_sha256 "$file")
    v3_phase_fence_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
  done
}

append_v3_phase_fence_file() {
  local file=$1
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  require_root_file "$file"
  if [[ -n "${v3_phase_fence_hashes["$file"]+x}" ]]; then
    [[ "$(holdfast_sha256 "$file")" == "${v3_phase_fence_hashes[$file]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
        "${v3_phase_fence_identities[$file]}" ]] || \
      holdfast_die "schema-v3 rollback phase authority changed before adoption: $file"
    return 0
  fi
  v3_phase_fence_files+=("$file")
  v3_phase_fence_hashes["$file"]=$(holdfast_sha256 "$file")
  v3_phase_fence_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
}

validate_v3_phase_fence() {
  local file
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  validate_v3_state_dir_identity
  for file in "${v3_phase_fence_files[@]}"; do
    require_root_file "$file"
    [[ "$(holdfast_sha256 "$file")" == "${v3_phase_fence_hashes[$file]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
        "${v3_phase_fence_identities[$file]}" ]] || \
      holdfast_die "schema-v3 rollback phase authority changed during external verification: $file"
  done
  validate_v3_cached_control_authority
  (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
}

load_restored_compose_services() {
  local config_temp=$1 service
  restored_compose_services=()
  declare -gA restored_compose_has=()
  rollback_compose=(
    "$docker_bin" compose --env-file "$estate_root/deploy/.env"
    -f "$estate_root/deploy/docker-compose.yml" -f "$backup/rollback.override.yml"
  )
  "${rollback_compose[@]}" config --format json >"$config_temp"
  [[ "$(jq -er '.name' "$config_temp")" == "$compose_project" ]] || \
    holdfast_die "restored Compose project identity differs"
  mapfile -t restored_compose_services < <(jq -er '.services | keys[]' "$config_temp")
  for service in "${restored_compose_services[@]}"; do
    [[ "$service" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || holdfast_die "restored Compose contains an unsafe service name"
    [[ -z "${restored_compose_has[$service]:-}" ]] || holdfast_die "restored Compose repeats a service"
    restored_compose_has[$service]=1
  done
}

compute_restart_services() {
  local service
  restart_services=()
  for service in "${release_services[@]}"; do
    case "$service" in
      strad|rikune-analyzer)
        runtime_service_was_running "$service" || continue
        ;;
      *)
        rollback_service_was_running "$service" || continue
        ;;
    esac
    [[ "${restored_compose_has[$service]:-0}" == "1" ]] || continue
    restart_services+=("$service")
  done
}

service_is_restart_target() {
  local wanted=$1 service
  for service in "${restart_services[@]}"; do
    [[ "$service" == "$wanted" ]] && return 0
  done
  return 1
}

verify_restarted_and_excluded_services() {
  local service output state health
  local ids=()
  for service in "${restart_services[@]}"; do
    output=$(service_container_ids "$service") || holdfast_die "could not inspect reactivated service: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} == 1)) || holdfast_die "reactivated service container identity differs: $service"
    state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}")
    [[ "$state" == "running" ]] || holdfast_die "reactivated service is not running: $service=$state"
    health=$("$docker_bin" inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${ids[0]}")
    [[ "$health" == "none" || "$health" == "healthy" ]] || \
      holdfast_die "reactivated service is not healthy: $service=$health"
  done
  for service in "${release_services[@]}"; do
    service_is_restart_target "$service" && continue
    output=$(service_container_ids "$service") || holdfast_die "could not inspect service excluded from rollback activation: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple excluded service containers exist: $service"
    for container_id in "${ids[@]}"; do
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
      [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
        holdfast_die "service excluded from rollback activation became active: $service"
    done
  done
}

join_services() {
  local IFS=,
  printf '%s' "$*"
}

validate_rollback_arm() {
  local expected key value
  [[ "$(jq -er '.estate_root' "$state_file")" == "$estate_root" ]] || \
    holdfast_die "rollback state points to another estate"
  [[ "$(jq -er '.backup_dir' "$state_file")" == "$backup" ]] || \
    holdfast_die "rollback state points to another backup"
  original_transaction_sha=$(jq -er '.transaction_sha256' "$state_file")
  [[ "$original_transaction_sha" =~ ^[0-9a-f]{64}$ ]] || \
    holdfast_die "rollback state transaction identity is invalid"
  applied_targets_sha=$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")
  [[ "$(jq -er '.applied_targets_sha256' "$state_file")" == "$applied_targets_sha" ]] || \
    holdfast_die "rollback state applied-target authority was replaced"
  attempt_id=$(jq -er '.rollback_attempt_id' "$state_file")
  [[ "$attempt_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || holdfast_die "rollback attempt identity is unsafe"
  rollback_manifest_name=$(jq -er '.rollback_running_services_manifest' "$state_file")
  [[ "$rollback_manifest_name" == "ROLLBACK-RUNNING-SERVICES-${attempt_id}.before" ]] || \
    holdfast_die "rollback running-service manifest name differs"
  rollback_manifest="$state_dir/$rollback_manifest_name"
  require_root_file "$rollback_manifest"
  rollback_manifest_sha=$(holdfast_sha256 "$rollback_manifest")
  [[ "$(jq -er '.rollback_running_services_sha256' "$state_file")" == "$rollback_manifest_sha" ]] || \
    holdfast_die "rollback running-service manifest was replaced"
  validate_rollback_running_manifest "$rollback_manifest"

  rollback_armed_name=$(jq -er '.rollback_armed_receipt' "$state_file")
  [[ "$rollback_armed_name" == "ROLLBACK-EXECUTE-ARMED-${attempt_id}.receipt" ]] || \
    holdfast_die "rollback armed receipt name differs"
  rollback_armed_receipt="$state_dir/$rollback_armed_name"
  require_root_file "$rollback_armed_receipt"
  rollback_armed_sha=$(holdfast_sha256 "$rollback_armed_receipt")
  [[ "$(jq -er '.rollback_armed_receipt_sha256' "$state_file")" == "$rollback_armed_sha" ]] || \
    holdfast_die "rollback armed receipt was replaced"
  for expected in \
    "schema_version=2" "attempt_id=$attempt_id" "estate_root=$estate_root" \
    "backup_dir=$backup" "control_sha256=$control_sha" \
    "transaction_sha256=$original_transaction_sha" \
    "applied_targets_sha256=$applied_targets_sha" \
    "targets_sha256=$(holdfast_sha256 "$backup/TARGETS.sha256")" \
    "apply_preimages_sha256=$(holdfast_sha256 "$backup/APPLY-PREIMAGES.sha256")" \
    "apply_absent_sha256=$(holdfast_sha256 "$backup/APPLY-ABSENT.paths")" \
    "route_close_receipt=$route_receipt_name" \
    "route_close_receipt_sha256=$(holdfast_sha256 "$route_receipt")" \
    "route_close_preimage=$route_preimage_name" \
    "route_close_preimage_sha256=$(holdfast_sha256 "$route_preimage")" \
    "open_evidence_file=$frozen_open_evidence_name" \
    "open_evidence_sha256=$(holdfast_sha256 "$open_evidence")" \
    "open_signature_file=$frozen_open_signature_name" \
    "open_signature_sha256=$(holdfast_sha256 "$open_signature")" \
    "authority_public_key_file=$frozen_public_key_name" \
    "authority_public_key_sha256=$(holdfast_sha256 "$authority_public_key")" \
    "revocation_evidence_file=$frozen_revocation_evidence_name" \
    "revocation_evidence_sha256=$(holdfast_sha256 "$revocation_evidence")" \
    "revocation_signature_file=$frozen_revocation_signature_name" \
    "revocation_signature_sha256=$(holdfast_sha256 "$revocation_signature")" \
    "edge_rollback_evidence_file=$frozen_edge_evidence_name" \
    "edge_rollback_evidence_sha256=$edge_rollback_sha" \
    "edge_rollback_signature_file=$frozen_edge_signature_name" \
    "edge_rollback_signature_sha256=$edge_rollback_signature_sha" \
    "open_edge_evidence_file=$frozen_open_edge_name" \
    "open_edge_evidence_sha256=$open_edge_sha" \
    "compose_project=$compose_project" \
    "release_services=access-governance,verdict,newapi,rikune-analyzer,strad,sluice,sluice-internal" \
    "running_services_manifest=$rollback_manifest_name" \
    "running_services_sha256=$rollback_manifest_sha" \
    "runtime_prior_services_sha256=$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")" \
    "activation_policy=restore-exact-prior-running" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$rollback_armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "rollback armed authority differs: $key"
  done
  validate_successor_lineage_receipt "$rollback_armed_receipt"
}

validate_runtime_restore_phase_receipt() {
  local receipt="$state_dir/$runtime_phase_name" expected key value
  require_root_file "$receipt"
  for expected in \
    "schema_version=2" "phase=runtime_restore_done" "attempt_id=$attempt_id" \
    "rollback_armed_receipt_sha256=$rollback_armed_sha" \
    "runtime_restore_receipt_sha256=$(holdfast_sha256 "$backup/runtime/RESTORE.receipt")" \
    "runtime_backup_receipt_sha256=$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")" \
    "runtime_backup_manifest_sha256=$(holdfast_sha256 "$backup/runtime/SHA256SUMS")" \
    "transaction_before_sha256=$original_transaction_sha" \
    "applied_targets_sha256=$applied_targets_sha" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime-restore phase receipt differs: $key"
  done
  runtime_phase_sha=$(holdfast_sha256 "$receipt")
}

validate_phase_state_binding() {
  local name_field=$1 sha_field=$2 expected_name=$3 expected_sha=$4
  [[ "$(jq -er --arg field "$name_field" '.[$field]' "$state_file")" == "$expected_name" ]] || \
    holdfast_die "rollback phase state points to another receipt: $name_field"
  [[ "$(jq -er --arg field "$sha_field" '.[$field]' "$state_file")" == "$expected_sha" ]] || \
    holdfast_die "rollback phase state receipt was replaced: $sha_field"
}

persist_runtime_restore_phase() {
  local receipt="$state_dir/$runtime_phase_name" temporary state_tmp
  if [[ -e "$receipt" || -L "$receipt" ]]; then
    validate_runtime_restore_phase_receipt
  else
    temporary="$state_dir/.${runtime_phase_name}.$$"
    {
      printf 'schema_version=2\n'
      printf 'phase=runtime_restore_done\n'
      printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'attempt_id=%s\n' "$attempt_id"
      printf 'rollback_armed_receipt_sha256=%s\n' "$rollback_armed_sha"
      printf 'runtime_restore_receipt_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/RESTORE.receipt")"
      printf 'runtime_backup_receipt_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")"
      printf 'runtime_backup_manifest_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/SHA256SUMS")"
      printf 'transaction_before_sha256=%s\n' "$original_transaction_sha"
      printf 'applied_targets_sha256=%s\n' "$applied_targets_sha"
      printf 'ingress_opened=false\n'
    } >"$temporary"
    commit_atomic_file "$temporary" "$receipt"
    validate_runtime_restore_phase_receipt
  fi
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    append_v3_phase_fence_file "$receipt"
    validate_v3_phase_fence
  fi
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg name "$runtime_phase_name" --arg sha "$runtime_phase_sha" \
    '.state="rollback_runtime_restore_done" | .rollback_runtime_restore_phase_receipt=$name | .rollback_runtime_restore_phase_receipt_sha256=$sha | .ingress_opened=false' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"
  current_state="rollback_runtime_restore_done"
}

validate_estate_restore_phase_receipt() {
  local receipt="$state_dir/$estate_phase_name" expected key value
  require_root_file "$receipt"
  for expected in \
    "schema_version=2" "phase=estate_restore_done" "attempt_id=$attempt_id" \
    "rollback_armed_receipt_sha256=$rollback_armed_sha" \
    "runtime_restore_phase_receipt_sha256=$runtime_phase_sha" \
    "estate_transaction_sha256=$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" \
    "applied_targets_sha256=$applied_targets_sha" \
    "preimages_sha256=$(holdfast_sha256 "$backup/estate/PREIMAGES.sha256")" \
    "absent_sha256=$(holdfast_sha256 "$backup/estate/ABSENT.before")" \
    "live_estate_disposition=preimage" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "estate-restore phase receipt differs: $key"
  done
  estate_phase_sha=$(holdfast_sha256 "$receipt")
}

persist_estate_restore_phase() {
  local receipt="$state_dir/$estate_phase_name" temporary state_tmp restored_transaction_sha
  restored_transaction_sha=$(holdfast_sha256 "$backup/estate/TRANSACTION.json")
  if [[ -e "$receipt" || -L "$receipt" ]]; then
    validate_estate_restore_phase_receipt
  else
    temporary="$state_dir/.${estate_phase_name}.$$"
    {
      printf 'schema_version=2\n'
      printf 'phase=estate_restore_done\n'
      printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'attempt_id=%s\n' "$attempt_id"
      printf 'rollback_armed_receipt_sha256=%s\n' "$rollback_armed_sha"
      printf 'runtime_restore_phase_receipt_sha256=%s\n' "$runtime_phase_sha"
      printf 'estate_transaction_sha256=%s\n' "$restored_transaction_sha"
      printf 'applied_targets_sha256=%s\n' "$applied_targets_sha"
      printf 'preimages_sha256=%s\n' "$(holdfast_sha256 "$backup/estate/PREIMAGES.sha256")"
      printf 'absent_sha256=%s\n' "$(holdfast_sha256 "$backup/estate/ABSENT.before")"
      printf 'live_estate_disposition=preimage\n'
      printf 'ingress_opened=false\n'
    } >"$temporary"
    commit_atomic_file "$temporary" "$receipt"
    validate_estate_restore_phase_receipt
  fi
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    append_v3_phase_fence_file "$receipt"
    validate_v3_phase_fence
  fi
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg name "$estate_phase_name" --arg sha "$estate_phase_sha" \
    --arg transaction_sha "$restored_transaction_sha" \
    '.state="rollback_estate_restore_done" | .rollback_estate_restore_phase_receipt=$name | .rollback_estate_restore_phase_receipt_sha256=$sha | .rollback_estate_transaction_sha256=$transaction_sha | .ingress_opened=false' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"
  current_state="rollback_estate_restore_done"
}

load_exact_restart_authority() {
  local config_temp
  config_temp=$(mktemp "${TMPDIR:-/var/tmp}/holdfast-rollback-compose.XXXXXX")
  load_restored_compose_services "$config_temp"
  rm -f -- "$config_temp"
  compute_restart_services
  expected_reactivated_services="none"
  if ((${#restart_services[@]})); then
    expected_reactivated_services=$(join_services "${restart_services[@]}")
  fi
}

validate_services_reactivated_phase_receipt() {
  local receipt="$state_dir/$services_phase_name" expected key value
  require_root_file "$receipt"
  load_exact_restart_authority
  for expected in \
    "schema_version=2" "phase=services_reactivated_done" "attempt_id=$attempt_id" \
    "rollback_armed_receipt_sha256=$rollback_armed_sha" \
    "estate_restore_phase_receipt_sha256=$estate_phase_sha" \
    "reactivated_services=$expected_reactivated_services" \
    "excluded_services_inactive=passed" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "service-reactivation phase receipt differs: $key"
  done
  verify_restarted_and_excluded_services
  services_phase_sha=$(holdfast_sha256 "$receipt")
}

persist_services_reactivated_phase() {
  local receipt="$state_dir/$services_phase_name" temporary state_tmp
  if [[ -e "$receipt" || -L "$receipt" ]]; then
    validate_services_reactivated_phase_receipt
  else
    temporary="$state_dir/.${services_phase_name}.$$"
    {
      printf 'schema_version=2\n'
      printf 'phase=services_reactivated_done\n'
      printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'attempt_id=%s\n' "$attempt_id"
      printf 'rollback_armed_receipt_sha256=%s\n' "$rollback_armed_sha"
      printf 'estate_restore_phase_receipt_sha256=%s\n' "$estate_phase_sha"
      printf 'reactivated_services=%s\n' "$expected_reactivated_services"
      printf 'excluded_services_inactive=passed\n'
      printf 'ingress_opened=false\n'
    } >"$temporary"
    commit_atomic_file "$temporary" "$receipt"
    validate_services_reactivated_phase_receipt
  fi
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    append_v3_phase_fence_file "$receipt"
    validate_v3_phase_fence
  fi
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg name "$services_phase_name" --arg sha "$services_phase_sha" \
    '.state="rollback_services_reactivated_done" | .rollback_services_reactivated_phase_receipt=$name | .rollback_services_reactivated_phase_receipt_sha256=$sha | .ingress_opened=false' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"
  current_state="rollback_services_reactivated_done"
}

verify_fresh_running_snapshot() {
  local service output state expected="false"
  local ids=()
  for service in "${release_services[@]}"; do
    rollback_service_was_running "$service" && expected="true" || expected="false"
    output=$(service_container_ids "$service") || holdfast_die "could not revalidate release service before rollback: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple containers appeared before rollback: $service"
    if ((${#ids[@]} == 0)); then
      [[ "$expected" == "false" ]] || holdfast_die "captured running service disappeared before rollback: $service"
      continue
    fi
    state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}")
    if [[ "$expected" == "true" ]]; then
      [[ "$state" == "running" ]] || holdfast_die "captured service state changed before rollback: $service=$state"
    else
      [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
        holdfast_die "excluded service became active before rollback: $service=$state"
    fi
  done
}

validate_completed_rollback_receipt() {
  local receipt=$1 expected key value reactivated
  validate_runtime_restore_phase_receipt
  validate_estate_restore_phase_receipt
  validate_services_reactivated_phase_receipt
  validate_phase_state_binding rollback_runtime_restore_phase_receipt \
    rollback_runtime_restore_phase_receipt_sha256 "$runtime_phase_name" "$runtime_phase_sha"
  validate_phase_state_binding rollback_estate_restore_phase_receipt \
    rollback_estate_restore_phase_receipt_sha256 "$estate_phase_name" "$estate_phase_sha"
  validate_phase_state_binding rollback_services_reactivated_phase_receipt \
    rollback_services_reactivated_phase_receipt_sha256 "$services_phase_name" "$services_phase_sha"
  require_root_file "$receipt"
  for expected in \
    "schema_version=2" "rollback_armed_receipt_sha256=$rollback_armed_sha" \
    "running_services_sha256=$rollback_manifest_sha" \
    "runtime_prior_services_sha256=$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")" \
    "runtime_restore_phase_receipt_sha256=$runtime_phase_sha" \
    "estate_restore_phase_receipt_sha256=$estate_phase_sha" \
    "services_reactivated_phase_receipt_sha256=$services_phase_sha" \
    "route_close_receipt=$route_receipt_name" \
    "route_close_receipt_sha256=$(holdfast_sha256 "$route_receipt")" \
    "route_close_preimage=$route_preimage_name" \
    "route_close_preimage_sha256=$(holdfast_sha256 "$route_preimage")" \
    "revocation_evidence_sha256=$(holdfast_sha256 "$revocation_evidence")" \
    "open_evidence_sha256=$(holdfast_sha256 "$open_evidence")" \
    "runtime_restore_receipt_sha256=$(holdfast_sha256 "$backup/runtime/RESTORE.receipt")" \
    "estate_transaction_sha256=$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" \
    "runtime_restore=passed" "mixed_estate_restore=passed" \
    "orphan_cleanup=passed" \
    "service_reactivation=passed" "excluded_services_inactive=passed" \
    "activation_policy=restore-exact-prior-running" \
    "public_route_state=dual-stack-404" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "rollback completion receipt differs: $key"
  done
  reactivated=$(holdfast_receipt_value "$receipt" reactivated_services)
  [[ "$reactivated" == "$expected_reactivated_services" ]] || \
    holdfast_die "rollback receipt reactivated-services set differs from frozen recovery authority"
  validate_successor_lineage_receipt "$receipt"
}

finalize_rollback_state() {
  local receipt=$1 completed state_tmp current completed_sha receipt_sha state_sha
  require_root_file "$receipt"
  require_root_file "$state_file"
  receipt_sha=$(holdfast_sha256 "$receipt")
  state_sha=$(holdfast_sha256 "$state_file")
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    snapshot_v3_phase_fence
    append_v3_phase_fence_file "$receipt"
  fi
  revalidate_v3_successor_authority "$state_file"
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    validate_v3_phase_fence
    require_root_file "$receipt"
    require_root_file "$state_file"
    [[ "$(holdfast_sha256 "$receipt")" == "$receipt_sha" ]] || \
      holdfast_die "schema-v3 rollback completion receipt changed before finalization"
    [[ "$(holdfast_sha256 "$state_file")" == "$state_sha" ]] || \
      holdfast_die "schema-v3 rollback state changed before finalization"
    validate_completed_rollback_receipt "$receipt"
    validate_v3_phase_fence
    [[ "$(holdfast_sha256 "$receipt")" == "$receipt_sha" && \
      "$(holdfast_sha256 "$state_file")" == "$state_sha" ]] || \
      holdfast_die "schema-v3 rollback completion authority changed during finalization validation"
  fi
  completed="$state_dir/ROLLBACK-COMPLETE-${attempt_id}.json"
  current=$(jq -er '.state' "$state_file")
  if [[ "$current" != "rolled_back" ]]; then
    state_tmp="$state_dir/.ROLLBACK-COMPLETE.$$"
    jq --arg receipt_sha "$receipt_sha" \
      '.state="rolled_back" | .rollback_receipt_sha256=$receipt_sha | .ingress_opened=false' \
      "$state_file" >"$state_tmp"
    commit_atomic_file "$state_tmp" "$state_file"
  else
    [[ "$(jq -er '.rollback_receipt_sha256' "$state_file")" == "$receipt_sha" ]] || \
      holdfast_die "rolled-back state receipt was replaced"
  fi
  if [[ "$successor_rollback" == "true" ]]; then
    if [[ -e "$completed" || -L "$completed" ]]; then
      require_root_file "$completed"
      completed_sha=$(holdfast_sha256 "$completed")
      [[ "$completed_sha" == "$(holdfast_sha256 "$state_file")" ]] || \
        holdfast_die "successor rollback completion archive differs from CURRENT"
    else
      atomic_copy_authority "$state_file" "$completed"
    fi
    restore_immediate_predecessor_current
    if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
      "${HOLDFAST_TEST_SIGKILL_AFTER_PREDECESSOR_CURRENT_RESTORE:-0}" == "1" ]]; then
      kill -KILL "$$"
    fi
  else
    [[ ! -e "$completed" && ! -L "$completed" ]] || \
      holdfast_die "rollback completion state already exists"
    mv -- "$state_file" "$completed"
    sync -f "$completed"
    sync -f "$state_dir"
  fi
}

v3_rollback_terminal_candidate_scan_active="false"
v3_rollback_terminal_candidate_files=()
declare -A v3_rollback_terminal_candidate_hashes=() \
  v3_rollback_terminal_candidate_identities=()

snapshot_v3_rollback_terminal_candidate_namespace() {
  local candidate candidate_name
  [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]] || return 0
  validate_v3_state_dir_identity
  v3_rollback_terminal_candidate_files=()
  v3_rollback_terminal_candidate_hashes=()
  v3_rollback_terminal_candidate_identities=()
  while IFS= read -r candidate; do
    candidate_name=$(basename -- "$candidate")
    [[ "$candidate_name" =~ ^ROLLBACK-COMPLETE-[0-9]{8}T[0-9]{6}Z-[0-9]+\.json$ ]] || \
      holdfast_die "successor rollback completion archive name is unsafe"
    require_root_file "$candidate"
    v3_rollback_terminal_candidate_files+=("$candidate")
    v3_rollback_terminal_candidate_hashes["$candidate"]=$(holdfast_sha256 "$candidate")
    v3_rollback_terminal_candidate_identities["$candidate"]=$(stat -c \
      '%d:%i:%u:%h:%f' -- "$candidate")
  done < <(find "$state_dir" -mindepth 1 -maxdepth 1 \
    -name 'ROLLBACK-COMPLETE-*.json' -print | sort)
  v3_rollback_terminal_candidate_scan_active="true"
}

validate_v3_rollback_terminal_candidate_namespace() {
  local candidate index
  local -a current_candidates=()
  [[ "$v3_rollback_terminal_candidate_scan_active" == "true" ]] || return 0
  validate_v3_state_dir_identity
  while IFS= read -r candidate; do current_candidates+=("$candidate"); done \
    < <(find "$state_dir" -mindepth 1 -maxdepth 1 \
      -name 'ROLLBACK-COMPLETE-*.json' -print | sort)
  ((${#current_candidates[@]} == \
    ${#v3_rollback_terminal_candidate_files[@]})) || \
    holdfast_die "schema-v3 rollback completion archive namespace changed"
  for index in "${!v3_rollback_terminal_candidate_files[@]}"; do
    [[ "${current_candidates[$index]}" == \
      "${v3_rollback_terminal_candidate_files[$index]}" ]] || \
      holdfast_die "schema-v3 rollback completion archive namespace changed"
  done
  for candidate in "${v3_rollback_terminal_candidate_files[@]}"; do
    require_root_file "$candidate"
    [[ "$(holdfast_sha256 "$candidate")" == \
        "${v3_rollback_terminal_candidate_hashes[$candidate]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$candidate")" == \
        "${v3_rollback_terminal_candidate_identities[$candidate]}" ]] || \
      holdfast_die "schema-v3 rollback completion archive changed during external verification"
  done
}

validate_successor_completed_terminal() {
  local live_state_file=$state_file rollback_receipt="$backup/ROLLBACK.receipt"
  local rollback_receipt_sha candidate candidate_name completed="" completed_count=0
  local completed_sha current_sha state_control_sha activation_requested
  local file
  local -a completion_candidates=() terminal_files=()
  local -A terminal_hashes=() terminal_identities=()

  require_root_file "$live_state_file"
  require_root_file "$rollback_receipt"
  current_sha=$(holdfast_sha256 "$live_state_file")
  rollback_receipt_sha=$(holdfast_sha256 "$rollback_receipt")
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    snapshot_v3_rollback_terminal_candidate_namespace
    completion_candidates=("${v3_rollback_terminal_candidate_files[@]}")
  else
    while IFS= read -r candidate; do completion_candidates+=("$candidate"); done \
      < <(find "$state_dir" -mindepth 1 -maxdepth 1 \
        \( -type f -o -type l \) -name 'ROLLBACK-COMPLETE-*.json' -print | sort)
  fi
  for candidate in "${completion_candidates[@]}"; do
    candidate_name=$(basename -- "$candidate")
    [[ "$candidate_name" =~ ^ROLLBACK-COMPLETE-[0-9]{8}T[0-9]{6}Z-[0-9]+\.json$ ]] || \
      holdfast_die "successor rollback completion archive name is unsafe"
    require_root_file "$candidate"
    if jq -e --arg backup "$backup" --arg receipt_sha "$rollback_receipt_sha" \
      '.schema_version == 2 and .state == "rolled_back" and
       .backup_dir == $backup and .successor == true and
       .rollback_receipt_sha256 == $receipt_sha' "$candidate" >/dev/null; then
      completed_count=$((completed_count + 1))
      completed=$candidate
    fi
  done
  ((completed_count == 1)) || \
    holdfast_die "successor rollback completed terminal requires one exact completion archive"
  completed_sha=$(holdfast_sha256 "$completed")
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    terminal_files=(
      "$live_state_file"
      "$completed"
      "$rollback_receipt"
      "$backup/CONTROL.sha256"
      "$route_receipt"
      "$route_preimage"
    )
    for file in "${terminal_files[@]}"; do
      require_root_file "$file"
      terminal_hashes["$file"]=$(holdfast_sha256 "$file")
      terminal_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
    done
  fi

  # Validate from the archived successor state.  The live CURRENT is already
  # the predecessor and therefore cannot provide completion authority.
  local state_file=$completed
  attempt_id=$(jq -er '.rollback_attempt_id' "$state_file")
  [[ "$attempt_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
    "$completed" == "$state_dir/ROLLBACK-COMPLETE-${attempt_id}.json" ]] || \
    holdfast_die "successor rollback completion archive identity differs"
  runtime_phase_name="ROLLBACK-RUNTIME-RESTORE-DONE-${attempt_id}.receipt"
  estate_phase_name="ROLLBACK-ESTATE-RESTORE-DONE-${attempt_id}.receipt"
  services_phase_name="ROLLBACK-SERVICES-REACTIVATED-DONE-${attempt_id}.receipt"
  require_root_file "$route_receipt"
  [[ "$(jq -er '.route_close_receipt' "$state_file")" == "$route_receipt_name" ]] || \
    holdfast_die "successor rollback completion archive route receipt identity differs"
  [[ "$(jq -er '.route_close_receipt_sha256' "$state_file")" == \
    "$(holdfast_sha256 "$route_receipt")" ]] || \
    holdfast_die "successor rollback completion archive route receipt differs"
  require_root_file "$route_preimage"
  [[ "$(jq -er '.route_close_preimage' "$state_file")" == "$route_preimage_name" && \
    "$(jq -er '.route_close_preimage_sha256' "$state_file")" == \
    "$(holdfast_sha256 "$route_preimage")" ]] || \
    holdfast_die "successor rollback completion archive route preimage differs"

  load_frozen_rollback_authorities
  validate_v3_rollback_terminal_candidate_namespace
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    rollback_armed_receipt="$state_dir/$(jq -er '.rollback_armed_receipt' "$state_file")"
    rollback_manifest="$state_dir/$(jq -er '.rollback_running_services_manifest' "$state_file")"
    terminal_files+=(
      "$rollback_armed_receipt"
      "$rollback_manifest"
      "$open_evidence"
      "$open_signature"
      "$authority_public_key"
      "$revocation_evidence"
      "$revocation_signature"
      "$state_dir/$runtime_phase_name"
      "$state_dir/$estate_phase_name"
      "$state_dir/$services_phase_name"
      "$backup/runtime/RESTORE.receipt"
      "$backup/estate/TRANSACTION.json"
    )
    if [[ "$frozen_edge_evidence_name" != "none" ]]; then
      terminal_files+=(
        "$edge_rollback_evidence"
        "$edge_rollback_signature"
        "$open_edge_evidence"
      )
    fi
    for file in "${terminal_files[@]}"; do
      require_root_file "$file"
      if [[ -z "${terminal_hashes["$file"]+x}" ]]; then
        terminal_hashes["$file"]=$(holdfast_sha256 "$file")
        terminal_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
      fi
    done
  fi
  validate_backup_and_open_authority
  validate_v3_rollback_terminal_candidate_namespace
  [[ "$current_sha" == "$predecessor_current_sha" ]] || \
    holdfast_die "successor rollback terminal CURRENT is not the immediate predecessor"
  for path in "$revocation_evidence" "$revocation_signature"; do
    holdfast_require_absolute "$path"
  done
  run_python_tool "$authority_tool" "$script_dir/authority_evidence.py" --mode rollback \
    --evidence "$revocation_evidence" --signature "$revocation_signature" \
    --public-key "$authority_public_key" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" --open-evidence "$open_evidence" \
    --route-close-receipt "$route_receipt"
  validate_v3_rollback_terminal_candidate_namespace
  verify_closed_bracket
  validate_v3_rollback_terminal_candidate_namespace

  edge_rollback_sha="none"
  edge_rollback_signature_sha="none"
  open_edge_sha="none"
  if [[ "$(holdfast_receipt_value "$route_receipt" was_public_open)" == "true" ]]; then
    run_python_tool "$edge_tool" "$script_dir/edge_evidence.py" --mode rollback \
      --evidence "$edge_rollback_evidence" --signature "$edge_rollback_signature" \
      --public-key "$authority_public_key" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json" "${edge_policy_args[@]}" \
      --open-edge-evidence "$open_edge_evidence" --route-close-receipt "$route_receipt" \
      --revocation-evidence "$revocation_evidence"
    validate_v3_rollback_terminal_candidate_namespace
    edge_rollback_sha=$(holdfast_sha256 "$edge_rollback_evidence")
    edge_rollback_signature_sha=$(holdfast_sha256 "$edge_rollback_signature")
    open_edge_sha=$(holdfast_sha256 "$open_edge_evidence")
  fi
  verify_closed_bracket
  validate_v3_rollback_terminal_candidate_namespace

  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    revalidate_v3_successor_authority "$state_file"
    validate_v3_rollback_terminal_candidate_namespace
    for file in "${terminal_files[@]}"; do
      require_root_file "$file"
      [[ "$(holdfast_sha256 "$file")" == "${terminal_hashes[$file]}" && \
        "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
          "${terminal_identities[$file]}" ]] || \
        holdfast_die "schema-v3 rollback terminal authority changed during external verification: $file"
    done
    validate_v3_cached_control_authority
    validate_v3_rollback_terminal_candidate_namespace
  fi

  validate_runtime_prior_services
  validate_estate_restore_manifests
  control_sha=$(holdfast_sha256 "$backup/CONTROL.sha256")
  state_control_sha=$(jq -er '.control_sha256' "$state_file")
  [[ "$state_control_sha" == "$control_sha" ]] || \
    holdfast_die "successor rollback completion archive CONTROL differs"
  compose_project=$(jq -er '.name' "$backup/runtime/compose-config.json")
  [[ "$compose_project" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || \
    holdfast_die "runtime backup has an unsafe Compose project name"
  validate_rollback_arm
  runtime_phase_name="ROLLBACK-RUNTIME-RESTORE-DONE-${attempt_id}.receipt"
  estate_phase_name="ROLLBACK-ESTATE-RESTORE-DONE-${attempt_id}.receipt"
  services_phase_name="ROLLBACK-SERVICES-REACTIVATED-DONE-${attempt_id}.receipt"
  validate_completed_rollback_receipt "$rollback_receipt"
  activation_requested=$(holdfast_receipt_value "$rollback_armed_receipt" activate_services_requested)
  [[ "$(holdfast_receipt_value "$rollback_receipt" activate_services_requested)" == \
    "$activation_requested" ]] || \
    holdfast_die "successor rollback completion activation authority differs"
  [[ "$(jq -er '.rollback_estate_transaction_sha256' "$state_file")" == \
    "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" ]] || \
    holdfast_die "successor rollback completion transaction authority differs"
  verify_estate_disposition preimage

  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    for file in "${terminal_files[@]}"; do
      require_root_file "$file"
      [[ "$(holdfast_sha256 "$file")" == "${terminal_hashes[$file]}" && \
        "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
          "${terminal_identities[$file]}" ]] || \
        holdfast_die "schema-v3 rollback terminal authority changed during lifecycle verification: $file"
    done
    validate_v3_cached_control_authority
    (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
    validate_v3_rollback_terminal_candidate_namespace
  fi

  require_root_file "$completed"
  require_root_file "$rollback_receipt"
  require_root_file "$live_state_file"
  [[ "$(holdfast_sha256 "$completed")" == "$completed_sha" && \
    "$(holdfast_sha256 "$rollback_receipt")" == "$rollback_receipt_sha" && \
    "$(holdfast_sha256 "$live_state_file")" == "$predecessor_current_sha" ]] || \
    holdfast_die "successor rollback completed terminal authority changed during validation"
  validate_v3_rollback_terminal_candidate_namespace
}

if [[ "$phase" == "execute" && "$backup_expected_successor" == "true" && \
  "$(holdfast_sha256 "$state_file")" == "$(holdfast_sha256 "$backup/PREDECESSOR-CURRENT.json")" ]]; then
  validate_successor_completed_terminal
  echo "previously completed successor rollback was verified; ingress remains closed"
  exit 0
fi

if [[ "$phase" == "close-route" ]]; then
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    # Schema v3 carries its predecessor authority only in this backup.  Prove
    # that local lineage before the first route-database mutation.
    revalidate_v3_successor_authority "$state_file"
    snapshot_v3_close_route_probe_authority
  fi
  # After any schema-v3 local lineage proof, the frozen, transactionally
  # self-snapshotting down asset and public bracket still run before parsing
  # mutable armed/open metadata.
  route_receipt_was_present="false"
  if [[ -e "$route_receipt" || -L "$route_receipt" ]]; then
    route_receipt_was_present="true"
  fi
  execute_frozen_route_down
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    validate_v3_close_route_probe_authority
    require_root_file "$route_preimage"
    if [[ "$route_receipt_was_present" == "false" ]]; then
      [[ "$route_down_execution_evidence_sha" == \
        "$(holdfast_sha256 "$route_preimage")" ]] || \
        holdfast_die "schema-v3 route-down execution evidence differs from its preimage"
    fi
    append_v3_close_route_probe_file "$route_preimage"
  fi
  verify_closed_bracket
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    revalidate_v3_successor_authority "$state_file"
    validate_v3_close_route_probe_authority
  fi

  current_state=$(jq -er '.state' "$state_file")
  [[ "$current_state" == "ingress_open" || "$current_state" == "finalizing_route_armed" || "$current_state" == "ingress_compensation_unverified" || "$current_state" == "edge_prepared_route_closed" || "$current_state" == "applied_ingress_closed" ]] || \
    holdfast_die "route close refuses state $current_state"
  if [[ -e "$route_receipt" || -L "$route_receipt" ]]; then
    validate_route_close_receipt_for_adoption "$current_state"
    validate_v3_close_route_probe_authority
    commit_route_closed_state
    echo "previously completed route close was adopted; now finish revocation evidence"
    exit 0
  fi
  validate_backup_and_open_authority
  validate_v3_close_route_probe_authority
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    [[ "$route_down_execution_evidence_sha" == \
      "$(holdfast_sha256 "$route_preimage")" ]] || \
      holdfast_die "schema-v3 route-down execution evidence changed before receipt commit"
  fi

  preopen_edge_sha="none"
  was_public_open="false"
  if [[ "$current_state" == "ingress_open" ]]; then
    was_public_open="true"
    open_receipt="$state_dir/OPEN.receipt"
    [[ -f "$open_receipt" && ! -L "$open_receipt" ]] || holdfast_die "open receipt is absent"
    [[ "$(jq -er '.open_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$open_receipt")" ]] || \
      holdfast_die "open receipt was replaced"
    preopen_edge_sha=$(holdfast_receipt_value "$open_receipt" edge_evidence_sha256)
  elif [[ "$current_state" == "finalizing_route_armed" || "$current_state" == "ingress_compensation_unverified" ]]; then
    was_public_open="true"
    preopen_edge_sha=$(jq -er '.open_armed_edge_evidence_sha256' "$state_file")
  fi
  if [[ "$was_public_open" == "true" ]]; then
    [[ "$preopen_edge_sha" =~ ^[0-9a-f]{64}$ ]] || holdfast_die "public open edge evidence hash is invalid"
  fi
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    "${HOLDFAST_TEST_SIGKILL_BEFORE_ROUTE_CLOSE_RECEIPT:-0}" == "1" ]]; then
    kill -KILL "$$"
  fi

  receipt_tmp="$state_dir/.ROUTE-CLOSE.receipt.$$"
  {
    if [[ "$backup_successor_policy_version" == "4" || \
      "$backup_successor_policy_version" == "5" ]]; then
      printf 'schema_version=3\n'
    else
      printf 'schema_version=2\n'
    fi
    printf 'route_closed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'source_state=%s\n' "$current_state"
    printf 'estate_root=%s\n' "$estate_root"
    printf 'backup_dir=%s\n' "$backup"
    printf 'control_sha256=%s\n' "$(holdfast_sha256 "$backup/CONTROL.sha256")"
    printf 'state_before_sha256=%s\n' "$(holdfast_sha256 "$state_file")"
    printf 'route_down_sha256=%s\n' "$expected_route_down"
    printf 'route_down_execution_evidence_sha256=%s\n' "$route_down_execution_evidence_sha"
    if [[ "$backup_successor_policy_version" == "4" || \
      "$backup_successor_policy_version" == "5" ]]; then
      printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$open_evidence")"
      printf 'source_grant_id=%s\n' "$(jq -er '.source_grant_id' "$open_evidence")"
      printf 'was_public_open=%s\n' "$was_public_open"
      printf 'preopen_edge_evidence_sha256=%s\n' "$preopen_edge_sha"
      printf 'route_preimage_sha256=%s\n' "$(holdfast_sha256 "$route_preimage")"
      printf 'route_conflict_cleanup=same-name-or-rikune-root-or-analyze-host\n'
      printf 'route_state=absent\n'
      printf 'public_host=rikune.w33d.xyz\n'
      printf 'legacy_public_host=analyze.w33d.xyz\n'
      printf 'legacy_route_state=absent\n'
      printf 'legacy_public_ipv4_ipv6_closed_status=404\n'
    else
      printf 'route_preimage_sha256=%s\n' "$(holdfast_sha256 "$route_preimage")"
      printf 'route_conflict_cleanup=same-name-or-analyze-root\n'
      printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$open_evidence")"
      printf 'source_grant_id=%s\n' "$(jq -er '.source_grant_id' "$open_evidence")"
      printf 'was_public_open=%s\n' "$was_public_open"
      printf 'preopen_edge_evidence_sha256=%s\n' "$preopen_edge_sha"
      printf 'route_state=absent\n'
      printf 'public_host=analyze.w33d.xyz\n'
    fi
    printf 'edge_owner=existing-w33d-sluice\n'
    printf 'public_ipv4_ipv6_closed_status=404\n'
    printf 'db_public_db_bracket=absent-404-absent\n'
    printf 'external_edge_mutation=none\n'
  } >"$receipt_tmp"
  commit_atomic_file "$receipt_tmp" "$route_receipt"
  validate_route_close_receipt_keys "$route_receipt"
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    "${HOLDFAST_TEST_SIGKILL_AFTER_ROUTE_CLOSE_RECEIPT:-0}" == "1" ]]; then
    kill -KILL "$$"
  fi
  commit_route_closed_state
  echo "route is dual-stack 404 closed; now revoke the exact source grant, await all seven tombstones, then sign the policy-versioned rollback evidence"
  exit 0
fi

current_state=$(jq -er '.state' "$state_file")
[[ "$current_state" == "route_closed_awaiting_revocation" || \
  "$current_state" == "rollback_execute_armed" || \
  "$current_state" == "rollback_runtime_restore_done" || \
  "$current_state" == "rollback_estate_restore_done" || \
  "$current_state" == "rollback_services_reactivated_done" || \
  "$current_state" == "rolled_back" ]] || \
  holdfast_die "rollback execute refuses state $current_state"
require_root_file "$route_receipt"
require_root_file "$route_preimage"
[[ "$(jq -er '.route_close_receipt' "$state_file")" == "$route_receipt_name" && \
  "$(jq -er '.route_close_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$route_receipt")" ]] || \
  holdfast_die "route-close receipt was replaced"
[[ "$(jq -er '.route_close_preimage' "$state_file")" == "$route_preimage_name" && \
  "$(jq -er '.route_close_preimage_sha256' "$state_file")" == "$(holdfast_sha256 "$route_preimage")" ]] || \
  holdfast_die "route-close preimage was replaced"
if [[ "$current_state" != "route_closed_awaiting_revocation" ]]; then
  load_frozen_rollback_authorities
fi
snapshot_v3_execute_entry_authority
validate_backup_and_open_authority
for path in "$revocation_evidence" "$revocation_signature"; do holdfast_require_absolute "$path"; done
run_python_tool "$authority_tool" "$script_dir/authority_evidence.py" --mode rollback \
  --evidence "$revocation_evidence" --signature "$revocation_signature" \
  --public-key "$authority_public_key" --release-env "$backup/release.env" \
  --release-evidence "$backup/RELEASE-EVIDENCE.json" --open-evidence "$open_evidence" \
  --route-close-receipt "$route_receipt"
verify_closed_bracket

edge_rollback_sha="none"
edge_rollback_signature_sha="none"
open_edge_sha="none"
if [[ "$(holdfast_receipt_value "$route_receipt" was_public_open)" == "true" ]]; then
  [[ -n "$edge_rollback_evidence" && -n "$edge_rollback_signature" && -n "$open_edge_evidence" ]] || \
    holdfast_die "public rollback requires signed policy-versioned dual-stack 404 evidence"
  for path in "$edge_rollback_evidence" "$edge_rollback_signature" "$open_edge_evidence"; do holdfast_require_absolute "$path"; done
  run_python_tool "$edge_tool" "$script_dir/edge_evidence.py" --mode rollback \
    --evidence "$edge_rollback_evidence" --signature "$edge_rollback_signature" \
    --public-key "$authority_public_key" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" "${edge_policy_args[@]}" \
    --open-edge-evidence "$open_edge_evidence" \
    --route-close-receipt "$route_receipt" --revocation-evidence "$revocation_evidence"
  edge_rollback_sha=$(holdfast_sha256 "$edge_rollback_evidence")
  edge_rollback_signature_sha=$(holdfast_sha256 "$edge_rollback_signature")
  open_edge_sha=$(holdfast_sha256 "$open_edge_evidence")
fi
verify_closed_bracket
if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
  validate_v3_execute_entry_authority
  revalidate_v3_successor_authority "$state_file"
  validate_v3_execute_entry_authority
fi

rollback_receipt="$backup/ROLLBACK.receipt"
validate_runtime_prior_services
validate_estate_restore_manifests
control_sha=$(holdfast_sha256 "$backup/CONTROL.sha256")
state_control_sha=$(jq -er '.control_sha256' "$state_file")
[[ "$state_control_sha" == "$control_sha" ]] || \
  holdfast_die "rollback current state CONTROL differs"
compose_project=$(jq -er '.name' "$backup/runtime/compose-config.json")
[[ "$compose_project" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || \
  holdfast_die "runtime backup has an unsafe Compose project name"

fresh_arm="false"
if [[ "$current_state" == "route_closed_awaiting_revocation" ]]; then
  [[ ! -e "$rollback_receipt" && ! -L "$rollback_receipt" ]] || \
    holdfast_die "rollback receipt exists before execute is armed"
  [[ ! -e "$backup/runtime/RESTORE.receipt" && ! -L "$backup/runtime/RESTORE.receipt" ]] || \
    holdfast_die "runtime restore receipt exists before rollback execute is armed"
  original_transaction_sha=$(holdfast_sha256 "$backup/estate/TRANSACTION.json")
  applied_targets_sha=$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")
  [[ "$(jq -er '.transaction_sha256' "$state_file")" == "$original_transaction_sha" ]] || \
    holdfast_die "rollback current state transaction authority differs"
  [[ "$(jq -er '.applied_targets_sha256' "$state_file")" == "$applied_targets_sha" ]] || \
    holdfast_die "rollback current state applied-target authority differs"
  [[ "$(jq -er '.schema_version == 1 and .state == "applied"' \
    "$backup/estate/TRANSACTION.json")" == "true" ]] || \
    holdfast_die "rollback requires the exact applied estate transaction"
  verify_estate_disposition applied
  attempt_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  frozen_open_evidence_name="ROLLBACK-OPEN-EVIDENCE-${attempt_id}.json"
  frozen_open_signature_name="ROLLBACK-OPEN-SIGNATURE-${attempt_id}.sig"
  frozen_public_key_name="ROLLBACK-AUTHORITY-PUBLIC-KEY-${attempt_id}.pub"
  frozen_revocation_evidence_name="ROLLBACK-REVOCATION-EVIDENCE-${attempt_id}.json"
  frozen_revocation_signature_name="ROLLBACK-REVOCATION-SIGNATURE-${attempt_id}.sig"
  frozen_edge_evidence_name="none"
  frozen_edge_signature_name="none"
  frozen_open_edge_name="none"
  atomic_copy_authority "$open_evidence" "$state_dir/$frozen_open_evidence_name"
  atomic_copy_authority "$open_signature" "$state_dir/$frozen_open_signature_name"
  atomic_copy_authority "$authority_public_key" "$state_dir/$frozen_public_key_name"
  atomic_copy_authority "$revocation_evidence" "$state_dir/$frozen_revocation_evidence_name"
  atomic_copy_authority "$revocation_signature" "$state_dir/$frozen_revocation_signature_name"
  if [[ "$(holdfast_receipt_value "$route_receipt" was_public_open)" == "true" ]]; then
    frozen_edge_evidence_name="ROLLBACK-EDGE-EVIDENCE-${attempt_id}.json"
    frozen_edge_signature_name="ROLLBACK-EDGE-SIGNATURE-${attempt_id}.sig"
    frozen_open_edge_name="ROLLBACK-OPEN-EDGE-EVIDENCE-${attempt_id}.json"
    atomic_copy_authority "$edge_rollback_evidence" "$state_dir/$frozen_edge_evidence_name"
    atomic_copy_authority "$edge_rollback_signature" "$state_dir/$frozen_edge_signature_name"
    atomic_copy_authority "$open_edge_evidence" "$state_dir/$frozen_open_edge_name"
  fi
  open_evidence="$state_dir/$frozen_open_evidence_name"
  open_signature="$state_dir/$frozen_open_signature_name"
  authority_public_key="$state_dir/$frozen_public_key_name"
  revocation_evidence="$state_dir/$frozen_revocation_evidence_name"
  revocation_signature="$state_dir/$frozen_revocation_signature_name"
  if [[ "$frozen_edge_evidence_name" != "none" ]]; then
    edge_rollback_evidence="$state_dir/$frozen_edge_evidence_name"
    edge_rollback_signature="$state_dir/$frozen_edge_signature_name"
    open_edge_evidence="$state_dir/$frozen_open_edge_name"
  fi
  snapshot_v3_frozen_rollback_authorities
  if [[ ( "$backup_successor_policy_version" == "3" || \
    "$backup_successor_policy_version" == "4" || \
    "$backup_successor_policy_version" == "5" ) && \
    "$frozen_edge_evidence_name" != "none" ]]; then
    edge_rollback_sha=${v3_frozen_rollback_authority_hashes[$edge_rollback_evidence]}
    edge_rollback_signature_sha=${v3_frozen_rollback_authority_hashes[$edge_rollback_signature]}
    open_edge_sha=${v3_frozen_rollback_authority_hashes[$open_edge_evidence]}
  fi
  # Re-verify the immutable copies themselves.  Validation of the source paths
  # before copying is not sufficient across a validate-to-copy TOCTOU window.
  run_python_tool "$authority_tool" "$script_dir/authority_evidence.py" --mode open \
    --evidence "$open_evidence" --signature "$open_signature" \
    --public-key "$authority_public_key" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" \
    --dry-run-receipt "$backup/DRY-RUN.receipt"
  validate_v3_frozen_rollback_authorities
  run_python_tool "$authority_tool" "$script_dir/authority_evidence.py" --mode rollback \
    --evidence "$revocation_evidence" --signature "$revocation_signature" \
    --public-key "$authority_public_key" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" --open-evidence "$open_evidence" \
    --route-close-receipt "$route_receipt"
  validate_v3_frozen_rollback_authorities
  if [[ "$frozen_edge_evidence_name" != "none" ]]; then
    run_python_tool "$edge_tool" "$script_dir/edge_evidence.py" --mode rollback \
      --evidence "$edge_rollback_evidence" --signature "$edge_rollback_signature" \
      --public-key "$authority_public_key" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json" "${edge_policy_args[@]}" \
      --open-edge-evidence "$open_edge_evidence" \
      --route-close-receipt "$route_receipt" --revocation-evidence "$revocation_evidence"
    validate_v3_frozen_rollback_authorities
    if [[ "$backup_successor_policy_version" != "3" && \
      "$backup_successor_policy_version" != "4" && \
      "$backup_successor_policy_version" != "5" ]]; then
      edge_rollback_sha=$(holdfast_sha256 "$edge_rollback_evidence")
      edge_rollback_signature_sha=$(holdfast_sha256 "$edge_rollback_signature")
      open_edge_sha=$(holdfast_sha256 "$open_edge_evidence")
    fi
  fi
  validate_v3_execute_entry_authority
  validate_v3_frozen_rollback_authorities
  rollback_manifest_name="ROLLBACK-RUNNING-SERVICES-${attempt_id}.before"
  rollback_manifest="$state_dir/$rollback_manifest_name"
  rollback_manifest_tmp="$state_dir/.ROLLBACK-RUNNING-SERVICES.$$"
  capture_rollback_running_manifest "$rollback_manifest" "$rollback_manifest_tmp"
  validate_v3_frozen_rollback_authorities
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    validate_v3_execute_entry_authority
    revalidate_v3_successor_authority "$state_file"
    validate_v3_rollback_prearm_mutation_authority
    validate_v3_execute_entry_authority
    validate_v3_frozen_rollback_authorities
    [[ ! -e "$rollback_manifest" && ! -L "$rollback_manifest" ]] || \
      holdfast_die "schema-v3 rollback running manifest appeared before its mutation fence"
    commit_atomic_file "$rollback_manifest_tmp" "$rollback_manifest"
    validate_rollback_running_manifest "$rollback_manifest"
  fi
  rollback_manifest_sha=$(holdfast_sha256 "$rollback_manifest")

  rollback_armed_name="ROLLBACK-EXECUTE-ARMED-${attempt_id}.receipt"
  snapshot_v3_rollback_prearm_files
  if [[ "$backup_successor_policy_version" != "3" && \
    "$backup_successor_policy_version" != "4" && \
    "$backup_successor_policy_version" != "5" ]]; then
    revalidate_v3_successor_authority "$state_file"
    validate_v3_rollback_prearm_mutation_authority
  fi
  validate_v3_rollback_prearm_files
  rollback_armed_receipt="$state_dir/$rollback_armed_name"
  rollback_armed_tmp="$state_dir/.ROLLBACK-EXECUTE-ARMED.$$"
  [[ ! -e "$rollback_armed_receipt" && ! -L "$rollback_armed_receipt" && \
    ! -e "$rollback_armed_tmp" && ! -L "$rollback_armed_tmp" ]] || \
    holdfast_die "rollback armed receipt path already exists"
  {
    printf 'schema_version=2\n'
    printf 'armed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'attempt_id=%s\n' "$attempt_id"
    printf 'estate_root=%s\n' "$estate_root"
    printf 'backup_dir=%s\n' "$backup"
    printf 'control_sha256=%s\n' "$control_sha"
    printf 'transaction_sha256=%s\n' "$original_transaction_sha"
    printf 'applied_targets_sha256=%s\n' "$applied_targets_sha"
    printf 'targets_sha256=%s\n' "$(holdfast_sha256 "$backup/TARGETS.sha256")"
    printf 'apply_preimages_sha256=%s\n' "$(holdfast_sha256 "$backup/APPLY-PREIMAGES.sha256")"
    printf 'apply_absent_sha256=%s\n' "$(holdfast_sha256 "$backup/APPLY-ABSENT.paths")"
    printf 'route_close_receipt=%s\n' "$route_receipt_name"
    printf 'route_close_receipt_sha256=%s\n' "$(holdfast_sha256 "$route_receipt")"
    printf 'route_close_preimage=%s\n' "$route_preimage_name"
    printf 'route_close_preimage_sha256=%s\n' "$(holdfast_sha256 "$route_preimage")"
    printf 'open_evidence_file=%s\n' "$frozen_open_evidence_name"
    printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$open_evidence")"
    printf 'open_signature_file=%s\n' "$frozen_open_signature_name"
    printf 'open_signature_sha256=%s\n' "$(holdfast_sha256 "$open_signature")"
    printf 'authority_public_key_file=%s\n' "$frozen_public_key_name"
    printf 'authority_public_key_sha256=%s\n' "$(holdfast_sha256 "$authority_public_key")"
    printf 'revocation_evidence_file=%s\n' "$frozen_revocation_evidence_name"
    printf 'revocation_evidence_sha256=%s\n' "$(holdfast_sha256 "$revocation_evidence")"
    printf 'revocation_signature_file=%s\n' "$frozen_revocation_signature_name"
    printf 'revocation_signature_sha256=%s\n' "$(holdfast_sha256 "$revocation_signature")"
    printf 'edge_rollback_evidence_file=%s\n' "$frozen_edge_evidence_name"
    printf 'edge_rollback_evidence_sha256=%s\n' "$edge_rollback_sha"
    printf 'edge_rollback_signature_file=%s\n' "$frozen_edge_signature_name"
    printf 'edge_rollback_signature_sha256=%s\n' "$edge_rollback_signature_sha"
    printf 'open_edge_evidence_file=%s\n' "$frozen_open_edge_name"
    printf 'open_edge_evidence_sha256=%s\n' "$open_edge_sha"
    printf 'compose_project=%s\n' "$compose_project"
    printf 'release_service_count=7\n'
    printf 'release_services=access-governance,verdict,newapi,rikune-analyzer,strad,sluice,sluice-internal\n'
    printf 'running_services_manifest=%s\n' "$rollback_manifest_name"
    printf 'running_services_sha256=%s\n' "$rollback_manifest_sha"
    printf 'runtime_prior_services_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")"
    printf 'activate_services_requested=%s\n' "$activate"
    printf 'activation_policy=restore-exact-prior-running\n'
    printf 'ingress_opened=false\n'
    append_successor_lineage_receipt_fields
  } >"$rollback_armed_tmp"
  commit_atomic_file "$rollback_armed_tmp" "$rollback_armed_receipt"
  rollback_armed_sha=$(holdfast_sha256 "$rollback_armed_receipt")

  state_tmp="$state_dir/.CURRENT.json.$$"
  jq \
    --arg attempt "$attempt_id" --arg manifest "$rollback_manifest_name" \
    --arg manifest_sha "$rollback_manifest_sha" --arg armed "$rollback_armed_name" \
    --arg armed_sha "$rollback_armed_sha" --arg control "$control_sha" \
    '.state="rollback_execute_armed" | .rollback_attempt_id=$attempt | .rollback_running_services_manifest=$manifest | .rollback_running_services_sha256=$manifest_sha | .rollback_armed_receipt=$armed | .rollback_armed_receipt_sha256=$armed_sha | .control_sha256=$control | .ingress_opened=false' \
    "$state_file" >"$state_tmp"
  state_tmp_sha=$(holdfast_sha256 "$state_tmp")
  revalidate_v3_successor_authority "$state_file"
  validate_v3_rollback_prearm_mutation_authority
  validate_v3_rollback_prearm_files
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    validate_v3_execute_entry_authority
    require_root_file "$rollback_armed_receipt"
    [[ "$(holdfast_sha256 "$rollback_armed_receipt")" == "$rollback_armed_sha" ]] || \
      holdfast_die "schema-v3 rollback arm changed before CURRENT commit"
    validate_successor_lineage_receipt "$rollback_armed_receipt"
    [[ "$(holdfast_sha256 "$state_tmp")" == "$state_tmp_sha" ]] || \
      holdfast_die "schema-v3 rollback CURRENT candidate changed before commit"
  fi
  commit_atomic_file "$state_tmp" "$state_file"
  current_state="rollback_execute_armed"
  fresh_arm="true"
fi
validate_rollback_arm
runtime_phase_name="ROLLBACK-RUNTIME-RESTORE-DONE-${attempt_id}.receipt"
estate_phase_name="ROLLBACK-ESTATE-RESTORE-DONE-${attempt_id}.receipt"
services_phase_name="ROLLBACK-SERVICES-REACTIVATED-DONE-${attempt_id}.receipt"
activation_requested=$(holdfast_receipt_value "$rollback_armed_receipt" activate_services_requested)
[[ "$activation_requested" == "true" || "$activation_requested" == "false" ]] || \
  holdfast_die "rollback armed activation compatibility value differs"

if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && "${HOLDFAST_TEST_SIGKILL_AFTER_ROLLBACK_ARM:-0}" == "1" ]]; then
  kill -KILL "$$"
fi

# A receipt is written only after all restore and lifecycle proofs pass.  If a
# SIGKILL lands between that receipt and CURRENT finalization, reuse it without
# repeating or resampling the runtime mutation.
if [[ -e "$rollback_receipt" || -L "$rollback_receipt" ]]; then
  validate_completed_rollback_receipt "$rollback_receipt"
  finalize_rollback_state "$rollback_receipt"
  echo "previously completed checksum-bound rollback was finalized; ingress remains closed"
  exit 0
fi

if [[ "$current_state" == "rollback_execute_armed" ]]; then
  snapshot_v3_phase_fence
  [[ "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" == "$original_transaction_sha" && \
    "$(jq -er '.schema_version == 1 and .state == "applied"' \
      "$backup/estate/TRANSACTION.json")" == "true" ]] || \
    holdfast_die "pre-restore estate transaction differs from the armed authority"
  verify_estate_disposition applied
  if [[ "$fresh_arm" == "true" ]]; then verify_fresh_running_snapshot; fi
  revalidate_v3_successor_authority "$state_file"
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    validate_v3_phase_fence
    validate_rollback_arm
    validate_runtime_prior_services
    validate_estate_restore_manifests
    verify_estate_disposition applied
  fi
  quiesce_release_services
  if [[ -e "$state_dir/$runtime_phase_name" || -L "$state_dir/$runtime_phase_name" ]]; then
    validate_runtime_restore_receipt
  elif [[ -e "$backup/runtime/RESTORE.receipt" || -L "$backup/runtime/RESTORE.receipt" ]]; then
    # runtime-restore commits RESTORE.receipt only after its full mutation.  A
    # crash in the following receipt/state gap is adopted instead of replayed.
    validate_runtime_restore_receipt
  else
    revalidate_v3_successor_authority "$state_file"
    if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
      validate_v3_phase_fence
      validate_rollback_arm
      validate_runtime_prior_services
      validate_estate_restore_manifests
      verify_estate_disposition applied
    fi
    "$runtime_restore" --execute --compose-root "$estate_root" --backup-dir "$backup/runtime"
    validate_runtime_restore_receipt
    if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
      "${HOLDFAST_TEST_SIGKILL_AFTER_RUNTIME_RESTORE:-0}" == "1" ]]; then
      kill -KILL "$$"
    fi
  fi
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    append_v3_phase_fence_file "$backup/runtime/RESTORE.receipt"
    revalidate_v3_successor_authority "$state_file"
    validate_v3_phase_fence
    validate_rollback_arm
    validate_runtime_restore_receipt
    validate_runtime_prior_services
    validate_estate_restore_manifests
    verify_estate_disposition applied
    validate_v3_phase_fence
  fi
  persist_runtime_restore_phase
fi

if [[ "$current_state" == "rollback_runtime_restore_done" || \
  "$current_state" == "rollback_estate_restore_done" || \
  "$current_state" == "rollback_services_reactivated_done" || \
  "$current_state" == "rolled_back" ]]; then
  validate_runtime_restore_phase_receipt
  validate_phase_state_binding rollback_runtime_restore_phase_receipt \
    rollback_runtime_restore_phase_receipt_sha256 "$runtime_phase_name" "$runtime_phase_sha"
fi

if [[ "$current_state" == "rollback_runtime_restore_done" ]]; then
  snapshot_v3_phase_fence
  revalidate_v3_successor_authority "$state_file"
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    validate_v3_phase_fence
    validate_rollback_arm
    validate_runtime_restore_phase_receipt
    validate_phase_state_binding rollback_runtime_restore_phase_receipt \
      rollback_runtime_restore_phase_receipt_sha256 "$runtime_phase_name" "$runtime_phase_sha"
    validate_estate_restore_manifests
  fi
  quiesce_release_services
  transaction_state=$(jq -er '.state' "$backup/estate/TRANSACTION.json")
  if [[ "$transaction_state" == "restored" ]]; then
    verify_estate_disposition preimage
  else
    [[ "$transaction_state" == "applied" ]] || \
      holdfast_die "estate transaction has an unknown rollback phase: $transaction_state"
    verify_estate_disposition mixed
    revalidate_v3_successor_authority "$state_file"
    if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
      validate_v3_phase_fence
      validate_rollback_arm
      validate_runtime_restore_phase_receipt
      validate_phase_state_binding rollback_runtime_restore_phase_receipt \
        rollback_runtime_restore_phase_receipt_sha256 "$runtime_phase_name" "$runtime_phase_sha"
      validate_estate_restore_manifests
      [[ "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" == \
        "$original_transaction_sha" && \
        "$(jq -er '.schema_version == 1 and .state == "applied"' \
          "$backup/estate/TRANSACTION.json")" == "true" ]] || \
        holdfast_die "schema-v3 estate authority changed before rollback restore"
      verify_estate_disposition mixed
    fi
    run_python_tool "$estate_transaction" "$script_dir/estate_transaction.py" restore \
      --estate-root "$estate_root" --backup-dir "$backup/estate"
    require_root_file "$backup/estate/TRANSACTION.json"
    [[ "$(jq -er '.schema_version == 1 and .state == "restored"' \
      "$backup/estate/TRANSACTION.json")" == "true" ]] || \
      holdfast_die "estate rollback did not record restored state"
    verify_estate_disposition preimage
    if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
      "${HOLDFAST_TEST_SIGKILL_AFTER_ESTATE_RESTORE:-0}" == "1" ]]; then
      kill -KILL "$$"
    fi
  fi
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    append_v3_phase_fence_file "$backup/estate/TRANSACTION.json"
    revalidate_v3_successor_authority "$state_file"
    validate_v3_phase_fence
    validate_rollback_arm
    validate_runtime_restore_phase_receipt
    validate_phase_state_binding rollback_runtime_restore_phase_receipt \
      rollback_runtime_restore_phase_receipt_sha256 "$runtime_phase_name" "$runtime_phase_sha"
    validate_estate_restore_manifests
    [[ "$(jq -er '.schema_version == 1 and .state == "restored"' \
      "$backup/estate/TRANSACTION.json")" == "true" ]] || \
      holdfast_die "schema-v3 estate transaction changed before phase commit"
    verify_estate_disposition preimage
    validate_v3_phase_fence
  fi
  persist_estate_restore_phase
fi

if [[ "$current_state" == "rollback_estate_restore_done" || \
  "$current_state" == "rollback_services_reactivated_done" || \
  "$current_state" == "rolled_back" ]]; then
  validate_estate_restore_phase_receipt
  validate_phase_state_binding rollback_estate_restore_phase_receipt \
    rollback_estate_restore_phase_receipt_sha256 "$estate_phase_name" "$estate_phase_sha"
  [[ "$(jq -er '.rollback_estate_transaction_sha256' "$state_file")" == \
    "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" ]] || \
    holdfast_die "rollback state restored-transaction identity differs"
  verify_estate_disposition preimage
fi

if [[ "$current_state" == "rollback_estate_restore_done" ]]; then
  snapshot_v3_phase_fence
  load_exact_restart_authority
  if ((${#restart_services[@]})); then
    revalidate_v3_successor_authority "$state_file"
    if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
      validate_v3_phase_fence
      validate_rollback_arm
      validate_runtime_restore_phase_receipt
      validate_phase_state_binding rollback_runtime_restore_phase_receipt \
        rollback_runtime_restore_phase_receipt_sha256 "$runtime_phase_name" "$runtime_phase_sha"
      validate_estate_restore_phase_receipt
      validate_phase_state_binding rollback_estate_restore_phase_receipt \
        rollback_estate_restore_phase_receipt_sha256 "$estate_phase_name" "$estate_phase_sha"
      [[ "$(jq -er '.schema_version == 1 and .state == "restored"' \
        "$backup/estate/TRANSACTION.json")" == "true" ]] || \
        holdfast_die "schema-v3 restored estate transaction changed before activation"
      verify_estate_disposition preimage
      load_exact_restart_authority
      validate_v3_phase_fence
    fi
    "${rollback_compose[@]}" up -d --no-build --wait --wait-timeout 300 --no-deps \
      "${restart_services[@]}"
  fi
  verify_restarted_and_excluded_services
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    "${HOLDFAST_TEST_SIGKILL_AFTER_SERVICE_REACTIVATION:-0}" == "1" ]]; then
    kill -KILL "$$"
  fi
  if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
    revalidate_v3_successor_authority "$state_file"
    validate_v3_phase_fence
    validate_rollback_arm
    validate_runtime_restore_phase_receipt
    validate_phase_state_binding rollback_runtime_restore_phase_receipt \
      rollback_runtime_restore_phase_receipt_sha256 "$runtime_phase_name" "$runtime_phase_sha"
    validate_estate_restore_phase_receipt
    validate_phase_state_binding rollback_estate_restore_phase_receipt \
      rollback_estate_restore_phase_receipt_sha256 "$estate_phase_name" "$estate_phase_sha"
    [[ "$(jq -er '.schema_version == 1 and .state == "restored"' \
      "$backup/estate/TRANSACTION.json")" == "true" ]] || \
      holdfast_die "schema-v3 restored estate transaction changed before service phase commit"
    verify_estate_disposition preimage
    load_exact_restart_authority
    verify_restarted_and_excluded_services
    validate_v3_phase_fence
  fi
  persist_services_reactivated_phase
fi

if [[ "$current_state" == "rollback_services_reactivated_done" || \
  "$current_state" == "rolled_back" ]]; then
  validate_services_reactivated_phase_receipt
  validate_phase_state_binding rollback_services_reactivated_phase_receipt \
    rollback_services_reactivated_phase_receipt_sha256 "$services_phase_name" "$services_phase_sha"
fi
snapshot_v3_phase_fence
verify_closed_bracket

reactivated_services="$expected_reactivated_services"
revalidate_v3_successor_authority "$state_file"
if [[ "$backup_successor_policy_version" == "3" || "$backup_successor_policy_version" == "4" || "$backup_successor_policy_version" == "5" ]]; then
  validate_v3_phase_fence
  validate_rollback_arm
  validate_runtime_prior_services
  validate_runtime_restore_phase_receipt
  validate_phase_state_binding rollback_runtime_restore_phase_receipt \
    rollback_runtime_restore_phase_receipt_sha256 "$runtime_phase_name" "$runtime_phase_sha"
  validate_estate_restore_phase_receipt
  validate_phase_state_binding rollback_estate_restore_phase_receipt \
    rollback_estate_restore_phase_receipt_sha256 "$estate_phase_name" "$estate_phase_sha"
  validate_services_reactivated_phase_receipt
  validate_phase_state_binding rollback_services_reactivated_phase_receipt \
    rollback_services_reactivated_phase_receipt_sha256 "$services_phase_name" "$services_phase_sha"
  verify_estate_disposition preimage
  validate_v3_phase_fence
fi
rollback_receipt_tmp="$backup/.ROLLBACK.receipt.$$"
{
  printf 'schema_version=2\n'
  printf 'rolled_back_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'rollback_armed_receipt_sha256=%s\n' "$rollback_armed_sha"
  printf 'running_services_sha256=%s\n' "$rollback_manifest_sha"
  printf 'runtime_prior_services_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")"
  printf 'runtime_restore_phase_receipt_sha256=%s\n' "$runtime_phase_sha"
  printf 'estate_restore_phase_receipt_sha256=%s\n' "$estate_phase_sha"
  printf 'services_reactivated_phase_receipt_sha256=%s\n' "$services_phase_sha"
  printf 'route_close_receipt=%s\n' "$route_receipt_name"
  printf 'route_close_receipt_sha256=%s\n' "$(holdfast_sha256 "$route_receipt")"
  printf 'route_close_preimage=%s\n' "$route_preimage_name"
  printf 'route_close_preimage_sha256=%s\n' "$(holdfast_sha256 "$route_preimage")"
  printf 'revocation_evidence_sha256=%s\n' "$(holdfast_sha256 "$revocation_evidence")"
  printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$open_evidence")"
  printf 'runtime_restore_receipt_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/RESTORE.receipt")"
  printf 'estate_transaction_sha256=%s\n' "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")"
  printf 'runtime_restore=passed\n'
  printf 'mixed_estate_restore=passed\n'
  printf 'orphan_cleanup=passed\n'
  printf 'service_reactivation=passed\n'
  printf 'reactivated_services=%s\n' "$reactivated_services"
  printf 'excluded_services_inactive=passed\n'
  printf 'activation_policy=restore-exact-prior-running\n'
  printf 'activate_services_requested=%s\n' "$activation_requested"
  printf 'public_route_state=dual-stack-404\n'
  printf 'ingress_opened=false\n'
  append_successor_lineage_receipt_fields
} >"$rollback_receipt_tmp"
commit_atomic_file "$rollback_receipt_tmp" "$rollback_receipt"
if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
  "${HOLDFAST_TEST_SIGKILL_AFTER_ROLLBACK_RECEIPT:-0}" == "1" ]]; then
  kill -KILL "$$"
fi
validate_completed_rollback_receipt "$rollback_receipt"
finalize_rollback_state "$rollback_receipt"
echo "checksum-bound estate and runtime were restored; ingress remains closed"
