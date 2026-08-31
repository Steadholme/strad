#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --candidate-root PATH --image-tag REGISTRY/REPO:TAG --builder-id HTTPS_URI --release-tool-revision COMMIT --metadata-file NEW_FILE --receipt NEW_FILE" >&2
  exit 2
}

require_private_directory() {
  local path=$1
  local label=$2
  [[ -d "$path" && ! -L "$path" && "$(readlink -f -- "$path")" == "$path" && \
     "$(stat -c '%u' -- "$path")" == 0 && \
     -z "$(find "$path" -maxdepth 0 -perm /077 -print -quit)" ]] || {
    echo "$label must be a canonical root-owned private directory: $path" >&2
    exit 1
  }
}

require_control_file() {
  local path=$1
  local label=$2
  [[ -f "$path" && ! -L "$path" && "$(readlink -f -- "$path")" == "$path" && \
     "$(stat -c '%u' -- "$path")" == 0 && "$(stat -c '%h' -- "$path")" == 1 ]] || {
    echo "$label must be a root-owned single-link regular file: $path" >&2
    exit 1
  }
}

snapshot_parent=""
build_snapshot=""
cleanup_snapshot() {
  set +e
  if [[ -n "$build_snapshot" && -n "$snapshot_parent" && \
        "$build_snapshot" == "$snapshot_parent"/.holdfast-access-build.* && \
        -d "$build_snapshot" && ! -L "$build_snapshot" && \
        "$(dirname -- "$build_snapshot")" == "$snapshot_parent" ]]; then
    chmod -R u+w -- "$build_snapshot" >/dev/null 2>&1
    rm -rf --one-file-system -- "$build_snapshot"
  fi
}

candidate_root=""
image_tag=""
builder_id=""
release_tool_revision=""
metadata_file=""
receipt=""
while (($#)); do
  case "$1" in
    --candidate-root) [[ $# -ge 2 ]] || usage; candidate_root=$2; shift 2 ;;
    --image-tag) [[ $# -ge 2 ]] || usage; image_tag=$2; shift 2 ;;
    --builder-id) [[ $# -ge 2 ]] || usage; builder_id=$2; shift 2 ;;
    --release-tool-revision) [[ $# -ge 2 ]] || usage; release_tool_revision=$2; shift 2 ;;
    --metadata-file) [[ $# -ge 2 ]] || usage; metadata_file=$2; shift 2 ;;
    --receipt) [[ $# -ge 2 ]] || usage; receipt=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$candidate_root" && -n "$image_tag" && -n "$builder_id" && -n "$release_tool_revision" && -n "$metadata_file" && -n "$receipt" ]] || usage
for path in "$candidate_root" "$metadata_file" "$receipt"; do
  [[ "$path" = /* && "$path" != "/" ]] || usage
done
[[ "$release_tool_revision" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "$image_tag" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+:[A-Za-z0-9._-]+$ && "$image_tag" != *@sha256:* ]] || usage
[[ "$builder_id" =~ ^https://[^[:space:]]+$ ]] || {
  echo "builder identity must be a stable HTTPS URI" >&2
  exit 1
}
[[ ! -e "$metadata_file" && ! -L "$metadata_file" && ! -e "$receipt" && ! -L "$receipt" ]] || {
  echo "metadata and receipt outputs must be new paths" >&2
  exit 1
}
for parent in "$(dirname -- "$metadata_file")" "$(dirname -- "$receipt")"; do
  require_private_directory "$parent" "output parent"
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
strad_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
candidate_access="$candidate_root/access-governance"
evidence="$candidate_root/RELEASE-EVIDENCE.json"
targets="$candidate_root/TARGETS.sha256"
render_inputs="$candidate_root/RENDER-INPUTS.sha256"
delta="$candidate_root/SUCCESSOR-DELTA.sha256"
require_private_directory "$(dirname -- "$candidate_root")" "candidate parent"
require_private_directory "$candidate_root" "candidate root"
[[ -d "$candidate_access" && ! -L "$candidate_access" && \
   "$(readlink -f -- "$candidate_access")" == "$candidate_access" && \
   "$(stat -c '%u' -- "$candidate_access")" == 0 ]] || {
  echo "candidate Access tree is absent or unsafe" >&2
  exit 1
}
require_control_file "$evidence" "candidate release evidence"
require_control_file "$targets" "candidate target manifest"
require_control_file "$render_inputs" "candidate render-input manifest"
require_control_file "$delta" "candidate successor delta"
for output in "$metadata_file" "$receipt"; do
  output_parent=$(dirname -- "$output")
  [[ "$output_parent" != "$candidate_root" && \
     "$output_parent" != "$candidate_root"/* ]] || {
    echo "build outputs must be outside the immutable candidate root" >&2
    exit 1
  }
done
[[ "$(git -C "$strad_root" rev-parse HEAD)" == "$release_tool_revision" ]] || {
  echo "release tool revision differs from Strad HEAD" >&2
  exit 1
}
[[ -z "$(git -C "$strad_root" status --porcelain=v1 --untracked-files=all -- ops/holdfast)" ]] || {
  echo "Holdfast release tooling checkout is not clean" >&2
  exit 1
}

snapshot_parent=$(dirname -- "$metadata_file")
require_private_directory "$snapshot_parent" "build snapshot parent"
build_snapshot=$(mktemp -d --tmpdir="$snapshot_parent" .holdfast-access-build.XXXXXXXXXX)
[[ "$(dirname -- "$build_snapshot")" == "$snapshot_parent" && \
   "$(basename -- "$build_snapshot")" == .holdfast-access-build.* ]] || {
  echo "mktemp returned a build snapshot outside its authority parent" >&2
  exit 1
}
require_private_directory "$build_snapshot" "build snapshot"
trap cleanup_snapshot EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot_candidate="$build_snapshot/candidate"
mkdir -m 0700 -- "$snapshot_candidate"
cp -a -- "$candidate_root/." "$snapshot_candidate/"
if [[ -n "$(find "$snapshot_candidate" ! -type f ! -type d -print -quit)" ]]; then
  echo "candidate snapshot contains a non-regular object" >&2
  exit 1
fi
if [[ -n "$(find "$snapshot_candidate" ! -user root -print -quit)" ]]; then
  echo "candidate snapshot contains a non-root-owned object" >&2
  exit 1
fi
ignored_entry=$(find "$snapshot_candidate" \
  \( -type d \( -name .git -o -name .workflow -o -name target -o -name __pycache__ \) \
     -o -type f \( -name '*.pyc' -o -name '*.log' \) \) \
  -print -quit)
[[ -z "$ignored_entry" ]] || {
  echo "candidate snapshot contains Docker-irrelevant ignored debris: $ignored_entry" >&2
  exit 1
}
find "$snapshot_candidate" -type f -exec chmod 0400 -- {} +
for recovery_file in RECOVERY-COMPLETION-ATTESTATION.json \
  RECOVERY-COMPLETION-ATTESTATION.sig RECOVERY-COMPLETION-ATTESTATION.pub; do
  if [[ -e "$snapshot_candidate/$recovery_file" || \
    -L "$snapshot_candidate/$recovery_file" ]]; then
    require_control_file \
      "$snapshot_candidate/$recovery_file" "snapshotted recovery completion authority"
    chmod 0600 -- "$snapshot_candidate/$recovery_file"
  fi
done
if jq -e '.predecessor_binding.recovery_completion? != null' \
  "$snapshot_candidate/RELEASE-EVIDENCE.json" >/dev/null; then
  mapfile -t recovery_completion_files < <(
    jq -er \
      '.predecessor_binding.recovery_completion |
       [.archive,.receipt,.armed_receipt,.failure_receipt][]' \
      "$snapshot_candidate/RELEASE-EVIDENCE.json"
  )
  [[ "${#recovery_completion_files[@]}" -eq 4 ]] || {
    echo "snapshotted Gen5 recovery completion file set is not exact" >&2
    exit 1
  }
  for recovery_file in "${recovery_completion_files[@]}"; do
    [[ "$recovery_file" == "${recovery_file##*/}" && \
       "${#recovery_file}" -le 200 && \
       "$recovery_file" =~ ^APPLY-[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
      echo "snapshotted Gen5 recovery completion filename is invalid" >&2
      exit 1
    }
    require_control_file \
      "$snapshot_candidate/$recovery_file" "snapshotted Gen5 recovery completion authority"
    chmod 0600 -- "$snapshot_candidate/$recovery_file"
  done
fi
find "$snapshot_candidate" -mindepth 1 -type d -exec chmod 0500 -- {} +
chmod 0700 -- "$snapshot_candidate"

candidate_root="$snapshot_candidate"
candidate_access="$candidate_root/access-governance"
evidence="$candidate_root/RELEASE-EVIDENCE.json"
targets="$candidate_root/TARGETS.sha256"
render_inputs="$candidate_root/RENDER-INPUTS.sha256"
delta="$candidate_root/SUCCESSOR-DELTA.sha256"
require_private_directory "$build_snapshot" "build snapshot"
[[ -d "$candidate_access" && ! -L "$candidate_access" && \
   "$(readlink -f -- "$candidate_access")" == "$candidate_access" && \
   "$(stat -c '%u' -- "$candidate_access")" == 0 ]] || {
  echo "snapshotted Access tree is absent or unsafe" >&2
  exit 1
}
require_control_file "$evidence" "snapshotted release evidence"
require_control_file "$targets" "snapshotted target manifest"
require_control_file "$render_inputs" "snapshotted render-input manifest"
require_control_file "$delta" "snapshotted successor delta"

python3 "$script_dir/validate_release_evidence.py" \
  --evidence "$evidence" \
  --successor-policy "$script_dir/successor-policy.json"
jq -e \
  --arg revision "$release_tool_revision" \
  '.schema_version == 2 and
   .release_mode == "successor" and
   .catalog_only == true and
   .release == {} and
   .access_governance_build_input_schema == "access-build-input/2" and
   .holdfast_release_tool_revision == $revision' \
  "$evidence" >/dev/null
python3 "$script_dir/render_input_binding.py" verify \
  --ops-root "$script_dir" \
  --manifest "$render_inputs" \
  --stage-root "$candidate_root" \
  --release-evidence "$evidence" \
  --expected-mode successor-catalog \
  --require-root-owner
(
  cd "$candidate_root"
  sha256sum --check TARGETS.sha256
)
observed_build_input=$(python3 - "$script_dir" "$candidate_root" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from render_input_binding import access_build_input_sha_v2

print(access_build_input_sha_v2(Path(sys.argv[2]), require_root_owner=True))
PY
)
expected_build_input=$(jq -r '.access_governance_build_input_sha256' "$evidence")
[[ "$observed_build_input" == "$expected_build_input" ]] || {
  echo "candidate Access build input differs from release evidence" >&2
  exit 1
}

docker buildx build \
  --file "$candidate_access/Dockerfile" \
  --platform linux/amd64 \
  --provenance="mode=max,builder-id=$builder_id" \
  --sbom=true \
  --metadata-file "$metadata_file" \
  --tag "$image_tag" \
  --push \
  "$candidate_access"
image_digest=$(jq -er '."containerimage.digest" | select(test("^sha256:[0-9a-f]{64}$"))' "$metadata_file")
image_ref="${image_tag%:*}@${image_digest}"
docker buildx imagetools inspect "$image_ref" >/dev/null
observed_builder_id=$(
  docker buildx imagetools inspect "$image_ref" \
    --format '{{json .Provenance.SLSA.runDetails.builder.id}}' |
    jq -er 'select(type == "string" and length >= 8)'
)
[[ "$observed_builder_id" == "$builder_id" ]] || {
  echo "registry provenance builder identity differs from the requested builder" >&2
  exit 1
}

umask 077
set -o noclobber
{
  printf 'schema=holdfast-access-candidate-build/1\n'
  printf 'platform=linux/amd64\n'
  printf 'image=%s\n' "$image_ref"
  printf 'build_input_schema=access-build-input/2\n'
  printf 'build_input_sha256=%s\n' "$observed_build_input"
  printf 'candidate_evidence_sha256=%s\n' "$(sha256sum "$evidence" | cut -d' ' -f1)"
  printf 'candidate_targets_sha256=%s\n' "$(sha256sum "$targets" | cut -d' ' -f1)"
  printf 'render_inputs_sha256=%s\n' "$(sha256sum "$render_inputs" | cut -d' ' -f1)"
  printf 'metadata_sha256=%s\n' "$(sha256sum "$metadata_file" | cut -d' ' -f1)"
  printf 'holdfast_release_tool_revision=%s\n' "$release_tool_revision"
  printf 'provenance=mode.max\n'
  printf 'provenance_builder_id=%s\n' "$observed_builder_id"
  printf 'sbom=enabled\n'
} >"$receipt"
chmod 0600 "$metadata_file" "$receipt"
echo "Access candidate pushed: $image_ref"
