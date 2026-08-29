#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --estate-root PATH --output NEW_PATH [--successor --current-state FILE --predecessor-candidate PATH --predecessor-stage PATH --recovery-completion-root PATH --release-tool-revision COMMIT]" >&2
  exit 2
}

estate_root=""
output=""
successor=false
current_state=""
predecessor_candidate=""
predecessor_stage=""
recovery_completion_root=""
release_tool_revision=""
while (($#)); do
  case "$1" in
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
    --successor) successor=true; shift ;;
    --current-state) [[ $# -ge 2 ]] || usage; current_state=$2; shift 2 ;;
    --predecessor-candidate) [[ $# -ge 2 ]] || usage; predecessor_candidate=$2; shift 2 ;;
    --predecessor-stage) [[ $# -ge 2 ]] || usage; predecessor_stage=$2; shift 2 ;;
    --recovery-completion-root) [[ $# -ge 2 ]] || usage; recovery_completion_root=$2; shift 2 ;;
    --release-tool-revision) [[ $# -ge 2 ]] || usage; release_tool_revision=$2; shift 2 ;;
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
render_args=(
  --estate-root "$estate_root"
  --stage-root "$output"
  --catalog-only
)
if [[ "$successor" == true ]]; then
  [[ -n "$current_state" && -n "$predecessor_candidate" && -n "$predecessor_stage" && -n "$release_tool_revision" ]] || usage
  for path in "$current_state" "$predecessor_candidate" "$predecessor_stage"; do
    [[ "$path" = /* && "$path" != "/" ]] || usage
  done
  if [[ -n "$recovery_completion_root" ]]; then
    [[ "$recovery_completion_root" = /* && "$recovery_completion_root" != "/" ]] || usage
  fi
  [[ "$release_tool_revision" =~ ^[0-9a-f]{40}$ ]] || usage
  render_args+=(
    --successor
    --current-state "$current_state"
    --predecessor-candidate "$predecessor_candidate"
    --predecessor-stage "$predecessor_stage"
    --release-tool-revision "$release_tool_revision"
  )
  if [[ -n "$recovery_completion_root" ]]; then
    render_args+=(--recovery-completion-root "$recovery_completion_root")
  fi
elif [[ -n "$current_state" || -n "$predecessor_candidate" || -n "$predecessor_stage" || -n "$recovery_completion_root" || -n "$release_tool_revision" ]]; then
  usage
fi
exec python3 "$script_dir/render.py" "${render_args[@]}"
