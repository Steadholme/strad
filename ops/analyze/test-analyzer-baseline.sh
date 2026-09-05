#!/usr/bin/env bash
set -euo pipefail

image=""
output=""
while (($# > 0)); do
  case "$1" in
    --image)
      image="${2:-}"
      shift 2
      ;;
    --output)
      output="${2:-}"
      shift 2
      ;;
    *)
      echo "unknown argument" >&2
      exit 64
      ;;
  esac
done

test -n "$image"
test -n "$output"
docker image inspect "$image" >/dev/null

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
expected_output="$script_root/evidence/analyzer-baseline-v1.json"
case "$output" in
  ops/analyze/evidence/analyzer-baseline-v1.json)
    output="$expected_output"
    ;;
  "$expected_output") ;;
  *)
    echo "--output must target ops/analyze/evidence/analyzer-baseline-v1.json" >&2
    exit 64
    ;;
esac
if [ -e "$output" ]; then unlink "$output"; fi

docker run --rm --entrypoint sh "$image" -ec '
  test "$(id -u)" = 1000
  test "$(id -g)" = 1000
  test "$(getent passwd 1000 | cut -d: -f6)" = /home/rikune
  test -d /home/rikune
  test -w /home/rikune
  test "$HOME" = /home/rikune
'

container="strad-analyzer-baseline-${RANDOM}-$$"
probe_root="$(mktemp -d /tmp/strad-analyzer-baseline.XXXXXX)"
bridge_token="$(openssl rand -hex 32)"
file_key="$(openssl rand -hex 32)"
receipt_tmp=""

cleanup() {
  docker stop --time 1 "$container" >/dev/null 2>&1 || true
  docker rm "$container" >/dev/null 2>&1 || true
  if [ -n "$receipt_tmp" ] && [ -e "$receipt_tmp" ]; then unlink "$receipt_tmp"; fi
  find "$probe_root" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p \
  "$probe_root/workspaces/ghidra-projects" \
  "$probe_root/storage" \
  "$probe_root/state" \
  "$probe_root/cache" \
  "$probe_root/audit/ghidra"
chown -R 1000:1000 "$probe_root"

docker run -d --name "$container" --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 127.0.0.1::18090 \
  -v "$probe_root/workspaces:/data/workspaces" \
  -v "$probe_root/storage:/data/storage" \
  -v "$probe_root/state:/data/state" \
  -v "$probe_root/cache:/data/cache" \
  -v "$probe_root/audit:/data/audit" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700 \
  -e STRAD_BRIDGE_TOKEN="$bridge_token" \
  -e RIKUNE_FILE_SERVER_API_KEY="$file_key" \
  "$image" >/dev/null

bridge_port="$(docker port "$container" 18090/tcp | sed 's/.*://')"
ready=""
for _ in $(seq 1 240); do
  if [ "$(docker inspect -f '{{.State.Running}}' "$container")" != true ]; then
    break
  fi
  if ready="$(curl --silent --show-error --fail --max-time 15 "http://127.0.0.1:${bridge_port}/readyz" 2>/dev/null)"; then
    break
  fi
  sleep 1
done
if ! printf '%s' "$ready" | jq -e '. == {"status":"ready"}' >/dev/null 2>&1; then
  echo "ASSERT: service readiness is mandatory before composite analysis" >&2
  exit 1
fi

sample="$probe_root/sample.elf"
docker cp "$container:/usr/bin/true" "$sample" >/dev/null
test "$(od -An -tx1 -N4 "$sample" | tr -d ' \n')" = 7f454c46
sample_sha256="$(sha256sum "$sample" | cut -d' ' -f1)"
sample_bytes="$(stat -c %s "$sample")"

poll_operation() {
  local operation_id="$1"
  local response state
  for _ in $(seq 1 360); do
    response="$(curl --silent --show-error --fail-with-body --max-time 15 \
      "http://127.0.0.1:${bridge_port}/internal/v1/operations/${operation_id}" \
      -H "Authorization: Bearer ${bridge_token}")"
    state="$(printf '%s' "$response" | jq -er '.data.state')"
    case "$state" in
      succeeded)
        printf '%s' "$response"
        return 0
        ;;
      failed|unknown)
        echo "ASSERT: analyzer operation entered terminal non-success state" >&2
        return 1
        ;;
      pending) sleep 1 ;;
      *)
        echo "ASSERT: analyzer operation returned an unknown state" >&2
        return 1
        ;;
    esac
  done
  echo "ASSERT: analyzer operation did not complete before deadline" >&2
  return 1
}

upload_request_sha256="$(printf 'sample-upload\n%s\n%s' "$sample_bytes" "$sample_sha256" | sha256sum | cut -d' ' -f1)"
upload_operation_id="550e8400-e29b-41d4-a716-446655440200"
curl --silent --show-error --fail-with-body --max-time 330 \
  -X POST "http://127.0.0.1:${bridge_port}/internal/v1/samples/upload" \
  -H "Authorization: Bearer ${bridge_token}" \
  -H 'Content-Type: application/octet-stream' \
  -H "Content-Length: ${sample_bytes}" \
  -H "X-Content-SHA256: ${sample_sha256}" \
  -H "X-Operation-ID: ${upload_operation_id}" \
  -H "X-Request-SHA256: ${upload_request_sha256}" \
  --data-binary "@${sample}" >/dev/null
upload_result="$(poll_operation "$upload_operation_id")"
sample_id="$(printf '%s' "$upload_result" | jq -er --arg digest "$sample_sha256" \
  'if .data.result.sample_id == ("sha256:" + $digest) and (.data.result.file_type | type) == "string" then .data.result.sample_id else error("bridge upload identity mismatch") end')"

start_body="$(jq -cn --arg sample_id "$sample_id" \
  '{action:"start",sample_id:$sample_id,goal:"static",depth:"balanced",backend_policy:"auto",allow_transformations:false,allow_live_execution:false,force_refresh:false,include_raw_result:false}')"
start_sha256="$(printf '%s' "$start_body" | sha256sum | cut -d' ' -f1)"
start_operation_id="550e8400-e29b-41d4-a716-446655440201"
curl --silent --show-error --fail-with-body --max-time 330 \
  -X POST "http://127.0.0.1:${bridge_port}/internal/v1/workflows/start" \
  -H "Authorization: Bearer ${bridge_token}" \
  -H 'Content-Type: application/json' \
  -H "X-Operation-ID: ${start_operation_id}" \
  -H "X-Request-SHA256: ${start_sha256}" \
  --data-binary "$start_body" >/dev/null
start_result="$(poll_operation "$start_operation_id")"
plan_id="$(printf '%s' "$start_result" | jq -er '.data.result.plan_id')"

promote_body="$(jq -cn --arg plan_id "$plan_id" \
  '{action:"promote",plan_id:$plan_id,through_stage:"function_map",allow_transformations:false,allow_live_execution:false,force_refresh:false,include_raw_result:false}')"
promote_sha256="$(printf '%s' "$promote_body" | sha256sum | cut -d' ' -f1)"
status_body="$(jq -cn --arg plan_id "$plan_id" \
  '{action:"status",plan_id:$plan_id,include_raw_result:false}')"
status="$(printf '%s' "$start_result" | jq -c '.data.result')"

fetch_status() {
  local response
  response="$(curl --silent --show-error --fail-with-body --max-time 30 \
    -X POST "http://127.0.0.1:${bridge_port}/internal/v1/workflows/status" \
    -H "Authorization: Bearer ${bridge_token}" \
    -H 'Content-Type: application/json' \
    --data-binary "$status_body")"
  printf '%s' "$response" | jq -c '.data'
}

for operation_suffix in 202 203 204; do
  if printf '%s' "$status" | jq -e '.latest_stage == "function_map"' >/dev/null 2>&1; then
    break
  fi
  stage_before="$(printf '%s' "$status" | jq -er '.latest_stage')"
  promote_operation_id="550e8400-e29b-41d4-a716-446655440${operation_suffix}"
  curl --silent --show-error --fail-with-body --max-time 330 \
    -X POST "http://127.0.0.1:${bridge_port}/internal/v1/workflows/promote" \
    -H "Authorization: Bearer ${bridge_token}" \
    -H 'Content-Type: application/json' \
    -H "X-Operation-ID: ${promote_operation_id}" \
    -H "X-Request-SHA256: ${promote_sha256}" \
    --data-binary "$promote_body" >/dev/null
  promote_result="$(poll_operation "$promote_operation_id")"
  status="$(printf '%s' "$promote_result" | jq -c '.data.result')"
  advanced=0
  for _ in $(seq 1 360); do
    latest_stage="$(printf '%s' "$status" | jq -er '.latest_stage')"
    if [ "$latest_stage" = function_map ]; then
      advanced=1
      break
    fi
    if [ "$latest_stage" != "$stage_before" ] && printf '%s' "$status" | jq -e \
      --arg latest "$latest_stage" \
      'any(.stage_statuses[]; .stage == $latest and (.status == "completed" or .status == "reused"))' \
      >/dev/null 2>&1; then
      advanced=1
      break
    fi
    status="$(fetch_status)"
    sleep 1
  done
  if [ "$advanced" -ne 1 ]; then
    echo "ASSERT: workflow promotion did not advance before deadline" >&2
    exit 1
  fi
done
if ! printf '%s' "$status" | jq -e '.latest_stage == "function_map"' >/dev/null 2>&1; then
  echo "ASSERT: workflow never reached function_map" >&2
  exit 1
fi
for _ in $(seq 1 360); do
  if printf '%s' "$status" | jq -e '
    .function_index_ready == true and
    any(.stage_statuses[]; .stage == "function_map" and (.status == "completed" or .status == "reused"))
  ' >/dev/null 2>&1; then
    break
  fi
  status="$(fetch_status)"
  sleep 1
done

ghidra_stage_status="$(printf '%s' "$status" | jq -er \
  '[.stage_statuses[] | select(.stage == "function_map")][0].status')"
printf '%s' "$status" | jq -e \
  '.function_index_ready == true and any(.stage_statuses[]; .stage == "function_map" and (.status == "completed" or .status == "reused"))' \
  >/dev/null

ghidra_functions_files="$(find "$probe_root/workspaces" -type f -path '*/ghidra/functions_*.json' | wc -l)"
if [ "$ghidra_functions_files" -ne 1 ]; then
  echo "ASSERT: exactly one Ghidra function-index artifact is mandatory" >&2
  exit 1
fi
ghidra_functions_path="$(find "$probe_root/workspaces" -type f -path '*/ghidra/functions_*.json' -print -quit)"
ghidra_function_count="$(jq -er \
  'if (.function_count | type) == "number" and .function_count > 0 and .function_count == (.functions | length) then .function_count else error("invalid Ghidra function index") end' \
  "$ghidra_functions_path")"
ghidra_functions_sha256="$(sha256sum "$ghidra_functions_path" | cut -d' ' -f1)"
ghidra_project_files="$(find "$probe_root/workspaces/ghidra-projects" -type f -name '*.gpr' | wc -l)"
ghidra_log_files="$(find "$probe_root/audit/ghidra" -type f | wc -l)"
if [ "$ghidra_project_files" -lt 1 ] || [ "$ghidra_log_files" -lt 1 ]; then
  echo "ASSERT: real Ghidra project and log evidence are mandatory" >&2
  exit 1
fi

image_id="$(docker image inspect "$image" --format '{{.Id}}')"
mkdir -p "$(dirname "$output")"
receipt_tmp="$(mktemp "${output}.tmp.XXXXXX")"
jq -n \
  --arg image_id "$image_id" \
  --arg sample_sha256 "$sample_sha256" \
  --argjson sample_bytes "$sample_bytes" \
  --arg plan_id "$plan_id" \
  --arg ghidra_stage_status "$ghidra_stage_status" \
  --arg ghidra_functions_sha256 "$ghidra_functions_sha256" \
  --argjson ghidra_function_count "$ghidra_function_count" \
  --argjson ghidra_project_files "$ghidra_project_files" \
  --argjson ghidra_log_files "$ghidra_log_files" \
  --arg completed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{schema_version:1,status:"passed",service_ready:true,passwd_home:"/home/rikune",image_id:$image_id,sample:{kind:"image_usr_bin_true_elf",upload_path:"bridge_internal_v1_samples_upload",sha256:$sample_sha256,bytes:$sample_bytes},workflow:{plan_id:$plan_id,function_map_status:$ghidra_stage_status,function_index_ready:true},ghidra:{functions_sha256:$ghidra_functions_sha256,function_count:$ghidra_function_count,project_file_count:$ghidra_project_files,log_file_count:$ghidra_log_files},completed_at:$completed_at}' \
  >"$receipt_tmp"
chmod 0600 "$receipt_tmp"
mv "$receipt_tmp" "$output"
receipt_tmp=""
jq -e '.schema_version == 1 and .status == "passed" and .service_ready == true and .sample.upload_path == "bridge_internal_v1_samples_upload" and .workflow.function_index_ready == true and .ghidra.function_count > 0 and .ghidra.project_file_count > 0 and .ghidra.log_file_count > 0' "$output" >/dev/null
printf '%s\n' 'real Ghidra analyzer baseline: pass'
