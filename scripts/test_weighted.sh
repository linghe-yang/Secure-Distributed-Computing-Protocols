#!/usr/bin/env bash
# Distributed weighted tests: one node executable and one configuration per process.
set -euo pipefail
cd "$(dirname "$0")/.."
protocol="${1:-all}"
case "$protocol" in all|wra|wavid|wrbc|wgather|wbinaa) ;; *) echo "Unknown weighted protocol: $protocol" >&2; exit 2 ;; esac
command -v python3 >/dev/null || { echo "Python 3 is required for result validation" >&2; exit 2; }
cargo_options=()
if [[ "${OFFLINE:-1}" == 1 ]]; then cargo_options+=(--offline); fi
build_type="${TYPE:-debug}"
case "$build_type" in debug) ;; release) cargo_options+=(--release) ;; *) echo "TYPE must be debug or release" >&2; exit 2 ;; esac
cargo build "${cargo_options[@]}" -p genconfig -p node --bin genconfig --bin node
if [[ "$protocol" == all ]]; then protocols=(wra wavid wrbc wgather wbinaa); else protocols=("$protocol"); fi
weights="${WEIGHTS:-5,3,2,1}"
threshold="${WEIGHT_THRESHOLD:-3}"
absent="${ABSENT:-}"
IFS="," read -r -a weight_array <<< "$weights"
num_nodes="${#weight_array[@]}"
test_timeout="${TEST_TIMEOUT:-40}"
bits="${BINAA_BITS:-8}"
payload_bytes="${PAYLOAD_BYTES:-65536}"
log_root="${LOG_DIR:-logs/weighted}"
mkdir -p -- "$log_root"
test_directory="$(mktemp -d "$log_root/$(date +%Y%m%d-%H%M%S)-XXXXXXXX")"
pids=()
stop_nodes() {
    local pid any_running status=0 stop_deadline=$((SECONDS + 3))
    for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    while (( SECONDS < stop_deadline )); do
        any_running=0
        for pid in "${pids[@]}"; do if kill -0 "$pid" 2>/dev/null; then any_running=1; fi; done
        if (( any_running == 0 )); then break; fi
        sleep 0.1
    done
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then echo "Node $pid did not stop gracefully" >&2; kill -KILL "$pid" 2>/dev/null || true; status=1; fi
        wait "$pid" || status=1
    done
    pids=()
    return "$status"
}
cleanup() {
    local status=$?
    stop_nodes || true
    if (( status != 0 )); then echo "Test failed; configurations and logs retained at $test_directory" >&2; fi
    exit "$status"
}
trap cleanup EXIT
trap "exit 130" INT
trap "exit 143" TERM
config_directory="$test_directory/config"
./target/"$build_type"/genconfig --NumNodes "$num_nodes" --delay 100 --blocksize 100 --base_port "${BASE_PORT:-24500}" --client_base_port "${CLIENT_BASE_PORT:-29000}" --client_run_port "${CLIENT_RUN_PORT:-29500}" --target "$config_directory" --weights "$weights" --weight-threshold "$threshold"
order_text="$(python3 scripts/check_weighted_results.py plan --config-dir "$config_directory" --absent "$absent" --order "${START_ORDER:-}" --bits "$bits" --payload-bytes "$payload_bytes" --timeout "$test_timeout")"
read -r -a launch_order <<< "$order_text"
echo "Distributed test files: $test_directory"
for component in "${protocols[@]}"; do
    if [[ "${RUN_UNIT_TESTS:-1}" == 1 ]]; then cargo test "${cargo_options[@]}" -p "$component"; fi
    result_directory="$test_directory/$component/results"
    mkdir -p -- "$result_directory"
    pids=()
    for id in "${launch_order[@]}"; do
        ./target/"$build_type"/node --config "$config_directory/nodes-$id.json" --protocol "$component" --test-absent "$absent" --test-timeout "$test_timeout" --test-bits "$bits" --test-payload-bytes "$payload_bytes" --test-result "$result_directory/node-$id.json" > "$test_directory/$component/node-$id.log" 2>&1 &
        pids+=("$!")
        printf "%s %s\n" "$id" "$!" >> "$test_directory/$component/pids.txt"
        if [[ "${START_DELAY:-0}" != 0 ]]; then sleep "$START_DELAY"; fi
    done
    deadline=$((SECONDS + test_timeout + 2))
    while true; do
        complete=1
        for index in "${!launch_order[@]}"; do
            id="${launch_order[$index]}"
            if ! kill -0 "${pids[$index]}" 2>/dev/null; then
                echo "$component node $id exited before test validation" >&2
                tail -n 30 "$test_directory/$component/node-$id.log" >&2
                exit 1
            fi
            if [[ ! -f "$result_directory/node-$id.json" ]]; then complete=0; fi
        done
        if (( complete == 1 )); then break; fi
        if (( SECONDS >= deadline )); then echo "$component distributed test timed out" >&2; exit 1; fi
        sleep 0.1
    done
    python3 scripts/check_weighted_results.py check --config-dir "$config_directory" --results "$result_directory" --pids "$test_directory/$component/pids.txt" --protocol "$component" --absent "$absent" --bits "$bits" --payload-bytes "$payload_bytes"
    stop_nodes || { echo "$component process shutdown failed" >&2; exit 1; }
done
echo "Distributed tests passed; logs retained at $test_directory"
