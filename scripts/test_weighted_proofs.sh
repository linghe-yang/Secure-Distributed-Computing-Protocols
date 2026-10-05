#!/usr/bin/env bash
# Real processes: silent holder, configurable layouts, and recovered source proofs.
set -euo pipefail
cd "$(dirname "$0")/.."
export TYPE="${TYPE:-release}" TOKIO_WORKER_THREADS="${TOKIO_WORKER_THREADS:-2}"
export TEST_TIMEOUT="${TEST_TIMEOUT:-120}" RUN_UNIT_TESTS=0
cargo test --offline --release -p crypto -p util -p wra -p wavid -p wrbc -p wgather -p wbinaa
for block in 32 64 256 4096; do
    for protocol in wavid wrbc; do
        WEIGHTS=5,3,2,1 WEIGHT_THRESHOLD=3 ABSENT=3 START_ORDER=2,1,0 START_DELAY=0.02 BLOCK_BYTES="$block" PAYLOAD_BYTES=131109 bash scripts/test_weighted.sh "$protocol"
    done
done
BLOCK_BYTES=128 PAYLOAD_BYTES=0 bash scripts/test_weighted.sh wavid
BLOCK_BYTES=256 PAYLOAD_BYTES="${LARGE_PAYLOAD_BYTES:-8388608}" ABSENT=3 bash scripts/test_weighted.sh wrbc
if [[ "${TEST_64_NODES:-1}" == 1 ]]; then
    equal_weights="$(python3 -c 'print(",".join(["1"]*64))')"
    for protocol in wavid wrbc; do
        WEIGHTS="$equal_weights" WEIGHT_THRESHOLD=21 ABSENT=63 BLOCK_BYTES=128 PAYLOAD_BYTES=65573 bash scripts/test_weighted.sh "$protocol"
    done
fi
