#!/usr/bin/env bash
# Regression matrix for optimized weighted transport and storage; uses real node processes.
set -euo pipefail
cd "$(dirname "$0")/.."
export TYPE="${TYPE:-release}" TOKIO_WORKER_THREADS="${TOKIO_WORKER_THREADS:-2}"
export TEST_TIMEOUT="${TEST_TIMEOUT:-120}" RUN_UNIT_TESTS=0
cargo test --offline --release -p crypto -p util -p wra -p wavid -p wrbc -p wgather -p wbinaa
WEIGHTS=5,3,2,1 WEIGHT_THRESHOLD=3 ABSENT= START_ORDER= PAYLOAD_BYTES=65536 bash scripts/test_weighted.sh all
WEIGHTS=5,3,2,1 WEIGHT_THRESHOLD=3 ABSENT=3 START_ORDER=2,1,0 START_DELAY=0.05 PAYLOAD_BYTES=65536 bash scripts/test_weighted.sh all
WEIGHTS=10,1,1,1,1 WEIGHT_THRESHOLD=4 ABSENT=2,3,4 START_ORDER=1,0 PAYLOAD_BYTES=65536 bash scripts/test_weighted.sh all
WEIGHTS=5,3,2,1 WEIGHT_THRESHOLD=3 ABSENT= START_ORDER= PAYLOAD_BYTES=0 bash scripts/test_weighted.sh wavid
WEIGHTS=5,3,2,1 WEIGHT_THRESHOLD=3 ABSENT=3 START_ORDER=2,1,0 PAYLOAD_BYTES="${LARGE_PAYLOAD_BYTES:-8388608}" bash scripts/test_weighted.sh wrbc
if [[ "${TEST_64_NODES:-1}" == 1 ]]; then
    equal_weights="$(python3 -c 'print(",".join(["1"]*64))')"
    WEIGHTS="$equal_weights" WEIGHT_THRESHOLD=21 ABSENT= START_ORDER= PAYLOAD_BYTES=65536 bash scripts/test_weighted.sh all
fi
