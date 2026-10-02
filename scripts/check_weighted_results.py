#!/usr/bin/env python3
"""Validate configuration, launch order, and outputs from separate node processes."""
import argparse
import hashlib
import json
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value):
    return int(value, 16 if value.startswith("0x") else 10)


def load_plan(directory, absent_text, order_text):
    first = json.loads((directory / "nodes-0.json").read_text())
    count = first["num_nodes"]
    weights = [integer(w) for w in first["weights"]]
    threshold = integer(first["weight_threshold"])
    require(len(weights) == count and all(w > 0 for w in weights), "invalid weight table")
    require(0 < threshold and 3 * threshold <= sum(weights), "invalid exclusive threshold")
    require(any(first["session_id"]), "missing shared session ID")
    absent = [int(s.strip()) for s in absent_text.split(",") if s.strip()]
    require(len(set(absent)) == len(absent), "duplicate absent ID")
    require(all(0 <= i < count for i in absent), "unknown absent ID")
    require(sum(weights[i] for i in absent) < threshold, "absent weight must be below T")
    active = [i for i in range(count) if i not in absent]
    order = [int(s.strip()) for s in order_text.split(",") if s.strip()] if order_text else active
    require(len(order) == len(active) and set(order) == set(active), "START_ORDER must list each active node exactly once")
    for i in range(count):
        node = json.loads((directory / f"nodes-{i}.json").read_text())
        require(node["id"] == i and node["num_nodes"] == count, "config ID mismatch")
        require((node["weights"], node["weight_threshold"], node["session_id"]) == (
            first["weights"], first["weight_threshold"], first["session_id"]
        ), "inconsistent public configuration")
    return first, weights, threshold, active, order


def check(directory, results, protocol, absent, bits, payload_bytes, pid_file):
    config, weights, threshold, active, _ = load_plan(directory, absent, "")
    expected_names = {f"node-{i}.json" for i in active}
    require({p.name for p in results.glob("*.json")} == expected_names, "missing or unexpected node results")
    reports = [json.loads((results / f"node-{i}.json").read_text()) for i in active]
    recorded_pids = None
    if pid_file is not None:
        rows = [tuple(map(int, line.split())) for line in pid_file.read_text().splitlines()]
        require(all(len(row) == 2 for row in rows), "invalid PID file")
        recorded_pids = dict(rows)
        require(len(rows) == len(active) and set(recorded_pids) == set(active), "PID file does not match active nodes")
    pids = set()
    for i, report in zip(active, reports):
        require(report["event"] == "output" and report["protocol"] == protocol, "wrong result kind")
        require(report["node"] == i and report["session_id"] == config["session_id"], "wrong node/session")
        pid = report["pid"]
        require(type(pid) is int and pid > 0 and pid not in pids, "nodes must run in different processes")
        if recorded_pids is not None:
            require(recorded_pids[i] == pid, "result PID differs from launched process")
        pids.add(pid)
    values = [r["result"] for r in reports]
    if protocol == "wra":
        require(all(value is True for value in values), "WRA unanimous input violated")
    elif protocol in ("wavid", "wrbc"):
        pattern = bytes((i * 31 + 17) % 256 for i in range(256))
        payload = pattern * (payload_bytes // 256) + pattern[:payload_bytes % 256]
        expected = {"bytes": payload_bytes, "sha256": hashlib.sha256(payload).hexdigest()}
        require(all(value == expected for value in values), "incorrect file or inconsistent delivery")
    elif protocol == "wgather":
        core = set(active)
        for value in values:
            require(isinstance(value, list) and all(type(i) is int for i in value), "invalid Gather set")
            require(len(set(value)) == len(value) and set(value) <= set(active), "unvalidated Gather dealer")
            require(sum(weights[i] for i in value) > sum(weights) - threshold, "Gather output below quorum")
            core.intersection_update(value)
        require(sum(weights[i] for i in core) > sum(weights) - threshold, "Gather common core below quorum")
    elif protocol == "wbinaa":
        for value in values:
            require(isinstance(value, list) and len(value) == config["num_nodes"], "wrong BinAA vector size")
        for coordinate in range(config["num_nodes"]):
            numerators = []
            for value in values:
                dyadic = value[coordinate]
                require(dyadic["exponent"] == bits, "unexpected BinAA precision")
                numerator = int(dyadic["numerator"])
                require(0 <= numerator <= 1 << bits, "BinAA interval validity violated")
                numerators.append(numerator)
            require(max(numerators) - min(numerators) <= 1, "BinAA agreement exceeds requested precision")
            if coordinate == 0:
                require(all(n == 0 for n in numerators), "unanimous zero violated")
            if coordinate == 1:
                require(all(n == 1 << bits for n in numerators), "unanimous one violated")
    else:
        raise AssertionError(f"unknown protocol: {protocol}")
    print(json.dumps({"protocol": protocol, "status": "passed", "participants": active,
                      "pids": [r["pid"] for r in reports], "results": str(results)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "check"))
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--absent", default="")
    parser.add_argument("--order", default="")
    parser.add_argument("--results", type=Path)
    parser.add_argument("--pids", type=Path)
    parser.add_argument("--protocol", choices=("wra", "wavid", "wrbc", "wgather", "wbinaa"))
    parser.add_argument("--bits", type=int, default=8)
    parser.add_argument("--payload-bytes", type=int, default=65536)
    parser.add_argument("--timeout", type=int, default=40)
    args = parser.parse_args()
    require(0 <= args.bits <= 4096, "BINAA_BITS must be in 0..4096")
    require(0 <= args.payload_bytes <= 64 * 1024 * 1024, "PAYLOAD_BYTES must be in 0..64 MiB")
    require(0 < args.timeout <= 2147483647, "TEST_TIMEOUT must be a positive integer up to 2147483647")
    if args.mode == "plan":
        _, _, _, _, order = load_plan(args.config_dir, args.absent, args.order)
        print(" ".join(map(str, order)))
    else:
        if args.results is None or args.protocol is None:
            parser.error("check requires --results and --protocol")
        check(args.config_dir, args.results, args.protocol, args.absent, args.bits, args.payload_bytes, args.pids)


if __name__ == "__main__":
    main()
