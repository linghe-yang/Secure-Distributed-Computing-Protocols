# Secure Distributed Computing Protocols

This repository implements a collection of secure distributed computing protocols that serve as building blocks for larger distributed systems. The protocols are designed to provide security guarantees in adversarial environments. 
However, this code has been written as a research prototype and has not been vetted for security. 
Therefore, this repository can contain serious security vulnerabilities. 
Use at your own risk.

## Repository Structure

### Core Protocol Modules
#### **Broadcast Protocols** ([`broadcast/`](broadcast/))
- **CTRBC (Cachin-Tessaro's Reliable Broadcast Protocol)** ([`broadcast/ctrbc/`](broadcast/ctrbc/)) - Cachin-Tessaro's Reliable broadcast protocol based on the protocol in `CT05`. 

- **ECC-RBC (Error-Correcting Code Reliable Broadcast)** ([`broadcast/ecc_rbc/`](broadcast/ecc_rbc/)) - Reliable broadcast using Reed-Solomon error-correcting codes in `NDD+22`.


#### **Dissemination Protocols** ([`dissemination/`](dissemination/))
- **ASKS (Asynchronous Secret Key Sharing)/ AwVSS (Asynchronous weak Verifiable Secret Sharing)** ([`dissemination/asks/`](dissemination/asks/)) - ASKS/AwVSS protocol in the `DDL+24,BBB+24`. 

- **AVID (Asynchronous Verifiable Information Dispersal)** ([`dissemination/avid/`](dissemination/avid/)) - Verifiable information dispersal protocols based on DispersedLedger `SPA+22`. 


#### **Consensus Protocols** ([`consensus/`](consensus/))

- **ACS (Asynchronous Common Subset)** ([`consensus/acs/`](consensus/acs/)) - Implements asynchronous common subset consensus protocol in the `DDL+24`
- **Binary Byzantine Agreement** ([`consensus/binary_ba/`](consensus/binary_ba/)) - Asynchronous Binary BA in `IBY22`.
- **FIN-MVBA (Finite Multi-Valued Byzantine Agreement)** ([`consensus/fin_mvba/`](consensus/fin_mvba/)) - Asynchronous Multi-valued Byzantine agreement protocol in FIN (`SWZ23`).
- **IBFT (Istanbul Byzantine Fault Tolerance)** ([`consensus/ibft/`](consensus/ibft/)) - PBFT-style Leader-based consensus protocol only using Message Authentication Codes in `Hen20`. 
- **RA (Reliable Agreement)** ([`consensus/ra/`](consensus/ra/)) - Reliable agreement protocol in `DDL+24`

## Building and Usage

This is a Rust project using Cargo. The compatibility between dependencies has been tested for Rust version `1.83.0`. To build all components:

```bash
cargo build --release
```
Run the following sequence of steps to start a protocol. 

1. **Generate Configuration Files**: This step generates the necessary configuration files for an $n$ party distributed system. 
```
mkdir testdata/
./target/release/genconfig --base_port 15000 --client_base_port 19000 --client_run_port 19500 --NumNodes 4 --blocksize 100 --delay 100 --target testdata/ --local true
```
These instructions generate configuration files for $n=4$ parties. Party $i$ runs on port `15000+i`, listens to requests on port `19000+i`, and syncs with a global synchronizer (this part is optional) on port `19500`. Please ensure the directory has been created to run this command. 

2. **Create channels and invoke protocol**: The following snippet of code illustrates a basic composition of distributed protocols. 
```rust
pub async fn spawn(config: Node)-> (anyhow::Result<oneshot::Sender<()>>, Vec<Result<oneshot::Sender<()>>>){
    // ctrbc_req_send_channel: Request sending channel, request receiving channel. The sending channel can be used to issue message requests to the RBC module. 
    // ctrbc_req_recv_channel: Request receiving channel - passed as an argument. The RBC module listens to this channel. 
    let (ctrbc_req_send_channel, ctrbc_req_recv_channel) = channel(10000);
    
    // ctrbc_out_send_channel: Output sending channel - passed as an argument. The RBC module sends outputs on this channel. 
    // ctrbc_out_recv_channel: Output receiving channel. We poll this channel to get outputs from RBC module.
    let (ctrbc_out_send_channel, mut ctrbc_out_recv_channel) = channel(10000);

    let mut statuses = Vec::new();

    // Start Cachin-Tessaro RBC protocol
    let _rbc_serv_status = ctrbc::Context::spawn(
        config,
        ctrbc_req_recv_channel, 
        ctrbc_out_send_channel, 
        false
    );

    statuses.push(_rbc_serv_status);
    
    let _resp = ctrbc_req_send_channel.send(Vec::new()).await.unwrap();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = ctrbc_out_recv_channel.recv() => {
                    // Execute handling logic for the received message from the channel
                    log::debug!("Received message from CTRBC channel {:?}", msg);
                    // self.process_ctrbc_event(ctrbc_msg.1, ctrbc_msg.0, ctrbc_msg.2).await;
                }
            }
        }
    });
    let (exit_tx, _exit_rx) = oneshot::channel();
    (Ok(exit_tx), vec![])
}
```
Protocols utilize `tokio` asynchronous channels or queues to receive requests and send outputs.
Each protocol takes two `tokio` channels as input: a receiver channel from which it receives requests (`req_recv` channel), and a sender channel to which it can send outputs (`out_send` channel). 
Each protocol's invocation takes these channels as arguments. 
A prominent example of protocol composition is in `consensus/acs`. 
This folder implements an Asynchronous Common Subset (ACS) protocol from Reliable Broadcast (CTRBC), Secret Key Sharing (ASKS), and Reliable Agreement (RA). 

3. **Build code and run parties**: After compiling the code, run $n=4$ parties to start the protocol. Each party waits until it establishes a tcp channel with **all** parties. 
The `scripts/test.sh` script can also be used to start all four parties locally. 


## Key Features

### Byzantine Fault Tolerance
All protocols are designed to handle Byzantine faults, where up to `t` out of `n` nodes can behave arbitrarily (where typically `n ≥ 3t + 1`).

### Asynchronous Operation
Most protocols operate in asynchronous network models, making no assumptions about message delivery times or clock synchronization.

### Modular Design
Each protocol is implemented as a separate module with well-defined interfaces, allowing them to be composed into larger systems.

### Network Abstraction
The implementation includes a robust networking layer with:
- TCP-based reliable communication
- Message acknowledgments
- Automatic connection management


## Applications

These protocols serve as building blocks for:
- Distributed ledgers and blockchains
- Secure asynchronous multi-party computation protocols
- Byzantine fault-tolerant state machine replication

## Research Context

This implementation is part of ongoing research in secure distributed computing, focusing on practical implementations of theoretically sound protocols that can handle adversarial conditions in distributed systems.

### Supporting Infrastructure

#### **Cryptographic Primitives** ([`crypto/`](crypto/))
- SHA256 Hash function, and Merkle trees based on Hardware-accelerated Hash based on AES
- Symmetric encryption (AES-based)
- Cryptographic utilities and random number generation

#### **Configuration Management** ([`config/`](config/))
- Network configuration and node setup
- Protocol parameter management

#### **Type Definitions** ([`types/`](types/))
- Common data structures and type definitions
- Replica identifiers and protocol messages

#### **Utilities** ([`util/`](util/))
- Helper functions and common utilities
- Networking abstractions

#### **Tools** ([`tools/`](tools/))
- **genconfig** - Configuration generation utility

## References
[1] Cachin, Christian, and Stefano Tessaro. "Asynchronous verifiable information dispersal." 24th IEEE Symposium on Reliable Distributed Systems (SRDS'05). IEEE, 2005.

[2] Alhaddad, Nicolas, Sourav Das, Sisi Duan, Ling Ren, Mayank Varia, Zhuolun Xiang, and Haibin Zhang. "Balanced byzantine reliable broadcast with near-optimal communication and improved computation." In Proceedings of the 2022 ACM Symposium on Principles of Distributed Computing, pp. 399-417. 2022.

[3] Das, Sourav, Sisi Duan, Shengqi Liu, Atsuki Momose, Ling Ren, and Victor Shoup. "Asynchronous consensus without trusted setup or public-key cryptography." In Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security, pp. 3242-3256. 2024.

[4] Bandarupalli, Akhil, Adithya Bhat, Saurabh Bagchi, Aniket Kate, and Michael K. Reiter. "Random beacons in monte carlo: Efficient asynchronous random beacon without threshold cryptography." In Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security, pp. 2621-2635. 2024.

[5] Yang, Lei, Seo Jin Park, Mohammad Alizadeh, Sreeram Kannan, and David Tse. "{DispersedLedger}:{High-Throughput} byzantine consensus on variable bandwidth networks." In 19th USENIX Symposium on Networked Systems Design and Implementation (NSDI 22), pp. 493-512. 2022.

[6] Abraham, Ittai, Naama Ben-David, and Sravya Yandamuri. "Efficient and adaptively secure asynchronous binary agreement via binding crusader agreement." In Proceedings of the 2022 ACM Symposium on Principles of Distributed Computing, pp. 381-391. 2022.

[7] Duan, Sisi, Xin Wang, and Haibin Zhang. "Fin: Practical signature-free asynchronous common subset in constant time." In Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security, pp. 815-829. 2023.

[8] Moniz, Henrique. "The Istanbul BFT consensus algorithm." arXiv preprint arXiv:2002.03613 (2020).
## Weighted primitives

The weighted crates are additive; existing algorithms retain their implementation.
All ten existing protocol service entry points now reject a participant weight other
than exactly 1, including equal weights such as [3, 3, 3, 3]. A missing weights field
in legacy JSON/TOML/YAML configurations means all weights are 1. Regenerate old binary
configuration files because the serialized Node layout has changed. CCBRB now uses
this workspace's config/types/crypto dependencies so it applies the same guard.

Weighted membership uses strictly positive arbitrary-precision integer weights.
Node.weights is ordered by physical node ID; Node.weight_threshold is the paper's
exclusive corrupt-weight bound T: actual corrupt weight B < T and 3T <= W, where W
is total weight. This is separate from legacy num_faults. Weights and T are serialized
as hexadecimal strings; genconfig accepts decimal or 0x-prefixed integers.
The shared session_id is generated freshly for the entire configuration bundle.

Threshold boundaries follow the Python reference: WRA, WAVID storage completion, and
WGather use strict weight > W-T quorums; relay thresholds are weight >= T. WBinAA
certification and ECHO2 termination use weight >= W-T. Do not replace these with
identity counts or change strict comparisons when configuring unit weights. For
example, four unit weights with T=1 tolerate only B=0 under this model; the old
four-node configuration with num_faults=1 retains its original meaning. Four weights
of 3 with T=4 allow one corrupt node in the weighted protocols.

| Crate | Directory | Local requests and outputs |
| --- | --- | --- |
| wra | consensus/wra | Register(header_id), Input(bit); Output(bit) |
| wavid | dissemination/wavid | Register(descriptor), Disperse, Retrieve; Stored, Complete, Result(File/Invalid) |
| wrbc | broadcast/wrbc | Register(file_bytes), Broadcast; Deliver(file) |
| wgather | consensus/wgather | Register, Start, Add(verified dealer); DeliverSet |
| wbinaa | consensus/wbinaa | Register(exact precision), Start(binary vector); DeliverVector |

Each crate follows context/msg/process/handlers/protocol. Context::run uses Tokio
select over authenticated network messages, local requests, and an explicit exit
signal. Context::spawn(config, requests, events) returns a one-shot shutdown sender.
State is independently usable for deterministic scheduling or composition over an
application-managed transport. InstanceId carries epoch, optional dealer, and slot;
protocol and session domains bind transport authentication and commitments.

Pre-register all expected instances on every node before allowing peers to send.
Prefer Context::spawn_with_manifest(config, requests, events, registrations), which
installs the manifest before binding its listener. Network traffic cannot create
instances; unknown instances are ignored. Dynamically registered instances emit
Registered; the application must coordinate their registration before sending.
WRA additionally accepts Expect in its manifest: it reserves one ECHO and one READY
slot per physical sender before the application knows the header_id, then Register
binds the header and replays matching votes. For simultaneous services, pass separate
port ranges with Node::with_protocol_port_offset(offset); choose nonoverlapping
ranges for WRA, WAVID, WRBC, Gather, and BinAA. The same service multiplexes epochs
and dealers; do not start another listener for each instance.

WAVID separates storage completion from retrieval. It assigns node i exactly
ceil(3*n*w_i/W) coding coordinates, so arbitrary numerical weights do not expand into
virtual nodes. Systematic GF(2^16) Reed-Solomon coding uses k=n and stripes of 32-byte
source blocks, with an authenticated directory and indexed proofs. Messages are
chunked at 32 KiB. Retrieval re-encodes recovered sources and checks the commitment;
inconsistent coding or nonzero padding produces a publicly verifiable StorageFault,
not a timeout-derived invalid result. Codec exposes source openings and fault
verification for composition with the later coin project. WRBC embeds the WAVID
state machine, starts retrieval, and delivers a valid file exactly once without an
additional quorum layer.

For joint coin storage/private-share receipts, use WAVID CompletionMode::External.
Its descriptor may initially leave root unset: early dealer packets are buffered
without issuing Stored. Once the higher-level broadcast authenticates the root,
Request::Pin binds it; verified packets then issue Stored. Request::Complete accepts
only that pinned root and represents an application-verified joint completion event,
for example a WRA result. It deliberately bypasses the standalone ACK/READY storage
quorum. The application remains responsible for matching headers, file lengths,
private share verification, and the joint predicate; WASKS/common coin is not included.
Retriever authorization is additive via Authorize, and stored data remains available
for late authorized requests after local output. Keep services and output consumers
alive until the application explicitly shuts them down.

WGather accepts Add only for an application-verified sharing completion. Its sets
use canonical index bitmaps, and outputs need a binding common core rather than
identical sets. WBinAA accepts one bit per dealer and uses exact BigInt/dyadic
arithmetic and compact round-relative codes. Precision::bits(b) requests tolerance
2^(-b); each output is numerator / 2^exponent. Coordinates progress independently,
and old rounds continue servicing delayed parties after vector delivery.

The new network utility uses pairwise HMAC-authenticated frames and acknowledgments,
checks session/component/configuration domains, and deduplicates reliable retries.
It uses independent per-peer queues so a silent peer cannot block another peer.
Transport retry timers do not decide protocol outcomes. This transport authenticates
but does not encrypt payloads; private coin shares must use an encrypted channel or
application encryption. Local state and transport sequences are not restart-persistent;
restart all services with a fresh configuration/session rather than reuse a live session.
Current resource limits are 4096 participants, 1024 registered instances per service,
512 MiB per WAVID/WRBC file, 1 MiB per frame, and 4096 BinAA rounds. Limits are upper bounds,
not promises that every combination fits available memory; outgoing peer queues and
retained storage need application-level lifetime and workload management.

The file cap includes headroom for the reference certified AX common-coin bulk.
With at most 64 participants, total weight W <= n^n, 256-bit keys and a 32-byte
secret, the layout uses 96G + 64n + 320 bytes for G binary gates. At n = 64,
W <= 2^384 requires at most 385 bit layers (including the equality boundary).
Sorter width is at most 129; the reference odd-even and bitonic networks use at
most 1800 and 2241 comparators per layer, respectively. Two gates per comparator
give conservative bulk bounds of 126.90 MiB and 157.99 MiB, even without gate
optimization. The 512 MiB cap provides more than 3x headroom for either backend.
These bounds concern one dealer's raw bulk; encoded storage, retrieval traffic,
and concurrent instances can consume substantially more memory and bandwidth.

The new IndexedTree reuses the repository's hash and proof types but hashes its
indexed/domain-bound branches with SHA-256. Tests exposed that legacy HashState::hash_two
encrypts temporary block copies and then reads the unchanged originals; consequently
some modified leaves do not change a legacy Merkle root. Legacy cryptographic logic
was retained as requested. Weighted commitments use the independent SHA-256 tree,
with singleton, malformed-proof, and every-leaf tampering tests. New wire and coding
formats are Rust-specific and do not claim byte interoperability with the Python model.

### Weighted distributed process tests

Run in Ubuntu/WSL from the repository root:

```bash
bash scripts/test_weighted.sh all
bash scripts/test_wra.sh
bash scripts/test_wavid.sh
bash scripts/test_wrbc.sh
bash scripts/test_wgather.sh
bash scripts/test_wbinaa.sh

# Three silent physical nodes have total weight 3 < T=4.
WEIGHTS=10,1,1,1,1 WEIGHT_THRESHOLD=4 ABSENT=2,3,4 bash scripts/test_weighted.sh all

# Equal weighted case supporting one corrupt node.
WEIGHTS=3,3,3,3 WEIGHT_THRESHOLD=4 ABSENT=3 bash scripts/test_weighted.sh all
```

The scripts build offline, generate a fresh configuration bundle, run state-machine
tests, and launch one independent node process for every active participant. Each
process loads only its own configuration and communicates with peers through TCP.
The node entry point selects ctrbc/wra/wavid/wrbc/wgather/wbinaa using --protocol;
weighted entries supply deterministic local test inputs. No syncer, batches, per,
lin, opt, or ibft arguments are needed for weighted tests.

Every process installs its instance manifest before binding the listener, so peers
can start independently without a cross-node registration barrier. Results are
written atomically, and nodes keep serving peers after local output. The script
checks all expected outputs and distinct process IDs, then sends SIGTERM and waits
for graceful exits. Failure paths terminate only the processes started by that
script. Configurations, per-node logs, PID lists, and JSON results are retained in
a unique run directory below logs/weighted; the directory is printed by the script.
Python 3 is used only for test result validation, not for the Rust protocols.

The original weighted-demo binary remains available as an additional single-process
TCP regression harness. The distributed scripts use the node binary.
Test settings can be supplied through environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| WEIGHTS / WEIGHT_THRESHOLD | 5,3,2,1 / 3 | Membership and exclusive corrupt-weight bound |
| ABSENT | empty | IDs whose processes are not launched; their total weight must be below T |
| START_ORDER | active IDs in ascending order | Comma-separated permutation of all active node IDs |
| START_DELAY | 0 | Seconds between launching consecutive processes |
| PAYLOAD_BYTES | 65536 | WAVID/WRBC deterministic file size; zero tests empty files |
| BINAA_BITS | 8 | Requested precision 2^(-bits) |
| TEST_TIMEOUT | 40 | Seconds allowed for each node to produce a result |
| BASE_PORT | 24500 | First participant TCP port |
| CLIENT_BASE_PORT / CLIENT_RUN_PORT | 29000 / 29500 | genconfig compatibility ports |
| LOG_DIR | logs/weighted | Parent directory for retained run artifacts |
| LOG_LEVEL | info | info, debug, or trace node logs |
| TYPE | debug | debug or release builds |
| OFFLINE | 1 | Set to 0 to permit Cargo dependency downloads |
| RUN_UNIT_TESTS | 1 | Set to 0 to run only the distributed process tests |

For example, exercise reverse startup with a delay and fragmented file transfer:

```bash
START_ORDER=3,2,1,0 START_DELAY=0.5 PAYLOAD_BYTES=131072 bash scripts/test_weighted.sh all
```

Node logs follow HashRand's log macros and simple_logger UTC timestamps. Every
physical log line includes the timestamp, severity, and module, with plain text
messages for startup, instance registration, storage/completion, results, and shutdown.
ANSI colors are disabled; multiline diagnostics receive a timestamp on each line.
Machine-readable reports remain in separate results/node-ID.json files. At info
level BinAA prints one exact dyadic coordinate per line. Use LOG_LEVEL=debug (node -v)
for received-message routing; LOG_LEVEL=trace corresponds to node -vv.

```text
2026-10-02T05:07:15.209Z INFO  [node::weighted_test] WAVID node 0: dispersal complete for instance InstanceId { epoch: 0, dealer: Some(0), slot: 0 } (root=...)
2026-10-02T05:07:15.595Z INFO  [node::weighted_test] WAVID node 0: delivered file (bytes=65536, sha256=...)
```

Each node can also be launched manually in a separate terminal, using configuration
files generated by the command below. Repeat for IDs 0 through 3:

```bash
./target/debug/node --config testdata/weighted/nodes-0.json --protocol wavid \
  --test-result testdata/weighted/results/node-0.json --test-timeout 40
```

Stop processes with Ctrl-C or SIGTERM after every participant has produced a result.
The test timeout only reports harness failure; it never supplies a protocol output.
WRA uses unanimous true input, WAVID/WRBC transfer a deterministic byte pattern,
Gather receives synthetic local completion validations for active dealers, and BinAA
uses unanimous zero/one coordinates alongside mixed input coordinates. These are
standalone component tests, not an end-to-end weighted coin execution.

Unit tests also cover duplicate/equivocating senders, threshold boundaries, late input
and validation, future BinAA rounds, exact agreement, invalid coding certificates,
large weights, authentication/replay, and late authorization. These are regression
checks, not a formal proof of the weighted algorithms.

Generate a reusable weighted configuration bundle explicitly with:

```bash
cargo run -p genconfig -- --NumNodes 4 --blocksize 100 --delay 100 \
  --base_port 15000 --client_base_port 19000 --client_run_port 19500 \
  --target testdata/weighted --weights 5,3,2,1 --weight-threshold 3
```

When --weights is supplied and --weight-threshold is omitted, T defaults to floor(W/3).
Review that exclusive bound against the intended corruption model before deployment.
