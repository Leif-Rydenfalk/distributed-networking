# net.mesh vs Tailscale: same machines, same minute

Measured 2026-10-13, 18:05-18:44 UTC.
Raw rows (44, 2 runs) are kept privately because they contain host addresses. Runner: `bench/vs-tailscale/src/main.rs` (Rust, std only).
"Not measured" means no number exists. Small samples: one to three runs per pair, so read the spread, not a single cell.

## Machines

| role | OS | mesh address | Tailscale path at the time |
|---|---|---|---|
| North Europe server | Debian 12, x86_64, 16 GB (short on free RAM) | yes | the reference end |
| East Asia laptop | macOS, arm64 | yes | direct UDP to the North Europe server |
| East Asia desktop | macOS, x86_64, macOS firewall on with stealth mode | yes | DERP relay (Los Angeles) at 18:30; direct over the LAN to the East Asia laptop |
| Central Europe server | Linux, x86_64, 4 GB | no (not joined to the mesh) | direct UDP |

How net.mesh carried traffic during the runs (read from the running processes, nothing was changed): both Macs run
`netmesh-leg client --mode leg`. Traffic toward a Mac comes down the Cloudflare WebSocket relay leg. Traffic from a Mac
goes up as plain UDP to the North Europe server's door. So every Europe<->East Asia mesh number below is the **relayed** path,
and the Tailscale number is **direct** UDP for the laptop.

## Method

Each pair has a client end and a server end. `vsts run --plan bench/vs-tailscale/plan-2026-10-13.txt` runs on the
North Europe server. For each pair it starts `vsts serve` on the server end over ssh, bound only to that machine's mesh and
tailnet addresses, never 0.0.0.0. The server holds at most 8 connections and exits when its ssh closes or after 25 min.
Then for each metric the runner measures the mesh address and the Tailscale address back to back, so both are taken
within the same 1-2 minutes. Which transport goes first alternates per metric and per round.

1. **TCP connect** (n=50, 100 ms apart, 3 s timeout each): a fresh `connect()` (the SYN/SYN-ACK round trip). "First byte"
   is connect, then send a 9-byte request, then read the 1-byte reply: what a new app session waits for.
2. **Ping** (n=100, 0.2 s apart, system `ping`, whole run capped at n*0.2+15 s): RTT p50/p99 and loss.
3. **Throughput**, 2 MB each way with a 60 s cap. iperf3 is not installed on any of the four machines, and the Macs
   were left untouched, so this is a timed transfer over one TCP connection. Down = server end writes 2 MB, client
   counts to the last byte. Up = client writes 2 MB, server counts to EOF and acknowledges the count. If the 60 s cap hits,
   a second connection asks the server how many bytes arrived and over how long. That rate counts bytes that really
   arrived, not bytes still in the sender's buffer.
4. **Relay vs direct**: see the machines section. The mesh leg mode was not switched (see "Not measured").
5. **Failover**: numbers come from bench/raft/KILL-ONE-2026-10-13.md. Nothing live was killed for this benchmark.

Rebuild and rerun:

```
cd bench/vs-tailscale && cargo build --release            # Linux ends
rustc -O --edition 2021 src/main.rs -o ~/.cache/vsts/vsts  # on each Mac (no crates, nothing to fetch)
./target/release/vsts run --plan plan-2026-10-13.txt --out runs-YYYY-MM-DD.jsonl
./target/release/vsts table --in runs-YYYY-MM-DD.jsonl [--run RUN_ID]
```

## Results

### North Europe server <-> East Asia laptop (3 rounds: 18:05, 18:39, 18:41 UTC)

| metric | round | net.mesh (relay leg) | Tailscale (direct UDP) |
|---|---|---|---|
| TCP connect p50 / p99 | 1 | 246 / 603 ms, 50/50 ok | 251 / 1255 ms, 49/50 ok |
| | 2 | 246 / 334 ms, 50/50 | 247 / 1318 ms, 49/50 |
| | 3 | 245 / 334 ms, 50/50 | 257 / 1318 ms, 50/50 |
| connect + first byte p50 / p99 | 1 | 499 / 1473 ms | 517 / 1500 ms |
| | 2 | 498 / 609 ms | 501 / 1565 ms |
| | 3 | 525 / 665 ms | 548 / 1649 ms |
| ping RTT p50 / p99, loss | 1 | 247 / 379 ms, 1 % | 249 / 331 ms, 4 % |
| | 2 | 246 / 565 ms, 0 % | 247 / 332 ms, 4 % |
| | 3 | 244 / 519 ms, 0 % | 249 / 371 ms, 5 % |
| throughput laptop -> server (out of the East Asia site) | 1 | 482 kB/s (2 MB in 4.2 s) | 628 kB/s (3.2 s) |
| | 2 | 542 kB/s (3.7 s) | 741 kB/s (2.7 s) |
| | 3 | 330 kB/s (6.1 s) | 568 kB/s (3.5 s) |
| throughput server -> laptop (into the East Asia site) | 1 | 101 kB/s (2 MB in 19.8 s) | 27 kB/s (1.59 MB in the 60 s cap, incomplete) |
| | 2 | 435 kB/s (4.6 s) | 100 kB/s (20.0 s) |
| | 3 | 268 kB/s (7.5 s) | 652 kB/s (3.1 s) |

Over the 3 rounds:
- **Connect**: p50 is equal, 246 vs 251 ms. The mesh p99 is lower (334-603 vs 1255-1318 ms). Tailscale lost 2 of 150
  connects, the mesh 0 of 150.
- **Ping**: p50 is equal. The mesh lost less (1 of 300 vs 13 of 300), but its p99 was higher (379-565 vs 331-371 ms).
- **Out of the East Asia site**: Tailscale is faster, 568-741 vs 330-542 kB/s.
- **Into the East Asia site**: the mesh median is 268 vs 100 kB/s, but the spread is wide. Tailscale ran from 27 to 652 kB/s and the
  mesh from 101 to 435. The 10 kB/s into the East Asia site from baseline-2026-10-10 did not repeat today.

### East Asia laptop <-> East Asia desktop (1 round, 18:18-18:22 UTC; desktop is the client)

| metric | net.mesh | Tailscale (direct over the LAN) |
|---|---|---|
| TCP connect p50 / p99 | 54 / 1068 ms, 50/50 ok; first byte 128 / 1117 ms | not measured: the ssh control channel to the desktop dropped the probe's output |
| ping RTT desktop -> laptop p50 / p99, loss | 46 / 213 ms (min 5 ms), 1 % | 7.6 / 103 ms, 1 % |
| throughput laptop -> desktop | 2677 kB/s (2 MB in 0.75 s) | 8468 kB/s (0.24 s) |
| throughput desktop -> laptop | 884 kB/s (2.3 s) | 2992 kB/s (0.67 s) |

Tailscale wins between the two Macs in the same room: about 6x lower median RTT and 3x the throughput. Its path is a
direct LAN connection. The mesh path between the Macs was not inspected for this run. A median of 46 ms against a
minimum of 5 ms says it does not stay on the LAN.

### North Europe server <-> East Asia desktop (1 round, 18:09-18:18 UTC; desktop is the client)

| metric | net.mesh | Tailscale |
|---|---|---|
| TCP connect p50 / p99 | 0/50: connect timed out (see below) | 784 / 2804 ms, 45/50 ok; first byte 1772 / 3590 ms |
| ping RTT desktop -> server p50 / p99, loss | 482 / 1466 ms (min 255 ms), 5 % | not measured: no output came back over ssh |
| throughput server -> desktop (into the East Asia site) | not measured (TCP blocked, see below) | 102 kB/s (2 MB in 19.6 s) |
| throughput desktop -> server | not measured | 30 kB/s (1.82 MB in the 60 s cap, incomplete) |

Why the mesh TCP rows are empty: the North Europe server's host firewall (ufw) accepts new TCP on the mesh interface only on a short
allow list of ports. The benchmark port was dropped. The desktop's macOS firewall (stealth mode)
refuses an unsigned listener, so it cannot be the server end either. The firewall was not changed. The runner has an
`sshd` plan mode that uses the desktop's sshd as the far end instead (`probe-ssh`, `source`, `sink`). At about 18:30 UTC
the desktop's sshd stopped answering, on Tailscale and on the LAN from the laptop alike, so that mode never ran.

### North Europe server <-> Central Europe server (1 round, 18:22 UTC)

| metric | net.mesh | Tailscale (direct UDP) |
|---|---|---|
| TCP connect p50 / p99 | not measured: no mesh address | 39 / 67 ms, 50/50; first byte 80 / 114 ms |
| ping RTT p50 / p99, loss | not measured | 37.2 / 42.8 ms, 0 % |
| throughput Central Europe -> North Europe | not measured | 5385 kB/s (2 MB in 0.37 s) |
| throughput North Europe -> Central Europe | not measured | 5481 kB/s (0.36 s) |

At 37 ms a 2 MB transfer finishes in about 10 RTTs, still inside TCP slow start, so these two rates mostly show slow
start, not link capacity.

### Failover and path switching (from earlier evidence, not rerun)

| what | net.mesh | Tailscale | source |
|---|---|---|---|
| control plane: first call after the Raft leader is killed | 12.78 s (election 3-6 s plus forwards over the the East Asia site link); second call 1.70 s | not measured (hosted control plane) | bench/raft/KILL-ONE-2026-10-13.md |
| path switch stall | median 0.84 s, worst 1.9 s | median 1.14 s | docs/TAILSCALE-GAPS.md row 3 |
| Huey path, East Asia laptop -> North Europe server, 180 s | 97 % of packets within 1 s, p99 1077 ms, 6 drops | 63 %, p99 1465 ms, 69 drops | bench/huey-path/AB30-DOOR-2026-10-11.md |

## Not measured, and why

- **Mesh leg forced vs direct UDP on the same pair**: the leg client on each Mac is a running launchd service started
  with `--mode leg`. Switching it to `--mode udp` means restarting that service, which was out of scope. The
  North Europe<->laptop table compares the mesh relay with Tailscale direct.
- **Any TCP metric between the North Europe server and the East Asia desktop over the mesh**: blocked by the host firewalls on
  both ends (above). Mesh ping from the desktop works.
- **Ping toward the East Asia desktop**: its stealth mode drops inbound ICMP on both transports. Ping from the desktop was
  used instead.
- **Central Europe server over the mesh**: it has no mesh address.
- **Tailscale TCP connect laptop<->desktop and Tailscale ping desktop->North Europe**: the ssh session that runs the probe on
  the desktop returned nothing (the desktop's ssh was already unreliable, 30-90 s logins). These are recorded as
  `"error":"no output"` rows.
- **iperf3 / sustained throughput**: not installed on any machine. 2 MB is too small to fill a fast link (see the
  Central Europe note).
- **Reconnect after a link kill and the 1 h soak** (also part of order row 3): not run here. bench/huey-path/SOAK-1H-2026-10-11.md
  has the earlier soak.
- **Tailscale control-plane failover**: hosted by Tailscale, so it cannot be killed from here.
- Side note: one 2-connect debug probe hit the laptop's mesh address during round 1's Tailscale connect phase.

## Rerun after LAN endpoints (2026-10-13, 19:57-20:08 UTC)

Commit 47a413f went live on both Macs: `netmesh up` registers private LAN addresses, and `netmesh lan-pick` switches a
peer to its LAN endpoint after a handshake within 1 s. Same runner, same 2 MB transfers. The laptop's root start job has
not rerun yet (it runs at boot), so only the desktop side picked its LAN endpoint.

| pair | metric | net.mesh | Tailscale |
|---|---|---|---|
| laptop <-> desktop (same LAN) | TCP connect p50 / p99 | 7.9 / 71 ms (50/50) | 9.5 / 118 ms (50/50) |
| laptop <-> desktop | connect + first byte p50 / p99 | 18.3 / 124 ms | 19.3 / 130 ms |
| laptop <-> desktop | ping p50 / p99, loss | 7.9 / 96 ms, 0 % | 7.8 / 101 ms, 0 % |
| laptop <-> desktop | laptop -> desktop | 8549 kB/s | 7576 kB/s |
| laptop <-> desktop | desktop -> laptop | 1567 kB/s | 6840 kB/s |
| Europe server <-> East Asia laptop (long haul, relay leg) | TCP connect p50 / p99 | 246 / 494 ms (50/50) | 248 / 356 ms (50/50) |
| Europe server <-> East Asia laptop | ping p50 / p99, loss | 238 / 572 ms, 0 % | 249 / 511 ms, 4 % |
| Europe server <-> East Asia laptop | laptop -> server | 542 kB/s | 735 kB/s |
| Europe server <-> East Asia laptop | server -> laptop | 514 kB/s | 125 kB/s |

Before the fix the same-LAN pair measured 46 ms ping p50 and 2677 / 884 kB/s on the mesh. Now the mesh matches Tailscale
on latency and beats it laptop -> desktop. Desktop -> laptop is still 4.4x slower; not yet explained (one round, the
laptop side still on its old endpoint). Long haul: the mesh keeps winning into the East Asia site (514 vs 125 kB/s) and
on loss, and still loses out of it (542 vs 735 kB/s).
