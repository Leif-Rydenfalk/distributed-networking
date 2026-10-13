# distributed-networking

A WireGuard mesh VPN written in Rust. Nodes are identified by ed25519 keys and get stable addresses in
`10.77.0.0/16`. The control plane is a 3-replica Raft group, so losing one control server does not stop
registrations or peer lookups. Nodes behind hostile networks reach the mesh through a WebSocket-over-TLS relay leg,
a NAT-PMP/STUN door with hole punching, and a path manager that moves each peer's WireGuard endpoint to the best
live path several times a second. A wasm build of the client runs a full mesh node inside a browser tab.

The crate is called `net-mesh`; the wire protocols are versioned `net.mesh/*`.

## Status

Working and tested, but young. The control plane, relay leg, NAT traversal, path manager and browser client have all
run on real long-haul WAN links, and each has an end-to-end test on loopback. Several things you expect from a
mature mesh VPN are missing (see the table below). APIs and wire formats may change before 1.0.

## Compared with Tailscale

| Feature | distributed-networking | Tailscale |
|---|---|---|
| WireGuard data plane | Yes: kernel WireGuard via `wg-quick`, or userspace boringtun / wireguard-go via UAPI | Yes |
| Coordination server | Self-hosted, 3-replica Raft (openraft), linearizable reads | Hosted SaaS (or Headscale, single server) |
| Node identity | ed25519 key per node, signed requests | Machine key + node key, SSO login |
| Admission | Admitted list, or a signed capability grant checked by an external verifier | SSO, auth keys, device approval |
| NAT traversal | NAT-PMP lease, STUN, address-filter punching from the server door | NAT-PMP, PCP, UPnP, STUN, disco, birthday-paradox punching |
| Relay | WebSocket over TLS (`netmesh-leg`), multiple relays with failover | DERP |
| Path selection | Authenticated probes every 200 ms, switch in under 1 s, hedged downlink | disco pings, endpoint selection |
| Browser client | wasm32 node (WireGuard + smoltcp) over the relay leg | tsconnect / wasm |
| Names (MagicDNS) | Not yet | Yes |
| ACLs / grants policy | Not yet (admission is all-or-nothing; browser tabs get a per-service nftables rule) | Yes |
| Subnet routes | Not yet | Yes |
| Exit nodes | Not yet | Yes |
| Node key expiry | Not yet (capability grants for joins and tabs do expire) | Yes |
| IPv6 inside the mesh | Not yet (IPv4 only) | Yes |
| Platforms | Linux and macOS (Unix only) | Linux, macOS, Windows, iOS, Android |

## Architecture

```
                      +--------------------------------------------+
                      |      control plane (3 Raft replicas)       |
                      |  netmesh-control   netmesh-control   ...   |
                      |  client port :7741  raft port :7751 (HMAC) |
                      +---------^---------------------^------------+
                                | signed JSON line    | signed JSON line
                                | (register / peers)  |
      +-------------------------+--+               +--+-----------------------+
      | node A                     |   WireGuard   | node B                     |
      |  netmesh up -> wg-quick    |<=============>|  netmesh up -> wg-quick    |
      |  netmesh-path (probes)     |  direct UDP   |  netmesh-path (probes)     |
      +-------------+--------------+               +-------------^------------+
                    | lossy path: WireGuard datagrams              |
                    | inside one TLS WebSocket                     | plain UDP
                    v                                              |
      +-------------+---------------------------------------------+-------------+
      | relay: netmesh-leg server (behind a TLS edge or reverse proxy)          |
      |  hello door (ed25519 + nonce), per-node loopback socket to WireGuard,   |
      |  split UDP ingress with HMAC beacons, NAT-PMP/STUN door, hedged downlink|
      +-------------^-----------------------------------------------------------+
                    | wss:// (tab hello: ephemeral keys + capability for one service)
      +-------------+--------------+
      | browser tab (wasm32)       |
      |  netmesh-client: boringtun |
      |  noise + smoltcp TCP/UDP   |
      +----------------------------+
```

- **Control plane** (`src/lib.rs`, `src/raft.rs`, `netmesh-control`). Every request is one JSON line over TCP,
  signed by the node's ed25519 key over the protocol tag, op, node id, timestamp, WireGuard key and endpoints.
  The leader runs the checks that need no write (signature, admission, clock window, replay, capability verdict),
  then commits a log entry; every replica applies it deterministically. Reads go through the log too.
- **Relay leg** (`src/leg.rs`, `netmesh-leg`). On paths where UDP is throttled or lossy but HTTPS is fine, a
  node carries its WireGuard datagrams over one WebSocket inside TLS. Each WebSocket binary message holds one or
  more `u16 length || datagram` frames. The server hands each node its own loopback UDP socket toward WireGuard, so
  kernel WireGuard roams the peer endpoint by itself. Split mode sends the uplink as plain UDP when that direction
  is fast.
- **NAT traversal** (`src/punch.rs`). A server behind a home router and a carrier-grade NAT leases its door port by
  NAT-PMP (120 s, renewed every 40 s), learns its public address by STUN from the door socket, announces it to
  clients and punches toward each client's IP.
- **Path manager** (`src/path.rs`, `netmesh-path`). Probes every candidate address of every peer, authenticated
  with a key both sides derive from their WireGuard keys, and moves the WireGuard endpoint to the best live
  candidate or back to the relay. TCP inside the tunnel survives a switch.
- **Browser client** (`crates/netmesh-client`). A complete node in a tab: WireGuard from vendored boringtun under
  a smoltcp TCP/UDP stack, over the relay leg. See its [README](crates/netmesh-client/README.md).

## Binaries

Build with `cargo build --release`; binaries land in `target/release/`.

### `netmesh` (node client)

```
netmesh id    [--key PATH]                 print this node's id (hex ed25519 public key)
netmesh wg    [--wg-key PATH]              print this node's WireGuard public key (created mode 0600 if missing)
netmesh up    --control HOST:PORT[,HOST:PORT...] [--endpoint IP:PORT ...] [--port 51877]
              [--out FILE] [--cap-file GRANT.hex]
                                           register, then print (or write mode 0600) a wg-quick config
netmesh peers --control HOST:PORT[,...]    the peer list as JSON
```

- `--key`: node key, 32 raw bytes (the ed25519 seed). Default `$HOME/.local/share/ce/identity/node.key`.
- `--wg-key`: WireGuard private key (base64). Default `$HOME/.local/share/net-mesh/wg.key`.
- `--control`: one address or a comma-separated list of replicas, tried in order on connect errors.
  `$HOME/.config/net-mesh/control`, if present, adds more replicas (comma or line separated).
- `--endpoint`: an address other nodes can reach this one at (repeatable; the first is the default endpoint).
- `--cap-file`: a capability grant (hex) for a node that is not on the control server's admitted list.

### `netmesh-control` (control server)

```
netmesh-control --listen 127.0.0.1:7741 --admitted admitted.json [--state state/control.json]
                [--cap-action ACTION [--iam CMD] [--iam-data-dir DIR]]

Raft mode (one of 3 replicas; state lives in the Raft log and snapshot, not --state):
netmesh-control --listen ADDR --admitted admitted.json --raft-id N --raft-listen ADDR
                --raft-peers 1=ADDR,2=ADDR,3=ADDR --raft-dir DIR --raft-secret FILE [--raft-init]
                [--raft-heartbeat-ms 500] [--raft-election-ms 1500-3000] [--raft-no-fast-elect]
```

- `--admitted`: JSON array of node ids, or `{"nodes": [...]}` with string ids or `{"node": id}` objects.
- `--cap-action`: admit a node that is not listed when the external verifier says its grant authorizes ACTION
  for that node id. The verifier is `--iam CMD` (default `$NETMESH_IAM`, else `iam`), called as
  `CMD verify --token HEX --requester NODE --action ACTION --use-roots --fail-closed --json [--data-dir DIR]`.
  Exit 0 plus an affirmative JSON verdict admits; anything else refuses.
- `--raft-peers`: the Raft port of every replica (including this one).
- `--raft-secret`: 32 raw bytes or 64 hex characters, mode 600; shared by the replicas, used for HMAC on every
  Raft frame.
- `--raft-init`: on exactly one replica, once. If a pre-Raft `--state` file is given, it becomes the cluster's first
  log entry, so existing nodes keep their addresses.
- Refuses to bind `0.0.0.0` or `[::]`.

### `netmesh-leg` (relay leg)

```
netmesh-leg server --listen 127.0.0.1:7742 --admitted admitted.json [--wg 127.0.0.1:51877]
                   [--udp-in PRIVATE_IP:51879]
                   [--udp-door LAN_IP:51880 [--natpmp GW_IP] [--stun HOST:PORT]] [--no-hedge]
netmesh-leg client --url wss://relay.example.com/v1/leg [--key PATH] [--listen 127.0.0.1:51878]
                   [--wg 127.0.0.1:51877] [--up-udp HOST:51879] [--door]
                   [--alt-urls URL,URL] [--dead-after SECS]
                   [--peer WG_PUB_B64 --udp-endpoint HOST:PORT [--uapi auto|SOCK | --wg-iface IF]
                    [--mode auto|leg|udp] [--loss-max 5]]
netmesh-leg probe  --url ws://127.0.0.1:7742/v1/leg [--key PATH]
netmesh-leg probe-id --key FILE
```

- Server `--listen` accepts loopback, `100.64.0.0/10` or mesh addresses only; put a TLS edge or reverse proxy in
  front. The admitted file is re-read every 5 s and a node taken off is cut at once.
- `--udp-in`: split mode. Clients send their uplink as plain UDP to this address after an HMAC beacon binds their
  source; the downlink stays on the leg.
- `--udp-door`: the same ingress on a private LAN address for a port forward. `--natpmp` leases the port on the
  router, `--stun` learns the public address. `--no-hedge` turns off the duplicate UDP downlink.
- Client `--alt-urls`: more relays; a leg that closes, is refused or goes quiet for `--dead-after` seconds moves to
  the next one.
- Client `--peer ... --udp-endpoint`: also pick that peer's WireGuard endpoint, the leg or the direct UDP path, by
  measured ping loss (checked every 60 s).

### `netmesh-path` (path manager)

```
netmesh-path --listen IP:PORT --peers PEERS.json [--wg-key PATH] (--uapi SOCK | --wg-iface IF)
             [--log FILE.jsonl] [--every-ms 200] [--dead-ms 500]
```

`PEERS.json`:

```json
[{"name": "peer-a", "wg_public": "<base64>", "candidates": ["192.0.2.10:51878"], "wg_port": 51877,
  "fallback": "127.0.0.1:51878"}]
```

`--listen` must be a private address (RFC 1918, loopback, `100.64.0.0/10` or mesh). Probes that fail the pair-key
MAC get no answer.

## Quickstart: 3 control replicas and 2 nodes on one Linux box

Needs root, `iproute2` and `wireguard-tools`. Two network namespaces stand in for two machines; the documentation
range `192.0.2.0/24` is used for the lab bridge.

```sh
cargo build --release
export PATH=$PWD/target/release:$PATH
mkdir -p lab && cd lab

# 1. a bridge and two namespaces
sudo ip link add nmbr0 type bridge && sudo ip addr add 192.0.2.1/24 dev nmbr0 && sudo ip link set nmbr0 up
for n in 1 2; do
  sudo ip netns add ns$n
  sudo ip link add veth$n type veth peer name eth0 netns ns$n
  sudo ip link set veth$n master nmbr0 up
  sudo ip -n ns$n addr add 192.0.2.1$n/24 dev eth0
  sudo ip -n ns$n link set eth0 up && sudo ip -n ns$n link set lo up
done

# 2. node keys and the admitted list
for n in 1 2; do head -c 32 /dev/urandom > node$n.key; chmod 600 node$n.key; done
echo "[\"$(netmesh id --key node1.key)\", \"$(netmesh id --key node2.key)\"]" > admitted.json

# 3. three control replicas (start 2 and 3 first, then 1 with --raft-init)
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > raft.secret && chmod 600 raft.secret
PEERS=1=127.0.0.1:7751,2=127.0.0.1:7752,3=127.0.0.1:7753
for i in 2 3 1; do
  init=$([ $i = 1 ] && echo --raft-init)
  netmesh-control --listen 192.0.2.1:774$i --admitted admitted.json --raft-id $i \
    --raft-listen 127.0.0.1:775$i --raft-peers $PEERS --raft-dir raft$i --raft-secret raft.secret $init \
    2> control$i.log &
  sleep 1
done
CONTROL=192.0.2.1:7741,192.0.2.1:7742,192.0.2.1:7743

# 4. register both nodes, then fetch configs (each now lists the other)
for n in 1 2; do
  sudo ip netns exec ns$n netmesh up --key node$n.key --wg-key wg$n.key --control $CONTROL \
    --endpoint 192.0.2.1$n:51877 > /dev/null
done
sleep 1   # request timestamps are in seconds and must rise per node
for n in 1 2; do
  sudo ip netns exec ns$n netmesh up --key node$n.key --wg-key wg$n.key --control $CONTROL \
    --endpoint 192.0.2.1$n:51877 --out nm$n.conf
  sudo ip netns exec ns$n wg-quick up ./nm$n.conf
done

# 5. ping across the mesh
ADDR2=$(sudo ip netns exec ns2 ip -4 -o addr show nm2 | awk '{print $4}' | cut -d/ -f1)
sudo ip netns exec ns1 ping -c 3 $ADDR2

# 6. kill one replica: registration and peer lookups keep working
kill %1
sudo ip netns exec ns1 netmesh peers --key node1.key --wg-key wg1.key --control $CONTROL
```

On two real machines, run the same `netmesh up` / `wg-quick up` on each, with `--endpoint` set to an address the
other machine can reach, and the control replicas on any three hosts both can reach (bind them to a private or
mesh address, never `0.0.0.0`).

Cleanup: `sudo ip netns exec ns1 wg-quick down ./nm1.conf` (same for ns2), `kill %2 %3`,
`sudo ip netns del ns1 ns2`, `sudo ip link del nmbr0`.

## Security model

- **Signed requests.** Every control request is signed by the node's ed25519 key. The server checks the
  signature, a +/-60 s clock window and a per-node rising timestamp, so a captured request cannot be replayed.
- **Default deny.** A node that is neither on the admitted list nor holding a valid capability grant is refused
  before anything reaches the Raft log, and never appears in anyone's peer list. Taking a node off the admitted
  list cuts its relay leg at once.
- **Capability-gated join.** A grant is a bearer chain bound to the node id; it is useless without the node key
  that signs the request, it is re-verified on every call, and a revoked or expired grant drops the node.
- **HMAC on Raft links.** Every frame between replicas carries HMAC-SHA256 under a 32-byte cluster secret (mode
  600) and a per-connection sequence number; a bad MAC or a non-rising sequence closes the link.
- **Relay door.** A relay client signs the server's fresh 32-byte nonce; nothing is forwarded before that check.
  Split-mode UDP sources are bound only by HMAC beacons with a 64-entry replay window, and only a fresh valid beacon
  is echoed (same size), so the door is not a reflector.
- **Path probes** are authenticated with an X25519-derived pair key; strangers get silence.
- **Browser tabs** use ephemeral keys and a capability scoped to one service for at most 10 minutes; each tab gets
  one WireGuard peer and one nftables element allowing TCP to that service's `addr:port` only, removed on expiry,
  close or 60 s of silence.
- **Closed by default.** Every listener refuses wildcard binds; the relay and path manager accept only loopback,
  private, CGNAT or mesh addresses. Key and state files are written mode 600.
- WireGuard provides end-to-end encryption of all mesh traffic; the relay never sees plaintext.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Tests

```sh
cargo test --all-targets                    # root crate: unit + loopback end-to-end tests
(cd crates/netmesh-client && cargo test)    # browser client, native build
```

Current count: 68 tests pass, 1 ignored (61 in the root crate across 7 test files, 7 in `netmesh-client`; the
ignored one is a documentation example). The full suite takes about 35 s on a 2-core machine after the build.

The end-to-end tests run everything on loopback: three in-process Raft replicas with a leader kill, a WAN-latency
proxy in front of one replica, the relay leg in both directions with strangers and replays, NAT-PMP/STUN parsing
against hostile input, live path failover, and a browser tab admitted, wired and expired. One test needs an
external IAM verifier and is skipped unless `NETMESH_TEST_IAM` names one.

The wasm build of the client is tested with `wasm-bindgen-test-runner`; see the client README.

## Benchmarks

Measured against Tailscale on the same machines in the same minute (2026-10-13; full method, every number and what was
not measured in [BENCHMARKS.md](BENCHMARKS.md)). Long-haul pair, Europe server to East Asia laptop, ~245 ms RTT; the
mesh ran over its relay leg, Tailscale over direct UDP:

| metric | distributed-networking | Tailscale |
|---|---|---|
| TCP connect p99 | 334-603 ms, 0/150 failed | 1255-1318 ms, 2/150 failed |
| ping loss | 1/300 | 13/300 |
| throughput into the East Asia site (median of 3) | 268 kB/s | 100 kB/s |
| throughput out of it (median of 3) | 482 kB/s | 628 kB/s |

Where we lose today: two machines on the same LAN. Tailscale finds the LAN path (7.6 ms, 8.5 MB/s), while the mesh
went through the relay (46 ms, 2.7 MB/s). LAN endpoint discovery is the fix in progress.

## License

Apache License 2.0, see [LICENSE](LICENSE). `crates/netmesh-client/vendor/boringtun` is boringtun 0.6.0 by
Cloudflare, BSD-3-Clause, with small wasm32 patches (see its `PATCH.md` and `LICENSE.md`). Third-party credits are
in [NOTICE](NOTICE).
