# Packet Tracer — Outgoing Traffic Monitor

Captures network traffic on this Linux host with Scapy and streams it, structured,
to a web dashboard over WebSocket. Two views:

- **System monitor** (`/`) — **outbound** traffic from this machine: core 5-tuple,
  resolved hostnames, per-process attribution, live stats.
- **Network monitor** (`/network`) — devices on your **LAN** and the traffic
  visible to this machine. Discovers devices (ARP) with vendor/hostname, and maps
  per-device traffic. See "Network monitor" below for what's actually visible.

The web UI (`frontend/`) is a deep-space **"orbital command center"**: your host
sits at a glowing hub while destinations orbit as a live constellation star-map
(nodes sized by volume, colored by protocol), packets fly the links as particles,
and clicking any node/row drills into an inspector. It was designed in Claude
Design and implemented against the JSON contract documented below. See
[`frontend/README.md`](frontend/README.md) for UI details.

## Setup

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Run

Packet capture requires raw-socket privileges:

```bash
bash run.sh                 # runs uvicorn under sudo
```

Then open <http://127.0.0.1:8000/> and generate some traffic
(`curl https://example.com`, `ping -c3 1.1.1.1`, `dig openai.com`).

**Alternative (no sudo at runtime)** — grant capabilities to the venv Python
once (note: this lets *any* code run by that interpreter capture packets):

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f .venv/bin/python)"
.venv/bin/python -m uvicorn packettracer.server:app --host 127.0.0.1 --port 8000
```

### Environment overrides

| Var | Default | Meaning |
|-----|---------|---------|
| `PT_HOST` | `127.0.0.1` | Bind address |
| `PT_PORT` | `8000` | Bind port |
| `PT_IFACE` | all | Interface to sniff (e.g. `wlan0`) |
| `PT_DISCOVERY` | `1` | Active ARP discovery sweep (`0` disables) |
| `PT_MITM` | `0` | **ARP-spoof interception** for the network view (`1` enables) — see below |
| `PT_MITM_TARGETS` | all | Comma-separated IPs to intercept; empty = every device except self/gateway |

## Architecture

```
Scapy AsyncSniffer (thread) ──▶ queue.Queue ──▶ asyncio pump ──WS──▶ browser
   │  BPF: src host <local ips>                         ▲
   ├─ direction guard (src ∈ local IPs)                 │
   ├─ DNS cache (learn IP→host from sniffed replies)    │
   ├─ process attribution (psutil.net_connections)      │
   └─ stats aggregator                                  │
```

- `packettracer/capture.py` — sniff, parse, classify direction, enrich, record.
- `packettracer/netinfo.py` — local IP set + BPF filter.
- `packettracer/processes.py` — `(proto, local_port) → pid/name`, ~1s cache.
- `packettracer/dns_cache.py` — passive IP→host learning + bounded reverse DNS.
- `packettracer/stats.py` — totals, protocol mix, top destinations, timeline.
- `packettracer/server.py` — FastAPI: host stream (`/ws`, `/api/snapshot`) +
  network stream (`/ws/network`, `/api/network/snapshot`), static UI.

Network monitor adds:
- `packettracer/lan.py` — local subnet/gateway detection + `DeviceRegistry` (IP↔MAC,
  vendor, hostname, first/last seen, is_self/is_gateway).
- `packettracer/oui.py` — small curated MAC→vendor table.
- `packettracer/netcapture.py` — promiscuous sniffer (no src filter) + active ARP
  discovery sweep; attributes each packet to a LAN device.
- `packettracer/netstats.py` — per-device aggregation joined with the registry.
- `packettracer/mitm.py` — optional ARP-spoof interceptor (`PT_MITM=1`); off by default.
- `packettracer/sni.py` — reads TLS **SNI** + HTTP **Host** from packets so the real
  destination (e.g. `google.com`) shows even when its DNS lookup was cached/encrypted.

## Network monitor (`/network`)

Shows the devices on your LAN as a constellation (gateway = hub) plus the traffic
visible to this machine. **What's actually visible depends on your network:**

- **Always works:** device discovery via ARP (with an active sweep of your /24),
  broadcast/multicast chatter (mDNS/SSDP/DHCP — mDNS also yields `.local` hostnames),
  and this host's own traffic.
- **Needs more:** seeing *other* devices' unicast traffic (phone→internet, etc.)
  requires the switch to deliver you those frames — i.e. **port mirroring / SPAN**,
  a hub, or running this on the gateway/router. On an ordinary switch you'll see
  every device on the map (via ARP) but volume mostly for broadcast + this host.

Active ARP discovery can be disabled with `PT_DISCOVERY=0`.

### Seeing other devices' traffic — interception mode (`PT_MITM=1`)

Because a switch only delivers you discovery + your own unicast, full per-device
traffic normally needs **port mirroring/SPAN, a TAP, or running on the gateway**.
If you don't have those, `PT_MITM=1` turns on **ARP-spoof interception**: this host
poisons the ARP caches of LAN devices and the gateway so their traffic is *routed
through this machine* (kernel IP-forwarding is enabled so connectivity is
preserved), making it visible to the sniffer and attributed per device. The
network map shows a pulsing **"intercepting"** badge while it's on.

```bash
sudo PT_MITM=1 bash run.sh                 # intercept every device
sudo PT_MITM=1 PT_MITM_TARGETS=192.168.1.20,192.168.1.30 bash run.sh   # only these
```

> ⚠️ **This is intrusive and only legal/ethical on a network you own.** It is a
> man-in-the-middle: it rewrites neighbours' ARP tables, can be disruptive, and is
> exactly what security tooling flags as an attack. It's off by default. On
> shutdown the original ARP mappings and `ip_forward`/`send_redirects` sysctls are
> restored. Implementation: `packettracer/mitm.py` (`ArpSpoofer`); forwarded
> duplicate frames are de-counted in `netcapture.py`.

**Where is a device going?** Each packet carries `peer_ip`/`peer_host` — the remote
endpoint the device is talking to — and the live-packet row renders it as
`device → google.com`. Hostnames come from three passive sources: sniffed DNS
replies, TLS **SNI**, and HTTP **Host** headers (`sni.py`), so you get real names
even for cached or encrypted DNS.

The network `stats` message extends the base stats with a `devices` array
(`{ip, mac, vendor, hostname, host, packets, bytes, by_proto, is_self, is_gateway, ...}`)
plus `gateway_ip` and `subnet`; packet items carry `peer_ip`/`peer_host` (the
remote endpoint the device is talking to). The frontend reuses the same
constellation/inspector components — see `frontend/README.md`.

## Data contract (for the future UI)

WebSocket messages are JSON objects with a `type` field.

**On connect** — `snapshot`:
```jsonc
{ "type": "snapshot",
  "stats": { /* see stats below */ },
  "recent_packets": [ /* array of packet objects */ ] }
```

**`packets`** (batched, ~every 100 ms):
```jsonc
{ "type": "packets", "items": [
  { "ts": 1733400000.12, "proto": "TCP",
    "src_ip": "192.168.1.10", "src_port": 54321,
    "dst_ip": "93.184.216.34", "dst_port": 443,
    "size": 1480, "dst_host": "example.com", "flags": "PA",
    "process": { "pid": 1234, "name": "firefox" } } ] }
```
`proto` ∈ `TCP|UDP|ICMP|ICMPv6|OTHER`. `dst_host`, `flags`, `process` may be `null`.

**`dns`** (batched):
```jsonc
{ "type": "dns", "items": [ { "ts": 1733400000.10, "query": "example.com", "qtype": "A" } ] }
```

**`stats`** (every 1 s):
```jsonc
{ "type": "stats",
  "total_packets": 5210, "total_bytes": 7340032, "throughput_bps": 120000,
  "by_proto": { "TCP": 4800, "UDP": 400, "ICMP": 10 },
  "top_destinations": [ { "ip": "93.184.216.34", "host": "example.com", "packets": 900, "bytes": 1200000 } ],
  "timeline": [ { "t": 1733400000, "bytes": 12000, "packets": 9 } ] }
```

**REST** — `GET /api/snapshot` returns `{ "stats": {...}, "recent_packets": [...] }`
for bootstrapping without a WebSocket.

## Notes & limitations

- Linux only (uses `AF_PACKET` via Scapy and `/proc`-backed psutil).
- "Outgoing" = packet's source IP is one of this host's addresses; loopback is excluded.
- Process attribution matches on local port and can miss very short-lived sockets.
- Bind stays on `127.0.0.1`; do not expose this to a network.
