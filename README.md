# Packet Tracer — Outgoing Traffic Monitor

Captures **outgoing** network traffic on this Linux host with Scapy and streams
it, structured, to a web dashboard over WebSocket. Shows the core 5-tuple,
resolved hostnames, per-process attribution, and live stats.

The bundled web UI (`frontend/`) is a **throwaway placeholder** to verify the
pipeline. The polished interface will be built later with the Claude Design
product against the stable JSON contract documented below.

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
- `packettracer/server.py` — FastAPI WS `/ws`, REST `/api/snapshot`, static UI.

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
