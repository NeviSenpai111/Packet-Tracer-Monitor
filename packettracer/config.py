"""Central configuration / tunables."""

from __future__ import annotations

import os

# --- Server -----------------------------------------------------------------
HOST = os.environ.get("PT_HOST", "127.0.0.1")
PORT = int(os.environ.get("PT_PORT", "8000"))

# --- Capture ----------------------------------------------------------------
# Interface to sniff. None = all interfaces (scapy default).
IFACE = os.environ.get("PT_IFACE") or None

# Refresh cadence (seconds) for re-deriving local IPs / rebuilding BPF filter.
LOCAL_IP_REFRESH_SEC = 30.0

# How often the process-attribution table is rebuilt from psutil (expensive).
PROCESS_REFRESH_SEC = 1.0

# --- Broadcaster ------------------------------------------------------------
# Max time between WebSocket packet flushes.
FLUSH_INTERVAL_SEC = 0.1
# Max packets buffered per flush before forcing a send.
FLUSH_MAX_BATCH = 200
# Bounded handoff queue between sniffer thread and asyncio loop.
QUEUE_MAXSIZE = 10000
# Stats emission cadence.
STATS_INTERVAL_SEC = 1.0

# --- Stats ------------------------------------------------------------------
TIMELINE_SECONDS = 60          # rolling throughput window
TOP_DESTINATIONS = 15          # top-N destinations to report
RECENT_PACKETS = 200           # packets retained for /api/snapshot bootstrap

# --- Network monitor (page 2) ----------------------------------------------
# Capture in promiscuous mode so we see broadcast/multicast + (with port
# mirroring) other devices' traffic, not just our own.
NET_PROMISC = True
# Active ARP discovery sweep of local /24s to find quiet devices.
DISCOVERY_ENABLED = os.environ.get("PT_DISCOVERY", "1") != "0"
DISCOVERY_INTERVAL_SEC = 45.0
DISCOVERY_MAX_HOSTS = 512       # skip sweeping subnets larger than this
DISCOVERY_SEND_GAP_SEC = 0.004  # throttle between ARP probes

# --- MITM (ARP spoofing) — OFF by default --------------------------------
# Active interception: poison the ARP caches of LAN devices and the gateway so
# their traffic is routed through THIS host, making other devices' unicast
# traffic visible without a managed switch / port mirror. This is intrusive and
# only appropriate on a network you own. Enable with PT_MITM=1.
MITM_ENABLED = os.environ.get("PT_MITM", "0") == "1"
# Re-assert the poisoned ARP entries this often (caches expire / get corrected).
MITM_INTERVAL_SEC = 2.0
# Restrict targets to these IPs (comma-separated). Empty = every discovered
# LAN device except this host and the gateway.
MITM_TARGETS = os.environ.get("PT_MITM_TARGETS", "")
# How many corrective ARP replies to send per target when restoring on exit.
MITM_RESTORE_ROUNDS = 4

# --- DNS --------------------------------------------------------------------
DNS_CACHE_MAX = 20000          # max IP->host entries
ENABLE_REVERSE_DNS = True      # best-effort PTR lookups for unknown IPs
REVERSE_DNS_WORKERS = 4
REVERSE_DNS_MAX_INFLIGHT = 256
