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

# --- DNS --------------------------------------------------------------------
DNS_CACHE_MAX = 20000          # max IP->host entries
ENABLE_REVERSE_DNS = True      # best-effort PTR lookups for unknown IPs
REVERSE_DNS_WORKERS = 4
REVERSE_DNS_MAX_INFLIGHT = 256
