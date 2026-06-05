"""Aggregate live statistics over the captured packet stream."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from . import config
from .models import PacketEvent


class StatsAggregator:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self._by_proto: dict[str, int] = defaultdict(int)
        # dst_ip -> {"host": str|None, "packets": int, "bytes": int}
        self._dst: dict[str, dict] = {}
        # rolling per-second buckets: epoch_second -> [bytes, packets]
        self._timeline: "deque[tuple[int, int, int]]" = deque(
            maxlen=config.TIMELINE_SECONDS
        )

    def record(self, pkt: PacketEvent) -> None:
        sec = int(pkt.ts)
        with self._lock:
            self.total_packets += 1
            self.total_bytes += pkt.size
            self._by_proto[pkt.proto] += 1

            d = self._dst.get(pkt.dst_ip)
            if d is None:
                d = {"host": pkt.dst_host, "packets": 0, "bytes": 0}
                self._dst[pkt.dst_ip] = d
            d["packets"] += 1
            d["bytes"] += pkt.size
            if pkt.dst_host and not d["host"]:
                d["host"] = pkt.dst_host

            if self._timeline and self._timeline[-1][0] == sec:
                t, b, p = self._timeline[-1]
                self._timeline[-1] = (t, b + pkt.size, p + 1)
            else:
                self._timeline.append((sec, pkt.size, 1))

    def snapshot(self) -> dict:
        now = int(time.time())
        with self._lock:
            top = sorted(
                self._dst.items(), key=lambda kv: kv[1]["bytes"], reverse=True
            )[: config.TOP_DESTINATIONS]
            top_destinations = [
                {
                    "ip": ip,
                    "host": v["host"],
                    "packets": v["packets"],
                    "bytes": v["bytes"],
                }
                for ip, v in top
            ]
            # Throughput = bytes in the most recent completed second.
            throughput_bps = 0
            for t, b, _p in reversed(self._timeline):
                if t < now:
                    throughput_bps = b * 8
                    break
            timeline = [
                {"t": t, "bytes": b, "packets": p} for (t, b, p) in self._timeline
            ]
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "throughput_bps": throughput_bps,
                "by_proto": dict(self._by_proto),
                "top_destinations": top_destinations,
                "timeline": timeline,
            }
