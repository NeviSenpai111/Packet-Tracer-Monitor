"""Per-device traffic aggregation for the network monitor.

Tracks traffic volume per LAN device and joins it with DeviceRegistry identity
to emit a stats snapshot whose `devices` / `top_destinations` shapes are
consumed directly by the (reused) constellation frontend.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from . import config


class NetworkStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self._by_proto: dict[str, int] = defaultdict(int)
        # device_ip -> {"packets", "bytes", "by_proto"{}, "last"}
        self._dev: dict[str, dict] = {}
        self._timeline: "deque[tuple[int, int, int]]" = deque(
            maxlen=config.TIMELINE_SECONDS
        )

    def record(self, device_ip: str, proto: str, size: int, ts: float) -> None:
        sec = int(ts)
        with self._lock:
            self.total_packets += 1
            self.total_bytes += size
            self._by_proto[proto] += 1

            d = self._dev.get(device_ip)
            if d is None:
                d = {"packets": 0, "bytes": 0, "by_proto": defaultdict(int), "last": ts}
                self._dev[device_ip] = d
            d["packets"] += 1
            d["bytes"] += size
            d["by_proto"][proto] += 1
            d["last"] = ts

            if self._timeline and self._timeline[-1][0] == sec:
                t, b, p = self._timeline[-1]
                self._timeline[-1] = (t, b + size, p + 1)
            else:
                self._timeline.append((sec, size, 1))

    def snapshot(self, registry, gateway_ip: str | None, subnet: str | None) -> dict:
        now = int(time.time())
        identities = {d["ip"]: d for d in registry.snapshot()}
        with self._lock:
            # Union of discovered devices (incl. silent) and devices with traffic.
            ips = set(identities) | set(self._dev)
            devices = []
            for ip in ips:
                ident = identities.get(ip, {})
                # The gateway is shown as the constellation hub, not a node.
                if ident.get("is_gateway") or ip == gateway_ip:
                    continue
                traf = self._dev.get(ip)
                by_proto = dict(traf["by_proto"]) if traf else {}
                label = ident.get("hostname") or ident.get("vendor") or ip
                devices.append({
                    "ip": ip,
                    "mac": ident.get("mac"),
                    "vendor": ident.get("vendor"),
                    "hostname": ident.get("hostname"),
                    "host": label,
                    "packets": traf["packets"] if traf else 0,
                    "bytes": traf["bytes"] if traf else 0,
                    "by_proto": by_proto,
                    "procs": {},  # no per-process attribution for remote devices
                    "last": traf["last"] if traf else ident.get("last_seen", 0),
                    "is_gateway": ident.get("is_gateway", ip == gateway_ip),
                    "is_self": ident.get("is_self", False),
                })
            devices.sort(key=lambda d: d["bytes"], reverse=True)
            top = [
                {"ip": d["ip"], "host": d["host"], "packets": d["packets"], "bytes": d["bytes"]}
                for d in devices[: config.TOP_DESTINATIONS]
            ]
            throughput_bps = 0
            for t, b, _p in reversed(self._timeline):
                if t < now:
                    throughput_bps = b * 8
                    break
            timeline = [{"t": t, "bytes": b, "packets": p} for (t, b, p) in self._timeline]
            return {
                "type": "stats",
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "throughput_bps": throughput_bps,
                "by_proto": dict(self._by_proto),
                "top_destinations": top,
                "timeline": timeline,
                "devices": devices,
                "gateway_ip": gateway_ip,
                "subnet": subnet,
                "device_count": len(devices),
            }
