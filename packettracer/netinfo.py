"""Local network info: which IPs belong to this host + BPF filter building."""

from __future__ import annotations

import socket
import threading
import time

import psutil

from . import config


class LocalAddresses:
    """Tracks the set of local IP addresses, refreshed periodically.

    Used both to classify packet direction (src in local set == outgoing) and
    to build a libpcap ``src host ...`` filter so the kernel does the work.
    """

    def __init__(self, refresh_sec: float = config.LOCAL_IP_REFRESH_SEC) -> None:
        self._refresh_sec = refresh_sec
        self._lock = threading.Lock()
        self._ips: set[str] = set()
        self._last_refresh = 0.0
        self.refresh()

    def refresh(self) -> set[str]:
        ips: set[str] = set()
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    # Strip IPv6 zone id (e.g. fe80::1%eth0).
                    ip = addr.address.split("%", 1)[0]
                    if ip:
                        ips.add(ip)
        with self._lock:
            self._ips = ips
            self._last_refresh = time.time()
        return ips

    def maybe_refresh(self) -> None:
        if time.time() - self._last_refresh >= self._refresh_sec:
            self.refresh()

    def is_local(self, ip: str) -> bool:
        with self._lock:
            return ip in self._ips

    def snapshot(self) -> set[str]:
        with self._lock:
            return set(self._ips)

    def bpf_filter(self) -> str | None:
        """Build a BPF expression matching packets *sourced* from this host.

        Returns None if no addresses are known (sniff everything).
        """
        ips = self.snapshot()
        # Loopback traffic is rarely interesting for "outgoing" monitoring and
        # bloats the stream; exclude the obvious loopback addresses.
        ips = {ip for ip in ips if ip not in ("127.0.0.1", "::1")}
        if not ips:
            return None
        return " or ".join(f"src host {ip}" for ip in sorted(ips))
