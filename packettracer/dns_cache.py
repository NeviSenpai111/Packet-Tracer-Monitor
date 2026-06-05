"""IP -> hostname resolution.

Primary source: passively learn mappings from sniffed DNS *responses* (no extra
network traffic, accurate to what the host actually resolved). Fallback:
best-effort reverse PTR lookups in a small thread pool, bounded to avoid
blocking or flooding.
"""

from __future__ import annotations

import socket
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

from . import config


class DnsCache:
    def __init__(
        self,
        max_entries: int = config.DNS_CACHE_MAX,
        enable_reverse: bool = config.ENABLE_REVERSE_DNS,
    ) -> None:
        self._lock = threading.Lock()
        self._map: "OrderedDict[str, str]" = OrderedDict()  # ip -> host
        self._max = max_entries
        self._enable_reverse = enable_reverse
        self._inflight: set[str] = set()
        self._pool = (
            ThreadPoolExecutor(max_workers=config.REVERSE_DNS_WORKERS)
            if enable_reverse
            else None
        )

    def _put(self, ip: str, host: str) -> None:
        with self._lock:
            self._map[ip] = host
            self._map.move_to_end(ip)
            while len(self._map) > self._max:
                self._map.popitem(last=False)

    def learn(self, ip: str, host: str) -> None:
        """Record a mapping learned from a DNS A/AAAA answer."""
        if ip and host:
            self._put(ip, host.rstrip("."))

    def get(self, ip: str) -> str | None:
        """Return a known hostname for ``ip``, scheduling a PTR lookup if not."""
        with self._lock:
            host = self._map.get(ip)
            if host is not None:
                self._map.move_to_end(ip)
                # Empty string is a cached negative (PTR lookup failed).
                return host or None
        self._schedule_reverse(ip)
        return None

    def _schedule_reverse(self, ip: str) -> None:
        if not self._enable_reverse or self._pool is None:
            return
        with self._lock:
            if ip in self._map or ip in self._inflight:
                return
            if len(self._inflight) >= config.REVERSE_DNS_MAX_INFLIGHT:
                return
            self._inflight.add(ip)
        self._pool.submit(self._reverse, ip)

    def _reverse(self, ip: str) -> None:
        host = None
        try:
            host = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror):
            host = None
        finally:
            with self._lock:
                self._inflight.discard(ip)
            # Cache negatives as empty so we don't retry endlessly.
            self._put(ip, host or "")

    def shutdown(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
