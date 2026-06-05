"""Map outgoing packets to the owning process via psutil.

``psutil.net_connections`` is relatively expensive, so the connection table is
rebuilt at most once per ``PROCESS_REFRESH_SEC`` and reused for lookups.
"""

from __future__ import annotations

import threading
import time

import psutil

from . import config
from .models import ProcessInfo


class ProcessResolver:
    def __init__(self, refresh_sec: float = config.PROCESS_REFRESH_SEC) -> None:
        self._refresh_sec = refresh_sec
        self._lock = threading.Lock()
        # key: (proto, local_port) -> ProcessInfo
        self._table: dict[tuple[str, int], ProcessInfo] = {}
        self._pid_names: dict[int, str] = {}
        self._last_refresh = 0.0

    def _rebuild(self) -> None:
        table: dict[tuple[str, int], ProcessInfo] = {}
        names = self._pid_names
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Not enough privileges — leave table empty (attribution = null).
            conns = []
        for c in conns:
            if not c.laddr or c.pid is None:
                continue
            proto = "TCP" if c.type == 1 else "UDP"  # SOCK_STREAM == 1
            lport = c.laddr.port
            name = names.get(c.pid)
            if name is None:
                try:
                    name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    name = "?"
                names[c.pid] = name
            table[(proto, lport)] = ProcessInfo(pid=c.pid, name=name)
        with self._lock:
            self._table = table
            self._last_refresh = time.time()

    def maybe_refresh(self) -> None:
        if time.time() - self._last_refresh >= self._refresh_sec:
            self._rebuild()
            # Drop stale pid->name entries occasionally to bound memory.
            if len(self._pid_names) > 5000:
                self._pid_names.clear()

    def lookup(self, proto: str, src_port: int | None) -> ProcessInfo | None:
        if src_port is None:
            return None
        with self._lock:
            return self._table.get((proto, src_port))
