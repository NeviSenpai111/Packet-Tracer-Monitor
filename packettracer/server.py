"""FastAPI server: WebSocket streams + REST snapshots + static frontend.

Serves two views, each a synchronous scapy sniffer bridged to async WebSocket
clients via a thread-safe ``queue.Queue`` drained on an executor:

  * host view   — outbound traffic from this machine   (/, /ws, /api/snapshot)
  * network view — devices & traffic on the LAN  (/network, /ws/network, /api/network/snapshot)
"""

from __future__ import annotations

import asyncio
import logging
import queue
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .capture import Sniffer
from .netcapture import NetworkSniffer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("packettracer.server")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


class ConnectionManager:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, message: dict) -> None:
        async with self._lock:
            clients = list(self._clients)
        dead = []
        for ws in clients:
            try:
                await ws.send_json(message)
            except Exception:  # noqa: BLE001 - client went away mid-send
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)


def _collect_batch(q: "queue.Queue", max_items: int, timeout: float) -> list:
    """Block up to ``timeout`` for the first item, then drain without waiting."""
    items: list = []
    try:
        items.append(q.get(timeout=timeout))
    except queue.Empty:
        return items
    for _ in range(max_items - 1):
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            break
    return items


def _to_dict(payload):
    """Payloads may be dataclasses (host view) or plain dicts (network view)."""
    return payload.to_dict() if hasattr(payload, "to_dict") else payload


class StreamApp:
    """Base: bridges a sniffer thread to WebSocket clients + stats broadcast."""

    name = "stream"
    disabled_reason = "live capture disabled (needs root / cap_net_raw)"

    def __init__(self) -> None:
        self.queue: "queue.Queue" = queue.Queue(maxsize=config.QUEUE_MAXSIZE)
        self.sniffer = None  # set by subclass
        self.manager = ConnectionManager()
        self.recent: deque = deque(maxlen=config.RECENT_PACKETS)
        self._tasks: list[asyncio.Task] = []
        self._running = False
        self.capture_ok = False

    # subclasses override to build the stats payload
    def _stats_snapshot(self) -> dict:
        raise NotImplementedError

    async def _pump(self) -> None:
        loop = asyncio.get_running_loop()
        while self._running:
            batch = await loop.run_in_executor(
                None, _collect_batch, self.queue,
                config.FLUSH_MAX_BATCH, config.FLUSH_INTERVAL_SEC,
            )
            if not batch:
                continue
            packets, dns = [], []
            for kind, payload in batch:
                if kind == "packet":
                    d = _to_dict(payload)
                    packets.append(d)
                    self.recent.append(d)
                elif kind == "dns":
                    dns.append(_to_dict(payload))
            if packets:
                await self.manager.broadcast({"type": "packets", "items": packets})
            if dns:
                await self.manager.broadcast({"type": "dns", "items": dns})

    async def _stats_loop(self) -> None:
        while self._running:
            await asyncio.sleep(config.STATS_INTERVAL_SEC)
            snap = self._stats_snapshot()
            snap["type"] = "stats"
            await self.manager.broadcast(snap)

    def start(self) -> None:
        self._running = True
        try:
            self.sniffer.start()
            self.capture_ok = True
        except Exception as e:  # noqa: BLE001 - typically PermissionError (no root)
            self.capture_ok = False
            log.warning(
                "[%s] packet capture unavailable (%s: %s) — serving UI only; run "
                "under sudo or grant cap_net_raw. The dashboard falls back to "
                "simulated traffic.", self.name, type(e).__name__, e,
            )
        self._tasks = [
            asyncio.create_task(self._pump()),
            asyncio.create_task(self._stats_loop()),
        ]

    async def stop(self) -> None:
        self._running = False
        if self.capture_ok:
            self.sniffer.stop()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass

    def snapshot(self) -> dict:
        return {"stats": self._stats_snapshot(), "recent_packets": list(self.recent)}

    async def serve_ws(self, ws: WebSocket) -> None:
        # If capture isn't running (e.g. no privileges), tell the client so it
        # transparently falls back to its bundled simulator.
        if not self.capture_ok:
            await ws.accept()
            await ws.send_json({"type": "unavailable", "reason": self.disabled_reason})
            await ws.close()
            return
        await self.manager.connect(ws)
        try:
            await ws.send_json({"type": "snapshot", **self.snapshot()})
            while True:
                await ws.receive_text()  # keepalive / disconnect detection
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001
            pass
        finally:
            await self.manager.disconnect(ws)


class HostApp(StreamApp):
    name = "host"

    def __init__(self) -> None:
        super().__init__()
        self.sniffer = Sniffer(self.queue)

    def _stats_snapshot(self) -> dict:
        return self.sniffer.stats.snapshot()


class NetworkApp(StreamApp):
    name = "network"

    def __init__(self) -> None:
        super().__init__()
        self.sniffer = NetworkSniffer(self.queue)

    def _stats_snapshot(self) -> dict:
        s = self.sniffer
        return s.stats.snapshot(s.registry, s.gateway_ip(), s.subnet())


host = HostApp()
network = NetworkApp()


@asynccontextmanager
async def lifespan(app: FastAPI):
    host.start()
    network.start()
    log.info("packettracer started on http://%s:%s", config.HOST, config.PORT)
    try:
        yield
    finally:
        await host.stop()
        await network.stop()


app = FastAPI(title="Packet Tracer", lifespan=lifespan)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/network")
async def network_index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "network.html")


@app.get("/api/snapshot")
async def api_snapshot() -> JSONResponse:
    return JSONResponse(host.snapshot())


@app.get("/api/network/snapshot")
async def api_network_snapshot() -> JSONResponse:
    return JSONResponse(network.snapshot())


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await host.serve_ws(ws)


@app.websocket("/ws/network")
async def ws_network_endpoint(ws: WebSocket) -> None:
    await network.serve_ws(ws)


# Static assets under /static.
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
