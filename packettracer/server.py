"""FastAPI server: WebSocket stream + REST snapshot + static frontend.

Bridges the synchronous scapy sniffer thread to async WebSocket clients via a
thread-safe ``queue.Queue`` drained on an executor.
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


class App:
    """Holds runtime state shared across requests/tasks."""

    def __init__(self) -> None:
        self.queue: "queue.Queue" = queue.Queue(maxsize=config.QUEUE_MAXSIZE)
        self.sniffer = Sniffer(self.queue)
        self.manager = ConnectionManager()
        self.recent: deque = deque(maxlen=config.RECENT_PACKETS)
        self._tasks: list[asyncio.Task] = []
        self._running = False

    async def _pump(self) -> None:
        loop = asyncio.get_running_loop()
        while self._running:
            batch = await loop.run_in_executor(
                None,
                _collect_batch,
                self.queue,
                config.FLUSH_MAX_BATCH,
                config.FLUSH_INTERVAL_SEC,
            )
            if not batch:
                continue
            packets = []
            dns = []
            for kind, payload in batch:
                if kind == "packet":
                    d = payload.to_dict()
                    packets.append(d)
                    self.recent.append(d)
                elif kind == "dns":
                    dns.append(payload.to_dict())
            if packets:
                await self.manager.broadcast({"type": "packets", "items": packets})
            if dns:
                await self.manager.broadcast({"type": "dns", "items": dns})

    async def _stats_loop(self) -> None:
        while self._running:
            await asyncio.sleep(config.STATS_INTERVAL_SEC)
            snap = self.sniffer.stats.snapshot()
            snap["type"] = "stats"
            await self.manager.broadcast(snap)

    def start(self) -> None:
        self._running = True
        self.sniffer.start()
        self._tasks = [
            asyncio.create_task(self._pump()),
            asyncio.create_task(self._stats_loop()),
        ]

    async def stop(self) -> None:
        self._running = False
        self.sniffer.stop()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass

    def snapshot(self) -> dict:
        snap = self.sniffer.stats.snapshot()
        return {"stats": snap, "recent_packets": list(self.recent)}


state = App()


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.start()
    log.info("packettracer started on http://%s:%s", config.HOST, config.PORT)
    try:
        yield
    finally:
        await state.stop()


app = FastAPI(title="Packet Tracer", lifespan=lifespan)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/snapshot")
async def api_snapshot() -> JSONResponse:
    return JSONResponse(state.snapshot())


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await state.manager.connect(ws)
    try:
        # Bootstrap the client with current state.
        snap = state.snapshot()
        await ws.send_json({"type": "snapshot", **snap})
        while True:
            # We don't expect client messages; this keeps the socket alive and
            # detects disconnects.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        pass
    finally:
        await state.manager.disconnect(ws)


# Static assets (app.js, style.css) under /static.
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
