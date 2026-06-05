# Packet Tracer — Constellation UI

A deep-space "orbital command center" dashboard for the outbound traffic monitor,
designed in [Claude Design](https://claude.ai/design) and implemented here.

- **Constellation star-map** (`constellation.jsx`) — host hub at center, destinations
  orbiting as nodes (sized by bytes, colored by dominant protocol), packets
  animated as particles along the links, radar sweep + starfield on `<canvas>`.
- **Panels** (`panels.jsx`) — live packet stream, top destinations, protocol-mix
  donut, DNS feed, throughput sparkline.
- **Inspector** (`inspector.jsx`) — click a node / stream row / destination to open a
  drill-down drawer (totals, protocol breakdown, attributed processes, recent
  packets). Click a process chip to pivot to a process view. `Esc` closes.
- **Tweaks panel** (`tweaks-panel.jsx`) — accent color, font, density, glow, motion,
  capture rate; pause toggle on the status light.

## How it gets data

The app boots `DataSource.create(...)` (`datasource.js`), which:

1. Connects to the backend at **`ws://<host>/ws`** and dispatches the
   `snapshot` / `packets` / `dns` / `stats` messages (see the contract in the
   project `README.md`).
2. Runs the design's client-side `StatsAgg` (from `sim.js`) over the **real**
   packet stream to derive the per-destination `by_proto` / process breakdowns
   the constellation and inspector need (the backend's `stats.top_destinations`
   only carries `{ip, host, packets, bytes}`).
3. **Falls back to the bundled simulator** (`sim.js`) automatically if the backend
   isn't reachable or replies `{"type":"unavailable"}` (capture needs root) — so
   the dashboard is fully demoable even without privileges.

## Running

Served by the backend itself — `index.html` loads everything from `/static/`:

```bash
bash run.sh            # backend serves the UI at http://127.0.0.1:8000/
```

Stack: React 18 + Babel-standalone over CDN (no build step). Fonts (Space Grotesk,
JetBrains Mono, Chakra Petch) load from Google Fonts, so first paint needs network.

To swap in a different backend host, change the `/ws` target in `datasource.js`.
