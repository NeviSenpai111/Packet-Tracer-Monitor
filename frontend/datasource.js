/* datasource.js — live data source for the dashboard.

   Connects to the real Packet Tracer backend at WebSocket `/ws` and dispatches
   the backend's `snapshot` / `packets` / `dns` / `stats` messages into the same
   callbacks the simulator used (see sim.js / README data contract).

   Because the backend's `stats.top_destinations` only carries {ip,host,packets,
   bytes}, but the constellation + inspector need per-destination protocol and
   process breakdowns, we run the design's own client-side StatsAgg over the
   real packet stream to derive getDestinations()/snapshot().

   If the backend isn't reachable (e.g. running the UI without root/capture),
   it transparently falls back to the bundled PacketSim so the dashboard still
   lives. Exposes the same interface as PacketSim.create(...). */
(function () {
  "use strict";

  const CONNECT_TIMEOUT_MS = 2500;  // no open within this -> assume no backend
  const RECONNECT_MS = 1500;
  const noop = function () {};

  function create(opts) {
    opts = opts || {};
    const onPackets = opts.onPackets || noop;
    const onDns = opts.onDns || noop;
    const onStats = opts.onStats || noop;
    const timelineSeconds = opts.timelineSeconds || 90;
    const topN = opts.topN || 8;

    const agg = new PacketSim.StatsAgg(timelineSeconds, topN);
    let rate = opts.rate != null ? opts.rate : 1;
    let running = false;
    let mode = "connecting";          // connecting | live | sim
    let ws = null, sim = null;
    let statTimer = null, connectTimer = null, retryTimer = null;
    let localIpSet = false;

    function setLocalIp(ip) {
      // The constellation hub label reads PacketSim.LOCAL_IP; point it at the
      // real source address once we've seen a packet.
      if (!localIpSet && ip) {
        localIpSet = true;
        try { window.PacketSim.LOCAL_IP = ip; } catch (e) {}
      }
    }

    function ingestPackets(items) {
      if (rate <= 0 || !items || !items.length) return;  // rate 0 == paused display
      setLocalIp(items[0].src_ip);
      for (const p of items) agg.record(p);
      onPackets(items);
    }

    function startSimFallback() {
      if (mode === "sim") return;
      mode = "sim";
      if (statTimer) { clearInterval(statTimer); statTimer = null; }
      // Delegate fully to the simulator (it manages its own aggregation).
      sim = PacketSim.create({ timelineSeconds, topN, onPackets, onDns, onStats });
      sim.setRate(rate);
      sim.start();
    }

    function connect() {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      try {
        ws = new WebSocket(proto + "://" + location.host + "/ws");
      } catch (e) {
        startSimFallback();
        return;
      }

      connectTimer = setTimeout(function () {
        if (mode === "connecting") {
          try { ws.close(); } catch (e) {}
          startSimFallback();
        }
      }, CONNECT_TIMEOUT_MS);

      ws.onopen = function () {
        clearTimeout(connectTimer);
        mode = "live";
        statTimer = setInterval(function () {
          if (rate > 0) onStats(agg.snapshot());
        }, 1000);
      };

      ws.onmessage = function (ev) {
        let msg;
        try { msg = JSON.parse(ev.data); } catch (e) { return; }
        switch (msg.type) {
          case "snapshot":
            if (msg.recent_packets && msg.recent_packets.length) {
              for (const p of msg.recent_packets) agg.record(p);
              setLocalIp(msg.recent_packets[msg.recent_packets.length - 1].src_ip);
            }
            onStats(agg.snapshot());
            break;
          case "packets":
            ingestPackets(msg.items || []);
            break;
          case "dns":
            if (rate > 0 && msg.items) onDns(msg.items);
            break;
          case "unavailable":
            // Backend is up but capture is disabled (no privileges) — switch to
            // the simulator so the dashboard still demonstrates fully.
            startSimFallback();
            try { ws.close(); } catch (e) {}
            break;
          case "stats":
            // Prefer our own agg snapshot so the stats stay consistent with the
            // per-destination breakdowns; backend `stats` is intentionally ignored.
            break;
        }
      };

      ws.onerror = function () { /* handled by onclose */ };

      ws.onclose = function () {
        clearTimeout(connectTimer);
        if (!running) return;
        if (mode === "live") {
          // Backend went away — try to reconnect.
          mode = "connecting";
          if (statTimer) { clearInterval(statTimer); statTimer = null; }
          retryTimer = setTimeout(connect, RECONNECT_MS);
        } else if (mode === "connecting") {
          startSimFallback();
        }
      };
    }

    return {
      start() {
        if (running) return;
        running = true;
        connect();
      },
      stop() {
        running = false;
        clearTimeout(connectTimer);
        clearTimeout(retryTimer);
        if (statTimer) { clearInterval(statTimer); statTimer = null; }
        if (ws) { try { ws.close(); } catch (e) {} }
        if (sim) sim.stop();
      },
      setRate(r) { rate = r; if (sim) sim.setRate(r); },
      getRate() { return rate; },
      snapshot() { return mode === "sim" && sim ? sim.snapshot() : agg.snapshot(); },
      getDestinations() { return mode === "sim" && sim ? sim.getDestinations() : agg.destinations(); },
      isRunning() { return running; },
      getMode() { return mode; },
    };
  }

  window.DataSource = { create };
})();
