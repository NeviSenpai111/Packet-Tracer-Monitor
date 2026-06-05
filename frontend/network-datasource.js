/* network-datasource.js — live data source for the network monitor page.

   Connects to the backend at WebSocket `/ws/network` and dispatches the
   `snapshot` / `packets` / `dns` / `stats` messages. Unlike the host view, the
   backend is authoritative for the device list (it knows MAC / vendor / hostname),
   so this source simply surfaces the latest `stats.devices` via getDestinations().

   Falls back to the bundled NetworkSim if the backend is unreachable or replies
   `{"type":"unavailable"}` (capture needs root). Same interface as PacketSim. */
(function () {
  "use strict";

  const CONNECT_TIMEOUT_MS = 2500;
  const RECONNECT_MS = 1500;
  const noop = function () {};

  function create(opts) {
    opts = opts || {};
    const onPackets = opts.onPackets || noop;
    const onDns = opts.onDns || noop;
    const onStats = opts.onStats || noop;
    const timelineSeconds = opts.timelineSeconds || 90;

    let rate = opts.rate != null ? opts.rate : 1;
    let running = false;
    let mode = "connecting";          // connecting | live | sim
    let ws = null, sim = null;
    let connectTimer = null, retryTimer = null;
    let lastDevices = [];
    let lastStats = { devices: [], gateway_ip: null, subnet: null };

    function startSimFallback() {
      if (mode === "sim") return;
      mode = "sim";
      sim = NetworkSim.create({ timelineSeconds, onPackets, onDns, onStats });
      sim.setRate(rate);
      sim.start();
    }

    function connect() {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      try {
        ws = new WebSocket(proto + "://" + location.host + "/ws/network");
      } catch (e) {
        startSimFallback();
        return;
      }

      connectTimer = setTimeout(function () {
        if (mode === "connecting") { try { ws.close(); } catch (e) {} startSimFallback(); }
      }, CONNECT_TIMEOUT_MS);

      ws.onopen = function () { clearTimeout(connectTimer); mode = "live"; };

      ws.onmessage = function (ev) {
        let msg;
        try { msg = JSON.parse(ev.data); } catch (e) { return; }
        switch (msg.type) {
          case "snapshot":
            if (msg.stats) { lastStats = msg.stats; lastDevices = msg.stats.devices || []; onStats(msg.stats); }
            if (rate > 0 && msg.recent_packets && msg.recent_packets.length) {
              onPackets(msg.recent_packets.slice().reverse());
            }
            break;
          case "packets":
            if (rate > 0 && msg.items) onPackets(msg.items);
            break;
          case "dns":
            if (rate > 0 && msg.items) onDns(msg.items);
            break;
          case "stats":
            lastStats = msg; lastDevices = msg.devices || []; onStats(msg);
            break;
          case "unavailable":
            startSimFallback();
            try { ws.close(); } catch (e) {}
            break;
        }
      };

      ws.onerror = function () { /* handled by onclose */ };

      ws.onclose = function () {
        clearTimeout(connectTimer);
        if (!running) return;
        if (mode === "live") { mode = "connecting"; retryTimer = setTimeout(connect, RECONNECT_MS); }
        else if (mode === "connecting") { startSimFallback(); }
      };
    }

    return {
      start() { if (running) return; running = true; connect(); },
      stop() {
        running = false;
        clearTimeout(connectTimer); clearTimeout(retryTimer);
        if (ws) { try { ws.close(); } catch (e) {} }
        if (sim) sim.stop();
      },
      setRate(r) { rate = r; if (sim) sim.setRate(r); },
      getRate() { return rate; },
      snapshot() { return mode === "sim" && sim ? sim.snapshot() : lastStats; },
      getDestinations() { return mode === "sim" && sim ? sim.getDestinations() : lastDevices; },
      isRunning() { return running; },
      getMode() { return mode; },
    };
  }

  window.NetworkDataSource = { create };
})();
