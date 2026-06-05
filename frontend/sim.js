/* sim.js — Realistic packet/DNS/stats simulator matching the Packet Tracer
   WebSocket/REST contract (see repo README.md). Plain JS, attaches to window.

   Emits the same shapes the real backend would:
     onPackets(items)  items: [{ts, proto, src_ip, src_port, dst_ip, dst_port,
                                  size, dst_host, flags, process:{pid,name}|null}]
     onDns(items)      items: [{ts, query, qtype}]
     onStats(stats)    stats: {total_packets,total_bytes,throughput_bps,
                               by_proto, top_destinations[], timeline[]}
   Also exposes getDestinations() with full per-host aggregates for the map.
*/
(function () {
  "use strict";

  const LOCAL_IP = "192.168.1.37";

  // Catalog of plausible outbound destinations. weight = relative chattiness.
  // kind drives the dominant protocol/color of the node.
  const CATALOG = [
    { host: "api.openai.com",        ip: "104.18.32.115",  weight: 22, proto: "TCP", port: 443, procs: ["python3", "chrome"], kind: "api" },
    { host: "github.com",            ip: "140.82.121.4",   weight: 14, proto: "TCP", port: 443, procs: ["git", "code"], kind: "api" },
    { host: "cdn.cloudflare.com",    ip: "104.16.85.20",   weight: 18, proto: "TCP", port: 443, procs: ["chrome", "firefox"], kind: "cdn" },
    { host: "rr3---googlevideo.com", ip: "142.250.72.206", weight: 26, proto: "UDP", port: 443, procs: ["firefox"], kind: "media" },
    { host: "registry.npmjs.org",    ip: "104.16.27.34",   weight: 8,  proto: "TCP", port: 443, procs: ["node", "npm"], kind: "cdn" },
    { host: "audio-fa.scdn.co",      ip: "35.186.224.47",  weight: 16, proto: "TCP", port: 443, procs: ["spotify"], kind: "media" },
    { host: "gateway.discord.gg",    ip: "162.159.130.234",weight: 12, proto: "UDP", port: 443, procs: ["Discord"], kind: "media" },
    { host: "one.one.one.one",       ip: "1.1.1.1",        weight: 10, proto: "UDP", port: 53,  procs: ["systemd-resolve"], kind: "dns" },
    { host: "dns.google",            ip: "8.8.8.8",        weight: 6,  proto: "UDP", port: 53,  procs: ["systemd-resolve"], kind: "dns" },
    { host: "steamcdn-a.akamaihd.net",ip: "23.59.94.30",   weight: 9,  proto: "TCP", port: 443, procs: ["steam"], kind: "cdn" },
    { host: "slack.com",             ip: "3.89.118.7",     weight: 7,  proto: "TCP", port: 443, procs: ["slack"], kind: "api" },
    { host: "us05web.zoom.us",       ip: "170.114.52.2",   weight: 8,  proto: "UDP", port: 8801,procs: ["zoom"], kind: "media" },
    { host: "archive.ubuntu.com",    ip: "185.125.190.36", weight: 4,  proto: "TCP", port: 80,  procs: ["apt"], kind: "cdn" },
    { host: "s3.amazonaws.com",      ip: "52.216.18.40",   weight: 9,  proto: "TCP", port: 443, procs: ["docker", "aws"], kind: "api" },
    { host: "telemetry.mozilla.org", ip: "44.235.12.9",    weight: 5,  proto: "TCP", port: 443, procs: ["firefox"], kind: "api" },
    { host: "grafana.internal",      ip: "10.0.0.12",      weight: 6,  proto: "TCP", port: 3000,procs: ["chrome"], kind: "internal" },
    { host: null,                    ip: "192.168.1.1",    weight: 5,  proto: "ICMP",port: null, procs: ["ping"], kind: "icmp" },
    { host: "fcm.googleapis.com",    ip: "142.250.72.234", weight: 7,  proto: "TCP", port: 443, procs: ["chrome"], kind: "api" },
  ];

  // pid pool — stable pid per process name
  const PIDS = {};
  let pidSeq = 1100;
  function pidFor(name) {
    if (!PIDS[name]) PIDS[name] = (pidSeq += Math.floor(7 + Math.random() * 40));
    return PIDS[name];
  }

  const TCP_FLAGS = ["PA", "PA", "PA", "A", "A", "S", "SA", "FA", "PA"];
  const QTYPES = ["A", "A", "A", "AAAA", "HTTPS", "CNAME"];

  function pick(arr) { return arr[(Math.random() * arr.length) | 0]; }
  function weightedPick(items) {
    let total = 0;
    for (const it of items) total += it.weight;
    let r = Math.random() * total;
    for (const it of items) { r -= it.weight; if (r <= 0) return it; }
    return items[items.length - 1];
  }

  function packetSize(proto, port) {
    if (proto === "ICMP" || proto === "ICMPv6") return 64 + ((Math.random() * 34) | 0);
    if (proto === "UDP" && port === 53) return 58 + ((Math.random() * 70) | 0);  // DNS
    if (proto === "UDP") return 180 + ((Math.random() * 1100) | 0);              // QUIC/media
    // TCP: mix of small ACKs and full data segments
    if (Math.random() < 0.32) return 40 + ((Math.random() * 26) | 0);
    return 220 + ((Math.random() * 1240) | 0);
  }

  function StatsAgg(timelineSeconds, topN) {
    this.total_packets = 0;
    this.total_bytes = 0;
    this.by_proto = {};
    this.dst = {};          // ip -> {host, packets, bytes, by_proto, procs:{}, last}
    this.timeline = [];     // [{t, bytes, packets}]
    this.timelineSeconds = timelineSeconds;
    this.topN = topN;
  }
  StatsAgg.prototype.record = function (p) {
    const sec = Math.floor(p.ts);
    this.total_packets++;
    this.total_bytes += p.size;
    this.by_proto[p.proto] = (this.by_proto[p.proto] || 0) + 1;
    let d = this.dst[p.dst_ip];
    if (!d) { d = { host: p.dst_host, packets: 0, bytes: 0, by_proto: {}, procs: {}, last: p.ts }; this.dst[p.dst_ip] = d; }
    d.packets++; d.bytes += p.size; d.last = p.ts;
    d.by_proto[p.proto] = (d.by_proto[p.proto] || 0) + 1;
    if (p.dst_host && !d.host) d.host = p.dst_host;
    if (p.process) d.procs[p.process.name] = (d.procs[p.process.name] || 0) + 1;
    const tl = this.timeline;
    if (tl.length && tl[tl.length - 1].t === sec) {
      tl[tl.length - 1].bytes += p.size; tl[tl.length - 1].packets += 1;
    } else {
      tl.push({ t: sec, bytes: p.size, packets: 1 });
      while (tl.length > this.timelineSeconds) tl.shift();
    }
  };
  StatsAgg.prototype.snapshot = function () {
    const now = Math.floor(Date.now() / 1000);
    const top = Object.keys(this.dst).map((ip) => {
      const v = this.dst[ip];
      return { ip, host: v.host, packets: v.packets, bytes: v.bytes };
    }).sort((a, b) => b.bytes - a.bytes).slice(0, this.topN);
    let throughput_bps = 0;
    for (let i = this.timeline.length - 1; i >= 0; i--) {
      if (this.timeline[i].t < now) { throughput_bps = this.timeline[i].bytes * 8; break; }
    }
    return {
      type: "stats",
      total_packets: this.total_packets,
      total_bytes: this.total_bytes,
      throughput_bps,
      by_proto: Object.assign({}, this.by_proto),
      top_destinations: top,
      timeline: this.timeline.slice(),
    };
  };
  StatsAgg.prototype.destinations = function () {
    return Object.keys(this.dst).map((ip) => {
      const v = this.dst[ip];
      return {
        ip, host: v.host, packets: v.packets, bytes: v.bytes,
        by_proto: Object.assign({}, v.by_proto),
        procs: Object.assign({}, v.procs), last: v.last,
      };
    });
  };

  function create(opts) {
    opts = opts || {};
    const onPackets = opts.onPackets || function () {};
    const onDns = opts.onDns || function () {};
    const onStats = opts.onStats || function () {};
    const timelineSeconds = opts.timelineSeconds || 90;
    const topN = opts.topN || 8;

    const agg = new StatsAgg(timelineSeconds, topN);
    let rate = opts.rate != null ? opts.rate : 1; // multiplier
    let packTimer = null, statTimer = null, running = false;

    function makePacket(now) {
      const c = weightedPick(CATALOG);
      let proto = c.proto;
      // a little protocol variety per host
      if (c.kind === "media" && proto === "TCP" && Math.random() < 0.4) proto = "UDP";
      const size = packetSize(proto, c.port);
      const procName = pick(c.procs);
      const process = Math.random() < 0.88 ? { pid: pidFor(procName), name: procName } : null;
      return {
        ts: now,
        proto,
        src_ip: LOCAL_IP,
        src_port: 32768 + ((Math.random() * 28000) | 0),
        dst_ip: c.ip,
        dst_port: c.port,
        size,
        dst_host: c.host,
        flags: proto === "TCP" ? pick(TCP_FLAGS) : null,
        process,
      };
    }

    function tick() {
      const now = Date.now() / 1000;
      // burst-y traffic: usually a few packets, sometimes a burst
      let n = 1 + ((Math.random() * 4) | 0);
      if (Math.random() < 0.12) n += 4 + ((Math.random() * 8) | 0);
      n = Math.max(0, Math.round(n * rate));
      const items = [];
      for (let i = 0; i < n; i++) {
        const p = makePacket(now + i * 0.001);
        agg.record(p);
        items.push(p);
      }
      if (items.length) onPackets(items);

      if (rate > 0 && Math.random() < 0.22) {
        const c = weightedPick(CATALOG.filter((x) => x.host));
        onDns([{ ts: now, query: c.host, qtype: pick(QTYPES) }]);
      }
    }

    return {
      start() {
        if (running) return;
        running = true;
        packTimer = setInterval(tick, 120);
        statTimer = setInterval(() => onStats(agg.snapshot()), 1000);
        // prime a little history so the UI isn't empty
        const base = Date.now() / 1000;
        for (let s = timelineSeconds; s > 0; s--) {
          const t = Math.floor(base) - s;
          const burst = 2 + ((Math.random() * 6) | 0);
          for (let i = 0; i < burst; i++) {
            const p = makePacket(t + i * 0.01); p.ts = t; agg.record(p);
          }
        }
        onStats(agg.snapshot());
      },
      stop() {
        running = false;
        clearInterval(packTimer); clearInterval(statTimer);
      },
      setRate(r) { rate = r; },
      getRate() { return rate; },
      snapshot() { return agg.snapshot(); },
      getDestinations() { return agg.destinations(); },
      isRunning() { return running; },
    };
  }

  // StatsAgg is exported so the live WebSocket data source (datasource.js) can
  // reuse the exact same client-side aggregation to build per-destination
  // by_proto / process breakdowns the inspector & constellation need.
  window.PacketSim = { create, CATALOG, LOCAL_IP, StatsAgg };
})();
