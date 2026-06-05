/* network-sim.js — simulates a home LAN for the network monitor page.

   Emits the same shapes the real /ws/network backend produces:
     onPackets(items)  items attributed to a LAN device (dst_ip = device ip)
     onDns(items)      {ts, query, qtype}
     onStats(stats)    {..., devices:[{ip,mac,vendor,host,by_proto,...}], gateway_ip, subnet}
   getDestinations() returns the per-device aggregates for the constellation. */
(function () {
  "use strict";

  const GATEWAY_IP = "192.168.1.1";
  const SUBNET = "192.168.1.0/24";

  // A plausible household of devices (the gateway is the hub, not listed here).
  const DEVICES = [
    { ip: "192.168.1.37",  mac: "3c:07:54:a1:b2:c3", vendor: "Apple",        host: "macbook-pro.local", kind: "laptop", weight: 20, is_self: true },
    { ip: "192.168.1.42",  mac: "fc:a6:21:11:22:33", vendor: "Samsung",      host: "galaxy-s23.local",  kind: "phone",  weight: 16 },
    { ip: "192.168.1.51",  mac: "cc:b8:a8:44:55:66", vendor: "Roku",         host: "living-room-tv",    kind: "tv",     weight: 24 },
    { ip: "192.168.1.64",  mac: "b8:27:eb:77:88:99", vendor: "Raspberry Pi", host: "pi-hole.local",     kind: "server", weight: 9  },
    { ip: "192.168.1.70",  mac: "fc:65:de:ab:cd:ef", vendor: "Amazon",       host: "echo-dot",          kind: "iot",    weight: 7  },
    { ip: "192.168.1.88",  mac: "24:0a:c4:de:ad:be", vendor: "Espressif",    host: "esp32-sensor",      kind: "iot",    weight: 5  },
    { ip: "192.168.1.92",  mac: "5c:aa:fd:12:34:56", vendor: "Sonos",        host: "sonos-kitchen",     kind: "media",  weight: 11 },
    { ip: "192.168.1.101", mac: "00:15:5d:0a:0b:0c", vendor: "Microsoft",    host: "work-pc",           kind: "laptop", weight: 14 },
    { ip: "192.168.1.120", mac: "50:91:e3:0d:0e:0f", vendor: "TP-Link",      host: "smart-plug",        kind: "iot",    weight: 4  },
  ];

  const PEERS = {
    laptop: [["TCP", 443, "github.com"], ["TCP", 443, "api.openai.com"], ["UDP", 443, "rr3---googlevideo.com"], ["TCP", 443, "slack.com"]],
    phone:  [["TCP", 443, "fcm.googleapis.com"], ["UDP", 443, "instagram.com"], ["TCP", 443, "apple-cloudkit.com"]],
    tv:     [["UDP", 443, "nflxvideo.net"], ["TCP", 443, "api.netflix.com"], ["UDP", 443, "rr5---googlevideo.com"]],
    media:  [["UDP", 443, "audio-fa.scdn.co"], ["TCP", 443, "spclient.wg.spotify.com"]],
    iot:    [["TCP", 8883, "iot.amazonaws.com"], ["TCP", 443, "device-metrics.amazon.com"]],
    server: [["UDP", 53, GATEWAY_IP], ["TCP", 443, "raw.githubusercontent.com"]],
  };
  const QTYPES = ["A", "A", "AAAA", "PTR", "HTTPS"];

  function pick(a) { return a[(Math.random() * a.length) | 0]; }
  function weightedPick(items) {
    let t = 0; for (const i of items) t += i.weight;
    let r = Math.random() * t;
    for (const i of items) { r -= i.weight; if (r <= 0) return i; }
    return items[items.length - 1];
  }
  function sizeFor(proto, kind) {
    if (kind === "iot") return 60 + ((Math.random() * 180) | 0);
    if (proto === "UDP") return 200 + ((Math.random() * 1100) | 0);
    if (Math.random() < 0.3) return 40 + ((Math.random() * 24) | 0);
    return 240 + ((Math.random() * 1200) | 0);
  }

  function NetAgg(timelineSeconds) {
    this.total_packets = 0; this.total_bytes = 0; this.by_proto = {};
    this.dev = {}; this.timeline = []; this.timelineSeconds = timelineSeconds;
  }
  NetAgg.prototype.record = function (ip, proto, size, ts) {
    const sec = Math.floor(ts);
    this.total_packets++; this.total_bytes += size;
    this.by_proto[proto] = (this.by_proto[proto] || 0) + 1;
    let d = this.dev[ip];
    if (!d) { d = { packets: 0, bytes: 0, by_proto: {}, last: ts }; this.dev[ip] = d; }
    d.packets++; d.bytes += size; d.last = ts;
    d.by_proto[proto] = (d.by_proto[proto] || 0) + 1;
    const tl = this.timeline;
    if (tl.length && tl[tl.length - 1].t === sec) { tl[tl.length - 1].bytes += size; tl[tl.length - 1].packets += 1; }
    else { tl.push({ t: sec, bytes: size, packets: 1 }); while (tl.length > this.timelineSeconds) tl.shift(); }
  };
  NetAgg.prototype.devices = function () {
    return DEVICES.map((c) => {
      const d = this.dev[c.ip] || { packets: 0, bytes: 0, by_proto: {}, last: 0 };
      return {
        ip: c.ip, mac: c.mac, vendor: c.vendor, hostname: c.host, host: c.host,
        packets: d.packets, bytes: d.bytes, by_proto: Object.assign({}, d.by_proto),
        procs: {}, last: d.last, is_gateway: false, is_self: !!c.is_self,
      };
    });
  };
  NetAgg.prototype.snapshot = function () {
    const now = Math.floor(Date.now() / 1000);
    const devices = this.devices().sort((a, b) => b.bytes - a.bytes);
    const top = devices.slice(0, 15).map((d) => ({ ip: d.ip, host: d.host, packets: d.packets, bytes: d.bytes }));
    let throughput_bps = 0;
    for (let i = this.timeline.length - 1; i >= 0; i--) { if (this.timeline[i].t < now) { throughput_bps = this.timeline[i].bytes * 8; break; } }
    return {
      type: "stats", total_packets: this.total_packets, total_bytes: this.total_bytes,
      throughput_bps, by_proto: Object.assign({}, this.by_proto),
      top_destinations: top, timeline: this.timeline.slice(),
      devices, gateway_ip: GATEWAY_IP, subnet: SUBNET, device_count: devices.length,
    };
  };

  function create(opts) {
    opts = opts || {};
    const onPackets = opts.onPackets || function () {};
    const onDns = opts.onDns || function () {};
    const onStats = opts.onStats || function () {};
    const agg = new NetAgg(opts.timelineSeconds || 90);
    let rate = opts.rate != null ? opts.rate : 1;
    let packTimer = null, statTimer = null, running = false;

    function makePacket(now) {
      const c = weightedPick(DEVICES);
      const peerList = PEERS[c.kind] || PEERS.laptop;
      const [proto, port, peerHost] = pick(peerList);
      const size = sizeFor(proto, c.kind);
      return {
        ts: now, proto, src_ip: c.ip, src_port: 32768 + ((Math.random() * 28000) | 0),
        dst_ip: c.ip, dst_port: port, size, dst_host: c.host,
        flags: proto === "TCP" ? pick(["PA", "A", "PA", "S"]) : null, process: null,
        peer_ip: null, peer_host: peerHost,
      };
    }

    function tick() {
      const now = Date.now() / 1000;
      let n = 1 + ((Math.random() * 4) | 0);
      if (Math.random() < 0.12) n += 3 + ((Math.random() * 7) | 0);
      n = Math.max(0, Math.round(n * rate));
      const items = [];
      for (let i = 0; i < n; i++) { const p = makePacket(now + i * 0.001); agg.record(p.dst_ip, p.proto, p.size, p.ts); items.push(p); }
      if (items.length) onPackets(items);
      if (rate > 0 && Math.random() < 0.25) {
        const c = weightedPick(DEVICES);
        onDns([{ ts: now, query: Math.random() < 0.5 ? c.host : pick(["github.com", "netflix.com", "apple.com", "googleapis.com"]), qtype: pick(QTYPES) }]);
      }
    }

    return {
      start() {
        if (running) return; running = true;
        // prime some history so the map isn't empty
        const base = Date.now() / 1000;
        for (let s = (opts.timelineSeconds || 90); s > 0; s--) {
          const t = Math.floor(base) - s, burst = 2 + ((Math.random() * 6) | 0);
          for (let i = 0; i < burst; i++) { const p = makePacket(t); agg.record(p.dst_ip, p.proto, p.size, t); }
        }
        onStats(agg.snapshot());
        packTimer = setInterval(tick, 120);
        statTimer = setInterval(() => onStats(agg.snapshot()), 1000);
      },
      stop() { running = false; clearInterval(packTimer); clearInterval(statTimer); },
      setRate(r) { rate = r; }, getRate() { return rate; },
      snapshot() { return agg.snapshot(); },
      getDestinations() { return agg.devices(); },
      isRunning() { return running; },
    };
  }

  window.NetworkSim = { create, DEVICES, GATEWAY_IP, SUBNET };
})();
