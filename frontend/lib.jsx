/* lib.jsx — shared formatters + small primitives. Exports to window. */
const { useState, useEffect, useRef, useMemo, useCallback } = React;

function fmtBytes(n) {
  if (n == null) return "—";
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}
function fmtBytesParts(n) {
  const s = fmtBytes(n).split(" ");
  return { num: s[0], unit: s[1] || "" };
}
function fmtBps(bps) {
  if (bps == null) return "—";
  if (bps < 1000) return bps + " bps";
  const u = ["Kbps", "Mbps", "Gbps"];
  let n = bps, i = -1;
  do { n /= 1000; i++; } while (n >= 1000 && i < u.length - 1);
  return n.toFixed(1) + " " + u[i];
}
function fmtBpsParts(bps) {
  const s = fmtBps(bps).split(" ");
  return { num: s[0], unit: s[1] || "" };
}
function fmtNum(n) { return (n || 0).toLocaleString("en-US"); }
function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("en-GB", { hour12: false }) + "." +
    String(d.getMilliseconds()).padStart(3, "0").slice(0, 3);
}

const PROTO_COLORS = {
  TCP: "var(--p-tcp)", UDP: "var(--p-udp)", ICMP: "var(--p-icmp)",
  ICMPv6: "var(--p-icmpv6)", OTHER: "var(--p-other)",
};
const PROTO_HEX = {
  TCP: "#2fd4e8", UDP: "#8b6cff", ICMP: "#ffb454", ICMPv6: "#ff5fd2", OTHER: "#7c8aa5",
};
function dominantProto(byProto) {
  let best = "OTHER", n = -1;
  for (const k in (byProto || {})) if (byProto[k] > n) { n = byProto[k]; best = k; }
  return best;
}
// stable pseudo-random in [0,1) from a string
function hash01(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
  return ((h >>> 0) % 100000) / 100000;
}

// Sparkline / area chart (SVG)
function Sparkline({ data, color, height = 40, fill = true, valueKey = "bytes" }) {
  const w = 300, h = height;
  if (!data || data.length < 2) return <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" />;
  const vals = data.map((d) => d[valueKey]);
  const max = Math.max(1, ...vals);
  const n = data.length;
  const x = (i) => (i / (n - 1)) * w;
  const y = (v) => h - 3 - (v / max) * (h - 6);
  let line = "";
  data.forEach((d, i) => { line += (i ? "L" : "M") + x(i).toFixed(1) + " " + y(d[valueKey]).toFixed(1) + " "; });
  const area = `M0 ${h} ` + data.map((d, i) => "L" + x(i).toFixed(1) + " " + y(d[valueKey]).toFixed(1)).join(" ") + ` L${w} ${h} Z`;
  const gid = "sg" + (color || "").replace(/[^a-z0-9]/gi, "");
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ display: "block" }}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.45" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <path d={area} fill={`url(#${gid})`} />}
      <path d={line} fill="none" stroke={color} strokeWidth="1.6" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

Object.assign(window, {
  fmtBytes, fmtBytesParts, fmtBps, fmtBpsParts, fmtNum, fmtTime,
  PROTO_COLORS, PROTO_HEX, dominantProto, hash01, Sparkline,
});
