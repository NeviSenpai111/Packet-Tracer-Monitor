/* panels.jsx — Panel shell + all side panels. Exports to window. */
const { useState: useStateP, useRef: useRefP, useEffect: useEffectP } = React;

function Panel({ title, meta, accentDot = true, children, bodyClass = "", noBody = false }) {
  return (
    <div className="panel">
      <div className="panel-hd">
        {accentDot && <span className="hd-accent" />}
        <h2>{title}</h2>
        {meta != null && <span className="hd-meta">{meta}</span>}
      </div>
      {noBody ? children : <div className={"panel-bd " + bodyClass}>{children}</div>}
    </div>
  );
}

/* ---------- live packet stream ---------- */
function PacketStream({ packets, onSelectDest, onSelectProc, newIds }) {
  return (
    <Panel title="Live Packets" meta={`${packets.length} shown`} bodyClass="stream">
      {packets.length === 0 && <div className="empty">awaiting capture…</div>}
      {/* render oldest->newest so new rows are APPENDED (never reordered) —
          column-reverse flips it visually so newest sits on top */}
      {packets.slice().reverse().map((p) => (
        <div className={"stream-row" + (newIds && newIds.has(p._id) ? " is-new" : "")} key={p._id}
             onClick={() => onSelectDest(p.dst_ip)}>
          <span className="t">{fmtTime(p.ts).slice(0, 12)}</span>
          <span className={"proto-tag proto-" + p.proto}>{p.proto}</span>
          <span className="dst">
            {p.dst_host ? <span className="h">{p.dst_host}</span> : <span className="h">{p.dst_ip}</span>}
            {p.dst_port != null && <span className="ip"> :{p.dst_port}</span>}
          </span>
          <span className="sz">{fmtBytes(p.size)}</span>
        </div>
      ))}
    </Panel>
  );
}

/* ---------- top destinations ---------- */
function TopDestinations({ stats, onSelectDest, selected, title }) {
  const top = (stats.top_destinations || []);
  const max = Math.max(1, ...top.map((d) => d.bytes));
  return (
    <Panel title={title || "Top Destinations"} meta={top.length ? "by volume" : ""}>
      {top.length === 0 && <div className="empty">no traffic yet</div>}
      {top.map((d, i) => {
        const name = d.host || d.ip;
        const isSel = selected && selected.type === "dest" && selected.ip === d.ip;
        return (
          <div className="li" key={d.ip} onClick={() => onSelectDest(d.ip)}
               style={isSel ? { background: "rgba(124,160,255,0.08)" } : null}>
            <span className="rank">{String(i + 1).padStart(2, "0")}</span>
            <div className="body">
              <div className="h">{name}</div>
              <div className="sub">{d.host ? d.ip + " · " : ""}{fmtNum(d.packets)} pkts</div>
              <div className="bar" style={{ width: (8 + (d.bytes / max) * 92) + "%" }} />
            </div>
            <span className="val">{fmtBytes(d.bytes)}</span>
          </div>
        );
      })}
    </Panel>
  );
}

/* ---------- protocol mix donut ---------- */
function ProtocolMix({ stats }) {
  const by = stats.by_proto || {};
  const entries = Object.keys(by).map((k) => ({ k, v: by[k] })).sort((a, b) => b.v - a.v);
  const total = entries.reduce((s, e) => s + e.v, 0) || 1;
  const R = 34, SW = 11, C = 2 * Math.PI * R;
  let acc = 0;
  return (
    <Panel title="Protocol Mix" meta={fmtNum(total) + " pkts"}>
      <div className="mix">
        <svg width="92" height="92" viewBox="0 0 92 92" style={{ flex: "none" }}>
          <circle cx="46" cy="46" r={R} fill="none" stroke="rgba(124,160,255,0.10)" strokeWidth={SW} />
          {entries.map((e) => {
            const frac = e.v / total;
            const dash = frac * C;
            const seg = (
              <circle key={e.k} cx="46" cy="46" r={R} fill="none"
                      stroke={PROTO_HEX[e.k] || "#7c8aa5"} strokeWidth={SW}
                      strokeDasharray={`${dash} ${C - dash}`}
                      strokeDashoffset={-acc * C}
                      transform="rotate(-90 46 46)"
                      strokeLinecap="butt"
                      style={{ filter: "drop-shadow(0 0 4px " + (PROTO_HEX[e.k] || "#7c8aa5") + "66)" }} />
            );
            acc += frac;
            return seg;
          })}
          <text x="46" y="43" textAnchor="middle" fontFamily="var(--font-mono)" fontSize="14" fontWeight="600" fill="var(--tx)">{entries.length}</text>
          <text x="46" y="56" textAnchor="middle" fontFamily="var(--font-mono)" fontSize="7.5" letterSpacing="1.5" fill="var(--tx-dim)">PROTO</text>
        </svg>
        <div className="legend">
          {entries.length === 0 && <div className="empty" style={{ padding: 0 }}>—</div>}
          {entries.map((e) => (
            <div className="leg" key={e.k}>
              <span className="sw" style={{ background: PROTO_HEX[e.k] || "#7c8aa5", boxShadow: "0 0 6px " + (PROTO_HEX[e.k] || "#7c8aa5") }} />
              <span className="nm">{e.k}</span>
              <span className="ct">{fmtNum(e.v)} · {Math.round((e.v / total) * 100)}%</span>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}

/* ---------- DNS feed ---------- */
function DnsFeed({ dns, newIds }) {
  return (
    <Panel title="DNS Queries" meta={dns.length ? "live" : ""} bodyClass="dns-list">
      {dns.length === 0 && <div className="empty">no lookups yet</div>}
      {dns.slice().reverse().map((d) => (
        <div className={"dns-li" + (newIds && newIds.has(d._id) ? " is-new" : "")} key={d._id}>
          <span className="qt">{d.qtype}</span>
          <span className="q">{d.query}</span>
          <span className="t" style={{ fontFamily: "var(--font-mono)", fontSize: 9.5, color: "var(--tx-dim)" }}>{fmtTime(d.ts).slice(0, 8)}</span>
        </div>
      ))}
    </Panel>
  );
}

/* ---------- throughput timeline ---------- */
function TimelineStrip({ stats, accentHex }) {
  const tl = stats.timeline || [];
  const cur = stats.throughput_bps || 0;
  const peak = Math.max(0, ...tl.map((d) => d.bytes)) * 8;
  return (
    <Panel title="Throughput" meta={"peak " + fmtBps(peak)}>
      <div className="timeline-strip">
        <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 6 }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 600, color: accentHex || "var(--accent)" }} className="tnum">{fmtBpsParts(cur).num}</span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--tx-mut)" }}>{fmtBpsParts(cur).unit}</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--tx-dim)" }}>last {tl.length}s</span>
        </div>
        <Sparkline data={tl} color={accentHex || "#35e3d4"} height={48} valueKey="bytes" />
      </div>
    </Panel>
  );
}

Object.assign(window, { Panel, PacketStream, TopDestinations, ProtocolMix, DnsFeed, TimelineStrip });
