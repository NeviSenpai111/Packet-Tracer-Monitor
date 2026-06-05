/* inspector.jsx — drill-down drawer for a selected destination or process.
   Exports <Inspector/> to window. */
const { useMemo: useMemoI } = React;

function StatBox({ k, v, sub }) {
  return (
    <div className="insp-stat">
      <div className="k">{k}</div>
      <div className="v tnum">{v}</div>
      {sub && <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--tx-dim)", marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function ProtoChips({ byProto }) {
  const entries = Object.keys(byProto || {}).map((k) => ({ k, v: byProto[k] })).sort((a, b) => b.v - a.v);
  const total = entries.reduce((s, e) => s + e.v, 0) || 1;
  if (!entries.length) return null;
  return (
    <div className="insp-sec">
      <div className="lab">Protocol breakdown</div>
      <div style={{ display: "flex", height: 8, borderRadius: 5, overflow: "hidden", marginBottom: 10, border: "1px solid var(--line)" }}>
        {entries.map((e) => (
          <div key={e.k} title={e.k} style={{ width: (e.v / total * 100) + "%", background: PROTO_HEX[e.k], boxShadow: "0 0 8px " + PROTO_HEX[e.k] }} />
        ))}
      </div>
      <div>
        {entries.map((e) => (
          <span className="chip" key={e.k} style={{ borderColor: PROTO_HEX[e.k] + "66" }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: PROTO_HEX[e.k] }} />
            {e.k} <span className="ct">{fmtNum(e.v)}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function RecentTo({ packets, label }) {
  return (
    <div className="insp-sec">
      <div className="lab">{label} <span style={{ color: "var(--tx-dim)" }}>· {packets.length}</span></div>
      <div style={{ border: "1px solid var(--line)", borderRadius: 10, overflow: "hidden" }}>
        {packets.length === 0 && <div className="empty" style={{ padding: 18 }}>none captured recently</div>}
        {packets.slice(0, 60).map((p) => (
          <div className="stream-row" key={p._id} style={{ cursor: "default", gridTemplateColumns: "70px 40px 1fr auto" }}>
            <span className="t">{fmtTime(p.ts).slice(0, 12)}</span>
            <span className={"proto-tag proto-" + p.proto}>{p.proto}</span>
            <span className="dst"><span className="ip">{p.flags ? "[" + p.flags + "] " : ""}:{p.dst_port}</span></span>
            <span className="sz">{fmtBytes(p.size)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DestInspector({ ip, destinations, packets, onSelectProc, destKind }) {
  const d = useMemoI(() => destinations.find((x) => x.ip === ip), [destinations, ip]);
  const recent = useMemoI(() => packets.filter((p) => p.dst_ip === ip), [packets, ip]);
  const kind = destKind || "Destination";
  if (!d) return <div className="empty">{kind.toLowerCase()} no longer active</div>;
  const proto = dominantProto(d.by_proto);
  const procs = Object.keys(d.procs || {}).map((n) => ({ n, v: d.procs[n] })).sort((a, b) => b.v - a.v);
  const avg = d.packets ? Math.round(d.bytes / d.packets) : 0;
  const isDevice = kind === "Device";
  return (
    <>
      <div className="insp-hd">
        <div className="ico" style={{ borderColor: PROTO_HEX[proto] + "66" }}>
          <span style={{ width: 18, height: 18, borderRadius: "50%", background: "radial-gradient(circle at 35% 30%, #fff, " + PROTO_HEX[proto] + ")", boxShadow: "0 0 12px " + PROTO_HEX[proto] }} />
        </div>
        <div className="ttl">
          <div className="kind">{kind}{d.is_gateway ? " · gateway" : ""} · {proto}</div>
          <h3>{d.host || d.ip}</h3>
          <div className="ip">{d.ip}{d.mac ? " · " + d.mac : ""}</div>
        </div>
      </div>
      <div className="insp-bd">
        <div className="insp-stats">
          <StatBox k="Bytes" v={fmtBytes(d.bytes)} />
          <StatBox k="Packets" v={fmtNum(d.packets)} />
          <StatBox k="Avg size" v={avg + " B"} />
          <StatBox k="Share" v={pctOfTotal(destinations, d.bytes) + "%"} sub="of all bytes" />
        </div>
        <ProtoChips byProto={d.by_proto} />
        {isDevice ? (
          <div className="insp-sec">
            <div className="lab">Device</div>
            <span className="chip">vendor <span className="ct">{d.vendor || "unknown"}</span></span>
            <span className="chip">mac <span className="ct">{d.mac || "—"}</span></span>
            {d.is_self && <span className="chip">this machine</span>}
            {d.is_gateway && <span className="chip">gateway / router</span>}
          </div>
        ) : (
          <div className="insp-sec">
            <div className="lab">Attributed processes</div>
            {procs.length === 0 && <div className="empty" style={{ padding: 0, textAlign: "left" }}>unattributed</div>}
            {procs.map((p) => (
              <span className="chip" key={p.n} onClick={() => onSelectProc(p.n)}>
                {p.n} <span className="ct">{fmtNum(p.v)} pkts</span>
              </span>
            ))}
          </div>
        )}
        <RecentTo packets={recent} label={isDevice ? "Recent activity" : "Recent packets"} />
      </div>
    </>
  );
}

function ProcInspector({ name, destinations, packets, onSelectDest }) {
  const touched = useMemoI(() => {
    const rows = [];
    let bytes = 0, packetsN = 0;
    const byProto = {};
    for (const d of destinations) {
      const c = (d.procs || {})[name];
      if (!c) continue;
      const frac = d.packets ? c / d.packets : 0;
      const eb = Math.round(d.bytes * frac);
      bytes += eb; packetsN += c;
      for (const pr in d.by_proto) byProto[pr] = (byProto[pr] || 0) + Math.round(d.by_proto[pr] * frac);
      rows.push({ ip: d.ip, host: d.host, bytes: eb, packets: c });
    }
    rows.sort((a, b) => b.bytes - a.bytes);
    return { rows, bytes, packets: packetsN, byProto };
  }, [destinations, name]);
  const recent = useMemoI(() => packets.filter((p) => p.process && p.process.name === name), [packets, name]);
  const pid = recent.length ? recent[0].process.pid : "—";
  return (
    <>
      <div className="insp-hd">
        <div className="ico" style={{ borderColor: "var(--accent-2)" }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-2)" strokeWidth="1.6">
            <rect x="4" y="4" width="16" height="16" rx="3" /><path d="M9 9h6v6H9z" /><path d="M12 1v3M12 20v3M1 12h3M20 12h3" />
          </svg>
        </div>
        <div className="ttl">
          <div className="kind">Process</div>
          <h3>{name}</h3>
          <div className="ip">pid {pid}</div>
        </div>
      </div>
      <div className="insp-bd">
        <div className="insp-stats">
          <StatBox k="Est. bytes" v={fmtBytes(touched.bytes)} />
          <StatBox k="Packets" v={fmtNum(touched.packets)} />
          <StatBox k="Destinations" v={fmtNum(touched.rows.length)} />
          <StatBox k="Protocols" v={fmtNum(Object.keys(touched.byProto).length)} />
        </div>
        <ProtoChips byProto={touched.byProto} />
        <div className="insp-sec">
          <div className="lab">Talks to</div>
          {touched.rows.map((r) => (
            <div className="li" key={r.ip} style={{ padding: "8px 0", borderColor: "var(--line)" }} onClick={() => onSelectDest(r.ip)}>
              <div className="body">
                <div className="h">{r.host || r.ip}</div>
                <div className="sub">{fmtNum(r.packets)} pkts</div>
              </div>
              <span className="val">{fmtBytes(r.bytes)}</span>
            </div>
          ))}
        </div>
        <RecentTo packets={recent} label="Recent packets" />
      </div>
    </>
  );
}

function pctOfTotal(destinations, bytes) {
  const total = destinations.reduce((s, d) => s + d.bytes, 0) || 1;
  return Math.round((bytes / total) * 100);
}

function Inspector({ selected, destinations, packets, onSelect, onClose, destKind }) {
  if (!selected) return null;
  return (
    <div className="inspector">
      <button className="insp-close" onClick={onClose} title="Close (Esc)">×</button>
      {selected.type === "dest"
        ? <DestInspector ip={selected.ip} destinations={destinations} packets={packets}
                         destKind={destKind}
                         onSelectProc={(n) => onSelect({ type: "proc", name: n })} />
        : <ProcInspector name={selected.name} destinations={destinations} packets={packets}
                         onSelectDest={(ip) => onSelect({ type: "dest", ip })} />}
    </div>
  );
}

Object.assign(window, { Inspector });
