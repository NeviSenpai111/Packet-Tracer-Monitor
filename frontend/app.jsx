/* app.jsx — composition + state. Mounts the whole dashboard. */
const { useState: useStateA, useEffect: useEffectA, useRef: useRefA, useCallback: useCallbackA } = React;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": "#35e3d4",
  "bgIntensity": 1,
  "density": "regular",
  "motion": "lively",
  "font": "sans",
  "captureRate": 1
}/*EDITMODE-END*/;

const ACCENTS = ["#35e3d4", "#5b8cff", "#8b6cff", "#ff5fd2", "#35e3a0"];
const MAX_PACKETS = 200;
const MAX_DNS = 60;

function BrandMark({ color }) {
  return (
    <svg className="mark" viewBox="0 0 40 40" fill="none">
      <circle cx="20" cy="20" r="17" stroke={color} strokeWidth="1" opacity="0.5" />
      <ellipse cx="20" cy="20" rx="17" ry="7" stroke={color} strokeWidth="1" opacity="0.35" transform="rotate(30 20 20)" />
      <ellipse cx="20" cy="20" rx="17" ry="7" stroke={color} strokeWidth="1" opacity="0.35" transform="rotate(-30 20 20)" />
      <circle cx="20" cy="20" r="3.4" fill={color} />
      <circle cx="33" cy="13" r="1.8" fill={color} />
      <circle cx="8" cy="27" r="1.4" fill={color} opacity="0.8" />
    </svg>
  );
}

function Metric({ k, num, unit, accent }) {
  return (
    <div className="metric">
      <span className="k">{k}</span>
      <span className="v">{num}{unit ? <small> {unit}</small> : null}</span>
    </div>
  );
}

function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);

  const [packets, setPackets] = useStateA([]);
  const [dns, setDns] = useStateA([]);
  const [stats, setStats] = useStateA({ total_packets: 0, total_bytes: 0, throughput_bps: 0, by_proto: {}, top_destinations: [], timeline: [] });
  const [destinations, setDestinations] = useStateA([]);
  const [lastBatch, setLastBatch] = useStateA(null);
  const [newIds, setNewIds] = useStateA(() => new Set());
  const [newDnsIds, setNewDnsIds] = useStateA(() => new Set());
  const [selected, setSelected] = useStateA(null);
  const [paused, setPaused] = useStateA(false);

  const idRef = useRefA(0);
  const simRef = useRefA(null);
  const batchN = useRefA(0);

  // boot the live data source (real backend WebSocket, with simulator fallback)
  useEffectA(() => {
    const sim = DataSource.create({
      timelineSeconds: 90, topN: 8,
      onPackets: (items) => {
        const stamped = items.map((p) => ({ ...p, _id: ++idRef.current }));
        setPackets((prev) => {
          const next = stamped.slice().reverse().concat(prev);
          return next.length > MAX_PACKETS ? next.slice(0, MAX_PACKETS) : next;
        });
        setNewIds(new Set(stamped.map((p) => p._id)));
        batchN.current++;
        setLastBatch({ items: stamped, n: batchN.current });
      },
      onDns: (items) => {
        const stamped = items.map((d) => ({ ...d, _id: ++idRef.current }));
        setDns((prev) => {
          const next = stamped.concat(prev);
          return next.length > MAX_DNS ? next.slice(0, MAX_DNS) : next;
        });
        setNewDnsIds(new Set(stamped.map((d) => d._id)));
      },
      onStats: (s) => {
        setStats(s);
        setDestinations(simRef.current ? simRef.current.getDestinations() : []);
      },
    });
    simRef.current = sim;
    sim.setRate(t.captureRate);
    sim.start();
    return () => sim.stop();
  }, []);

  // pause / rate
  useEffectA(() => { if (simRef.current) simRef.current.setRate(paused ? 0 : t.captureRate); }, [t.captureRate, paused]);

  // esc closes inspector
  useEffectA(() => {
    const onKey = (e) => { if (e.key === "Escape") setSelected(null); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const selectDest = useCallbackA((ip) => setSelected({ type: "dest", ip }), []);
  const accent = t.accent || "#35e3d4";

  const tb = fmtBytesParts(stats.total_bytes);
  const th = fmtBpsParts(stats.throughput_bps);

  return (
    <div className="pt-root"
         data-density={t.density}
         data-font={t.font === "sans" ? null : t.font}
         data-motion={t.motion}
         style={{ "--accent": accent, "--bg-intensity": t.bgIntensity }}>
      <div className="pt-bg"><div className="pt-grid" /></div>

      <div className="pt-shell">
        {/* top bar */}
        <div className="pt-topbar">
          <div className="brand">
            <BrandMark color={accent} />
            <div className="ttl">
              <b>PACKET TRACER</b>
              <span>outbound traffic monitor</span>
            </div>
          </div>
          <div className={"status" + (paused ? " off" : "")} onClick={() => setPaused((p) => !p)} style={{ cursor: "pointer", marginLeft: 22 }} title="Toggle capture">
            <span className="dot" />
            {paused ? "PAUSED" : "CAPTURING"}
          </div>
          <div className="metrics">
            <Metric k="Packets" num={fmtNum(stats.total_packets)} />
            <Metric k="Data" num={tb.num} unit={tb.unit} />
            <Metric k="Throughput" num={th.num} unit={th.unit} />
            <Metric k="Hosts" num={fmtNum(destinations.length)} />
          </div>
        </div>

        {/* main grid */}
        <div className="pt-main">
          <div className="pt-col">
            <PacketStream packets={packets.slice(0, 140)} onSelectDest={selectDest} newIds={newIds} />
          </div>

          <div className="pt-col">
            <div className="panel" style={{ flex: 1, minHeight: 0 }}>
              <div className="panel-hd">
                <span className="hd-accent" />
                <h2>Constellation</h2>
                <span className="hd-meta">live · {PacketSim.LOCAL_IP}</span>
              </div>
              <Constellation
                destinations={destinations}
                lastBatch={lastBatch}
                selected={selected}
                onSelect={setSelected}
                accentHex={accent}
                motion={t.motion} />
            </div>
            <TimelineStrip stats={stats} accentHex={accent} />
          </div>

          <div className="pt-col">
            <TopDestinations stats={stats} onSelectDest={selectDest} selected={selected} />
            <ProtocolMix stats={stats} />
            <DnsFeed dns={dns} newIds={newDnsIds} />
          </div>
        </div>
      </div>

      {/* inspector overlay */}
      <Inspector selected={selected} destinations={destinations} packets={packets}
                 onSelect={setSelected} onClose={() => setSelected(null)} />

      {/* tweaks */}
      <TweaksPanel>
        <TweakSection label="Appearance" />
        <TweakColor label="Accent" value={t.accent} options={ACCENTS} onChange={(v) => setTweak("accent", v)} />
        <TweakRadio label="Font" value={t.font} options={["sans", "mono", "hud"]} onChange={(v) => setTweak("font", v)} />
        <TweakRadio label="Density" value={t.density} options={["compact", "regular", "comfy"]} onChange={(v) => setTweak("density", v)} />
        <TweakSlider label="Background glow" value={t.bgIntensity} min={0} max={1.4} step={0.1} onChange={(v) => setTweak("bgIntensity", v)} />
        <TweakSection label="Motion & capture" />
        <TweakRadio label="Motion" value={t.motion} options={["subtle", "lively"]} onChange={(v) => setTweak("motion", v)} />
        <TweakSlider label="Capture rate" value={t.captureRate} min={0.2} max={3} step={0.1} unit="×" onChange={(v) => setTweak("captureRate", v)} />
      </TweaksPanel>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
