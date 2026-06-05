/* network-app.jsx — composition for the NETWORK view. Reuses the same
   constellation / panels / inspector components as the host view, but the nodes
   are LAN devices, the hub is the gateway, and data comes from /ws/network
   (NetworkDataSource, with NetworkSim fallback). */
const { useState: useStateN, useEffect: useEffectN, useRef: useRefN, useCallback: useCallbackN } = React;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": "#5b8cff",
  "bgIntensity": 1,
  "density": "regular",
  "motion": "lively",
  "font": "sans",
  "captureRate": 1
}/*EDITMODE-END*/;

const ACCENTS = ["#5b8cff", "#35e3d4", "#8b6cff", "#ff5fd2", "#35e3a0"];
const MAX_PACKETS = 200;
const MAX_DNS = 60;

function BrandMark({ color }) {
  return (
    <svg className="mark" viewBox="0 0 40 40" fill="none">
      <circle cx="20" cy="20" r="17" stroke={color} strokeWidth="1" opacity="0.5" />
      <circle cx="20" cy="20" r="9" stroke={color} strokeWidth="1" opacity="0.4" />
      <circle cx="20" cy="20" r="3" fill={color} />
      <circle cx="20" cy="3.4" r="1.8" fill={color} />
      <circle cx="36.6" cy="20" r="1.8" fill={color} />
      <circle cx="20" cy="36.6" r="1.8" fill={color} />
      <circle cx="3.4" cy="20" r="1.8" fill={color} />
    </svg>
  );
}

function Metric({ k, num, unit }) {
  return (
    <div className="metric">
      <span className="k">{k}</span>
      <span className="v">{num}{unit ? <small> {unit}</small> : null}</span>
    </div>
  );
}

function NetworkApp() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);

  const [packets, setPackets] = useStateN([]);
  const [dns, setDns] = useStateN([]);
  const [stats, setStats] = useStateN({ total_packets: 0, total_bytes: 0, throughput_bps: 0, by_proto: {}, top_destinations: [], timeline: [] });
  const [destinations, setDestinations] = useStateN([]);
  const [netInfo, setNetInfo] = useStateN({ gateway_ip: null, subnet: null, mitm: false });
  const [lastBatch, setLastBatch] = useStateN(null);
  const [newIds, setNewIds] = useStateN(() => new Set());
  const [newDnsIds, setNewDnsIds] = useStateN(() => new Set());
  const [selected, setSelected] = useStateN(null);
  const [paused, setPaused] = useStateN(false);

  const idRef = useRefN(0);
  const simRef = useRefN(null);
  const batchN = useRefN(0);

  useEffectN(() => {
    const src = NetworkDataSource.create({
      timelineSeconds: 90,
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
        if (s.gateway_ip !== undefined) setNetInfo({ gateway_ip: s.gateway_ip, subnet: s.subnet, mitm: !!s.mitm });
        setDestinations(simRef.current ? simRef.current.getDestinations() : []);
      },
    });
    simRef.current = src;
    src.setRate(t.captureRate);
    src.start();
    return () => src.stop();
  }, []);

  useEffectN(() => { if (simRef.current) simRef.current.setRate(paused ? 0 : t.captureRate); }, [t.captureRate, paused]);

  useEffectN(() => {
    const onKey = (e) => { if (e.key === "Escape") setSelected(null); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const selectDest = useCallbackN((ip) => setSelected({ type: "dest", ip }), []);
  const accent = t.accent || "#5b8cff";
  const tb = fmtBytesParts(stats.total_bytes);
  const th = fmtBpsParts(stats.throughput_bps);
  const hubIp = netInfo.gateway_ip || "LAN";

  return (
    <div className="pt-root"
         data-density={t.density}
         data-font={t.font === "sans" ? null : t.font}
         data-motion={t.motion}
         style={{ "--accent": accent, "--bg-intensity": t.bgIntensity }}>
      <div className="pt-bg"><div className="pt-grid" /></div>

      <div className="pt-shell">
        <div className="pt-topbar">
          <div className="brand">
            <BrandMark color={accent} />
            <div className="ttl">
              <b>NETWORK MONITOR</b>
              <span>LAN device &amp; traffic map</span>
            </div>
          </div>
          <div className={"status" + (paused ? " off" : "")} onClick={() => setPaused((p) => !p)} style={{ cursor: "pointer", marginLeft: 22 }} title="Toggle capture">
            <span className="dot" />
            {paused ? "PAUSED" : "MONITORING"}
          </div>
          <a href="/" className="pt-pagelink" title="Switch to system monitor">↞ SYSTEM</a>
          <div className="metrics">
            <Metric k="Packets" num={fmtNum(stats.total_packets)} />
            <Metric k="Data" num={tb.num} unit={tb.unit} />
            <Metric k="Throughput" num={th.num} unit={th.unit} />
            <Metric k="Devices" num={fmtNum(destinations.length)} />
          </div>
        </div>

        <div className="pt-main">
          <div className="pt-col">
            <PacketStream packets={packets.slice(0, 140)} onSelectDest={selectDest} newIds={newIds} />
          </div>

          <div className="pt-col">
            <div className="panel" style={{ flex: 1, minHeight: 0 }}>
              <div className="panel-hd">
                <span className="hd-accent" />
                <h2>Network Map</h2>
                <span className="hd-meta">
                  live · {netInfo.subnet || "discovering…"}
                  {netInfo.mitm ? <span className="hd-intercept"> · intercepting</span> : null}
                </span>
              </div>
              <Constellation
                destinations={destinations}
                lastBatch={lastBatch}
                selected={selected}
                onSelect={setSelected}
                accentHex={accent}
                motion={t.motion}
                hubIp={hubIp}
                hubSub="gateway" />
            </div>
            <TimelineStrip stats={stats} accentHex={accent} />
          </div>

          <div className="pt-col">
            <TopDestinations stats={stats} onSelectDest={selectDest} selected={selected} title="Devices" />
            <ProtocolMix stats={stats} />
            <DnsFeed dns={dns} newIds={newDnsIds} />
          </div>
        </div>
      </div>

      <Inspector selected={selected} destinations={destinations} packets={packets}
                 destKind="Device"
                 onSelect={setSelected} onClose={() => setSelected(null)} />

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

ReactDOM.createRoot(document.getElementById("root")).render(<NetworkApp />);
