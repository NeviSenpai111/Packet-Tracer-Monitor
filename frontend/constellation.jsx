/* constellation.jsx — the hero star-map.
   Canvas: starfield, radar sweep, hub rings, links, packet particles, pulses.
   DOM: one positioned, clickable node per destination + the central hub.
   Exports <Constellation/> to window. */
const { useState: useStateC, useEffect: useEffectC, useRef: useRefC, useMemo: useMemoC } = React;

function buildLayout(dests, w, h, max) {
  const cx = w / 2, cy = h / 2;
  // sort by bytes desc, take top `max`
  const sorted = dests.slice().sort((a, b) => b.bytes - a.bytes).slice(0, max);
  const rings = [
    { frac: 0.50, cap: 6 },
    { frac: 0.80, cap: 8 },
    { frac: 1.0, cap: 99 },
  ];
  const rxBase = Math.max(60, w / 2 - 70);
  const ryBase = Math.max(60, h / 2 - 56);
  const maxBytes = Math.max(1, ...sorted.map((d) => d.bytes));
  const out = {};
  let idx = 0, ringI = 0, ringStart = 0;
  // assign into rings sequentially
  const ringMembers = [[], [], []];
  sorted.forEach((d, i) => {
    let r = 0, c = 0;
    for (let k = 0; k < rings.length; k++) { if (c + rings[k].cap > i) { r = k; ringStart = c; break; } c += rings[k].cap; }
    ringMembers[r].push(d);
  });
  ringMembers.forEach((members, r) => {
    const frac = rings[r].frac;
    const rx = rxBase * frac, ry = ryBase * frac;
    const baseRot = (r * 0.7) + 0.2;
    members.forEach((d, i) => {
      const a = baseRot + (i / members.length) * Math.PI * 2 + (hash01(d.ip) - 0.5) * 0.4;
      const x = cx + Math.cos(a) * rx;
      const y = cy + Math.sin(a) * ry;
      const proto = dominantProto(d.by_proto);
      const sizeT = Math.log10(d.bytes + 1) / Math.log10(maxBytes + 1);
      const radius = 7 + sizeT * 19;
      out[d.ip] = { x, y, r: radius, proto, color: PROTO_HEX[proto] || "#7c8aa5", host: d.host, ip: d.ip, bytes: d.bytes, a };
    });
  });
  return { nodes: out, cx, cy };
}

function Constellation({ destinations, lastBatch, selected, onSelect, accentHex, motion, hubIp, hubSub }) {
  const hubLabel = (hubIp || PacketSim.LOCAL_IP) + " · " + (hubSub || "this host");
  const wrapRef = useRefC(null);
  const canvasRef = useRefC(null);
  const [size, setSize] = useStateC({ w: 800, h: 600 });

  const layout = useMemoC(() => buildLayout(destinations, size.w, size.h, 16), [destinations, size.w, size.h]);

  // refs for the animation loop
  const layoutRef = useRefC(layout); layoutRef.current = layout;
  const particlesRef = useRefC([]);
  const pulsesRef = useRefC([]);
  const starsRef = useRefC([]);
  const activityRef = useRefC({});       // ip -> last activity timestamp (ms)
  const accentRef = useRefC(accentHex); accentRef.current = accentHex || "#35e3d4";
  const motionRef = useRefC(motion); motionRef.current = motion;
  const selRef = useRefC(selected); selRef.current = selected;

  // measure
  useEffectC(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const r = el.getBoundingClientRect();
      setSize({ w: Math.max(200, r.width), h: Math.max(200, r.height) });
    });
    ro.observe(el);
    const r = el.getBoundingClientRect();
    setSize({ w: Math.max(200, r.width), h: Math.max(200, r.height) });
    return () => ro.disconnect();
  }, []);

  // starfield (regenerate on size)
  useEffectC(() => {
    const n = Math.round((size.w * size.h) / 9000);
    const stars = [];
    for (let i = 0; i < n; i++) {
      stars.push({
        x: Math.random() * size.w, y: Math.random() * size.h,
        r: Math.random() * 1.3 + 0.2,
        tw: Math.random() * Math.PI * 2,
        sp: 0.4 + Math.random() * 1.2,
        dx: (Math.random() - 0.5) * 0.04, dy: (Math.random() - 0.5) * 0.04,
      });
    }
    starsRef.current = stars;
  }, [size.w, size.h]);

  // spawn particles + register activity when a new batch arrives
  useEffectC(() => {
    if (!lastBatch || !lastBatch.items) return;
    const L = layoutRef.current.nodes;
    const now = performance.now();
    let spawned = 0;
    for (const p of lastBatch.items) {
      activityRef.current[p.dst_ip] = Date.now() / 1000;
      const node = L[p.dst_ip];
      if (!node) continue;
      if (particlesRef.current.length > 140) break;
      if (spawned > 16) break;
      particlesRef.current.push({
        ip: p.dst_ip, t: 0,
        speed: 0.0016 + Math.random() * 0.0011,
        color: PROTO_HEX[p.proto] || "#7c8aa5",
        born: now, big: p.size > 800,
      });
      spawned++;
    }
  }, [lastBatch]);

  // main animation loop
  useEffectC(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let raf, last = performance.now();
    const dpr = Math.min(2, window.devicePixelRatio || 1);

    function resize() {
      canvas.width = size.w * dpr; canvas.height = size.h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    resize();

    function frame(now) {
      const dt = Math.min(50, now - last); last = now;
      const W = size.w, H = size.h;
      const lay = layoutRef.current;
      const cx = lay.cx, cy = lay.cy;
      const accent = accentRef.current;
      const mo = motionRef.current;
      ctx.clearRect(0, 0, W, H);

      // starfield
      const stars = starsRef.current;
      for (const s of stars) {
        s.tw += 0.02 * s.sp;
        s.x += s.dx; s.y += s.dy;
        if (s.x < 0) s.x += W; if (s.x > W) s.x -= W;
        if (s.y < 0) s.y += H; if (s.y > H) s.y -= H;
        const a = 0.25 + 0.55 * (0.5 + 0.5 * Math.sin(s.tw));
        ctx.globalAlpha = a;
        ctx.fillStyle = "#cdd9ff";
        ctx.beginPath(); ctx.arc(s.x, s.y, s.r, 0, 7); ctx.fill();
      }
      ctx.globalAlpha = 1;

      // radar sweep (subtle rotating wedge), skip if motion off
      if (mo !== "subtle") {
        const ang = (now / 5200) % (Math.PI * 2);
        const R = Math.max(W, H);
        const g = ctx.createConicGradient ? null : null;
        ctx.save();
        ctx.translate(cx, cy); ctx.rotate(ang);
        const grad = ctx.createLinearGradient(0, 0, R, 0);
        grad.addColorStop(0, hexA(accent, 0.10));
        grad.addColorStop(1, hexA(accent, 0));
        ctx.fillStyle = grad;
        ctx.beginPath(); ctx.moveTo(0, 0);
        ctx.arc(0, 0, R, -0.18, 0.02); ctx.closePath(); ctx.fill();
        ctx.restore();
      }

      // links hub -> nodes
      const nowS = Date.now() / 1000;
      const nodes = lay.nodes;
      for (const ip in nodes) {
        const nd = nodes[ip];
        const act = activityRef.current[ip] || 0;
        const recent = Math.max(0, 1 - (nowS - act) / 4); // 0..1
        const baseA = 0.05 + 0.22 * recent;
        const isSel = selRef.current && selRef.current.type === "dest" && selRef.current.ip === ip;
        ctx.strokeStyle = hexA(nd.color, isSel ? 0.5 : baseA);
        ctx.lineWidth = isSel ? 1.6 : 1;
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(nd.x, nd.y); ctx.stroke();
      }

      // pulses (expanding rings on nodes)
      const pulses = pulsesRef.current;
      for (let i = pulses.length - 1; i >= 0; i--) {
        const pl = pulses[i];
        pl.t += dt / (mo === "lively" ? 620 : 820);
        if (pl.t >= 1) { pulses.splice(i, 1); continue; }
        const nd = nodes[pl.ip]; if (!nd) { pulses.splice(i, 1); continue; }
        ctx.strokeStyle = hexA(pl.color, (1 - pl.t) * 0.7);
        ctx.lineWidth = 1.4;
        ctx.beginPath(); ctx.arc(nd.x, nd.y, nd.r + 2 + pl.t * 26, 0, 7); ctx.stroke();
      }

      // particles hub -> node
      const ps = particlesRef.current;
      for (let i = ps.length - 1; i >= 0; i--) {
        const p = ps[i];
        const nd = nodes[p.ip];
        if (!nd) { ps.splice(i, 1); continue; }
        p.t += p.speed * dt;
        if (p.t >= 1) {
          pulses.push({ ip: p.ip, t: 0, color: p.color });
          ps.splice(i, 1); continue;
        }
        const e = p.t * p.t * (3 - 2 * p.t); // smoothstep
        const x = cx + (nd.x - cx) * e;
        const y = cy + (nd.y - cy) * e;
        const rad = p.big ? 2.6 : 1.8;
        // trail
        const tx = cx + (nd.x - cx) * Math.max(0, e - 0.06);
        const ty = cy + (nd.y - cy) * Math.max(0, e - 0.06);
        const tg = ctx.createLinearGradient(tx, ty, x, y);
        tg.addColorStop(0, hexA(p.color, 0)); tg.addColorStop(1, hexA(p.color, 0.8));
        ctx.strokeStyle = tg; ctx.lineWidth = rad; ctx.lineCap = "round";
        ctx.beginPath(); ctx.moveTo(tx, ty); ctx.lineTo(x, y); ctx.stroke();
        ctx.fillStyle = "#fff"; ctx.globalAlpha = 0.95;
        ctx.beginPath(); ctx.arc(x, y, rad * 0.7, 0, 7); ctx.fill();
        ctx.globalAlpha = 1;
        ctx.shadowColor = p.color; ctx.shadowBlur = 8;
        ctx.fillStyle = p.color;
        ctx.beginPath(); ctx.arc(x, y, rad, 0, 7); ctx.fill();
        ctx.shadowBlur = 0;
      }

      // hub concentric rings + glow
      const t = now / 1000;
      for (let k = 0; k < 3; k++) {
        const rr = 16 + k * 11 + Math.sin(t * 1.3 + k) * 1.5;
        ctx.strokeStyle = hexA(accent, 0.28 - k * 0.07);
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(cx, cy, rr, 0, 7); ctx.stroke();
      }
      const hg = ctx.createRadialGradient(cx, cy, 0, cx, cy, 40);
      hg.addColorStop(0, hexA(accent, 0.55)); hg.addColorStop(1, hexA(accent, 0));
      ctx.fillStyle = hg;
      ctx.beginPath(); ctx.arc(cx, cy, 40, 0, 7); ctx.fill();
      ctx.fillStyle = "#eaf6ff";
      ctx.beginPath(); ctx.arc(cx, cy, 5.5, 0, 7); ctx.fill();
      // tick marks around hub
      ctx.strokeStyle = hexA(accent, 0.4); ctx.lineWidth = 1;
      for (let a = 0; a < Math.PI * 2; a += Math.PI / 6) {
        const r1 = 44, r2 = 49;
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(a) * r1, cy + Math.sin(a) * r1);
        ctx.lineTo(cx + Math.cos(a) * r2, cy + Math.sin(a) * r2);
        ctx.stroke();
      }

      raf = requestAnimationFrame(frame);
    }
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, [size.w, size.h]);

  const nodes = layout.nodes;
  const cx = layout.cx, cy = layout.cy;
  return (
    <div className="constellation" ref={wrapRef}>
      <canvas ref={canvasRef} />
      <div className="cst-hint">OUTBOUND · {Object.keys(nodes).length} HOSTS</div>
      {/* hub label */}
      <div className="node hub" style={{ left: cx, top: cy + 30 }} onClick={() => onSelect(null)}>
        <div className="lbl" style={{ opacity: 1 }}>{hubLabel}</div>
      </div>
      {Object.values(nodes).map((nd) => {
        const isSel = selected && selected.type === "dest" && selected.ip === nd.ip;
        return (
          <div key={nd.ip}
               className={"node" + (isSel ? " sel" : "")}
               style={{ left: nd.x, top: nd.y, "--c": nd.color }}
               onClick={(e) => { e.stopPropagation(); onSelect({ type: "dest", ip: nd.ip }); }}>
            <div className="orb" style={{ width: nd.r * 2, height: nd.r * 2 }}>
              <div className="ring" />
            </div>
            <div className="lbl">{nd.host || nd.ip}</div>
          </div>
        );
      })}
      <div className="cst-legend">
        <div className="lg"><span className="sw" style={{ background: PROTO_HEX.TCP }} />TCP</div>
        <div className="lg"><span className="sw" style={{ background: PROTO_HEX.UDP }} />UDP</div>
        <div className="lg"><span className="sw" style={{ background: PROTO_HEX.ICMP }} />ICMP</div>
        <div className="lg"><span className="sw" style={{ background: PROTO_HEX.ICMPv6 }} />ICMPv6</div>
      </div>
    </div>
  );
}

// hex (#rrggbb) + alpha -> rgba()
function hexA(hex, a) {
  hex = (hex || "#35e3d4").replace("#", "");
  if (hex.length === 3) hex = hex.split("").map((c) => c + c).join("");
  const r = parseInt(hex.slice(0, 2), 16), g = parseInt(hex.slice(2, 4), 16), b = parseInt(hex.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${a})`;
}

Object.assign(window, { Constellation, hexA });
