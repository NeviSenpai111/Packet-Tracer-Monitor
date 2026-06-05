// Placeholder dashboard client. Consumes the WebSocket/REST contract documented
// in README.md. The real UI will be built later with the Claude Design product.

const MAX_ROWS = 300;
const $ = (id) => document.getElementById(id);

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + " " + u[i];
}

function fmtBps(bps) {
  if (bps < 1000) return bps + " bps";
  const u = ["Kbps", "Mbps", "Gbps"];
  let n = bps, i = -1;
  do { n /= 1000; i++; } while (n >= 1000 && i < u.length - 1);
  return n.toFixed(1) + " " + u[i];
}

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("en-GB") + "." + String(d.getMilliseconds()).padStart(3, "0");
}

function addPacketRow(p) {
  const tbody = $("packets").querySelector("tbody");
  const tr = document.createElement("tr");
  const dst = p.dst_host
    ? `<span class="host">${p.dst_host}</span> <span class="muted">${p.dst_ip}</span>`
    : p.dst_ip;
  const proc = p.process ? `${p.process.name} <span class="muted">(${p.process.pid})</span>` : "—";
  tr.innerHTML =
    `<td>${fmtTime(p.ts)}</td>` +
    `<td class="proto ${p.proto}">${p.proto}</td>` +
    `<td>${dst}</td>` +
    `<td>${p.dst_port ?? ""}</td>` +
    `<td>${fmtBytes(p.size)}</td>` +
    `<td>${proc}</td>`;
  tbody.prepend(tr);
  while (tbody.children.length > MAX_ROWS) tbody.removeChild(tbody.lastChild);
}

function addDns(items) {
  const ul = $("dns");
  for (const d of items) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="host">${d.query}</span><span class="meta">${d.qtype}</span>`;
    ul.prepend(li);
  }
  while (ul.children.length > 50) ul.removeChild(ul.lastChild);
}

function renderStats(s) {
  $("m-packets").textContent = s.total_packets.toLocaleString();
  $("m-bytes").textContent = fmtBytes(s.total_bytes);
  $("m-throughput").textContent = fmtBps(s.throughput_bps);
  $("m-proto").textContent =
    Object.entries(s.by_proto).map(([k, v]) => `${k}: ${v}`).join("  ") || "—";

  const ul = $("top-dst");
  ul.innerHTML = "";
  for (const d of s.top_destinations) {
    const li = document.createElement("li");
    const name = d.host || d.ip;
    li.innerHTML = `<span class="host">${name}</span><span class="meta">${fmtBytes(d.bytes)}</span>`;
    ul.appendChild(li);
  }
}

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  const status = $("status");

  ws.onopen = () => { status.textContent = "connected"; status.className = "status connected"; };
  ws.onclose = () => {
    status.textContent = "disconnected — retrying"; status.className = "status disconnected";
    setTimeout(connect, 1500);
  };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    switch (msg.type) {
      case "snapshot":
        if (msg.stats) renderStats(msg.stats);
        (msg.recent_packets || []).slice().reverse().forEach(addPacketRow);
        break;
      case "packets":
        msg.items.forEach(addPacketRow);
        break;
      case "dns":
        addDns(msg.items);
        break;
      case "stats":
        renderStats(msg);
        break;
    }
  };
}

connect();
