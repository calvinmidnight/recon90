const $ = (id) => document.getElementById(id);
const setStatus = (msg) => $("status").textContent = msg;

async function api(path) {
  setStatus("Requesting " + path + " ...");
  const r = await fetch(path);
  setStatus("Done.");
  return r.json();
}

async function checkPortal() {
  const div = $("portal-result");
  div.textContent = "Probing connectivity endpoints...";
  const data = await api("/api/check/portal");
  div.innerHTML = "";
  data.findings.forEach(f => {
    const p = document.createElement("div");
    const cls = f.verdict && f.verdict.includes("PORTAL") ? "danger" : "ok";
    p.innerHTML = `<span class="badge ${cls}">${f.verdict || "?"}</span> ${f.probe}` +
                  (f.redirect ? ` → ${f.redirect}` : "");
    div.appendChild(p);
  });
}

function fillTable(tableId, rows, cols) {
  const tb = $(tableId).querySelector("tbody");
  tb.innerHTML = "";
  rows.forEach(r => {
    const tr = document.createElement("tr");
    cols.forEach(c => {
      const td = document.createElement("td");
      td.textContent = r[c] ?? "";
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
}

async function scanLan() {
  const data = await api("/api/scan/lan");
  if (!data.available) { setStatus(data.reason); return; }
  fillTable("lan-table", data.hosts, ["ip", "mac", "hostname"]);
  setStatus(`Found ${data.hosts.length} devices on ${data.subnet}`);
}

async function scanWireless() {
  const note = $("wireless-note");
  note.textContent = "Scanning for 30 seconds...";
  const data = await api("/api/scan/wireless");
  if (!data.available) {
    note.textContent = data.reason;
    return;
  }
  fillTable("wifi-table", data.networks, ["ssid", "bssid", "channel", "encryption", "power"]);
  note.textContent = `Found ${data.networks.length} networks via ${data.interface}`;
}