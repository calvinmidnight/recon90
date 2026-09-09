#!/usr/bin/env python3
"""
Wi-Fi Recon Suite — ALL-IN-ONE FILE
Single file containing: Python backend (Flask), embedded HTML/CSS/JS dashboard,
and C++ LAN sweep helper (auto-compiled at runtime).

Platforms:
  Linux/Kali : full functionality (wireless scan via monitor mode, LAN, portal)
  Termux     : portal + LAN scans (Android blocks monitor mode on built-in Wi-Fi)

Run:
  pip install flask
  sudo python3 wifi_recon_suite.py     # sudo enables monitor mode on Linux
  open http://127.0.0.1:5000
"""

import os
import re
import sys
import shutil
import socket
import struct
import fcntl
import time
import ipaddress
import subprocess
import tempfile
import threading

from flask import Flask, jsonify, send_from_directory, Response

APP_DIR = os.path.dirname(os.path.abspath(__file__))
NATIVE_BIN = os.path.join(APP_DIR, "arpsweep")
CPP_SOURCE = r"""
// Fast parallel ARP/ping sweep of a /24 subnet.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>
#include <arpa/inet.h>
#include <unistd.h>

static std::mutex mtx;
static std::vector<std::string> results;

void probe(const std::string& ip) {
    std::string cmd = "ping -c1 -W1 " + ip + " >/dev/null 2>&1";
    if (system(cmd.c_str()) == 0) {
        std::ifstream arp("/proc/net/arp");
        std::string line;
        std::getline(arp, line);
        while (std::getline(arp, line)) {
            std::istringstream ss(line);
            std::string a, hw, mac;
            ss >> a >> hw;
            if (a == ip) {
                ss >> hw >> hw >> mac;
                std::lock_guard<std::mutex> lk(mtx);
                results.push_back(ip + " " + mac);
                return;
            }
        }
        std::lock_guard<std::mutex> lk(mtx);
        results.push_back(ip + " (no-arp)");
    }
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s 192.168.1.0/24\n", argv[0]); return 1; }
    std::string base = argv[1];
    base = base.substr(0, base.find('/'));
    std::string prefix = base.substr(0, base.rfind('.') + 1);

    std::vector<std::thread> pool;
    for (int i = 1; i < 255; i++) {
        pool.emplace_back(probe, prefix + std::to_string(i));
        if (pool.size() >= 64) {
            for (auto& t : pool) t.join();
            pool.clear();
        }
    }
    for (auto& t : pool) t.join();
    for (auto& r : results) printf("%s\n", r.c_str());
    return 0;
}
"""

def ensure_native_bin():
    """Compile the C++ LAN sweeper once; silent fallback to Python if no g++."""
    if os.path.exists(NATIVE_BIN):
        return True
    if not shutil.which("g++"):
        return False
    src = os.path.join(APP_DIR, "arpsweep.cpp")
    try:
        with open(src, "w") as f:
            f.write(CPP_SOURCE)
        subprocess.run(["g++", "-O2", "-pthread", src, "-o", NATIVE_BIN],
                       check=True, capture_output=True)
        os.remove(src)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- wireless

def _has_aircrack():
    return shutil.which("airodump-ng") is not None

def _monitor_iface():
    try:
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
        for block in out.split("Interface ")[1:]:
            if "type monitor" in block:
                return block.splitlines()[0].strip()
    except Exception:
        pass
    return None

def wireless_scan(seconds=30):
    if not _has_aircrack():
        return {
            "available": False,
            "reason": ("airodump-ng not found. Note: Android/Termux cannot enable "
                       "monitor mode on the built-in Wi-Fi chip. Use an OTG USB "
                       "adapter with aircrack-ng, or run on Linux/Kali."),
            "networks": [],
        }
    mon = _monitor_iface() or "wlan0"
    prefix = os.path.join(tempfile.gettempdir(), "recon")
    try:
        subprocess.run(["airodump-ng", "-w", prefix, mon],
                       capture_output=True, timeout=seconds)
    except subprocess.TimeoutExpired:
        pass  # expected: airodump runs until timeout

    networks = []
    csv_path = prefix + "-01.csv"
    try:
        with open(csv_path) as f:
            in_ap_section = False
            for line in f.read().splitlines():
                cols = line.split(",")
                if not cols or not cols[0]:
                    continue
                if cols[0].strip() == "BSSID":
                    in_ap_section = True
                    continue
                if (in_ap_section and len(cols) > 13
                        and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", cols[0])):
                    networks.append({
                        "bssid": cols[0], "channel": cols[3], "power": cols[8],
                        "encryption": cols[5], "ssid": cols[13],
                    })
        os.remove(csv_path)
    except FileNotFoundError:
        pass
    return {"available": True, "interface": mon, "networks": networks}


# ---------------------------------------------------------------- LAN sweep

def _local_net():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return None

def lan_sweep():
    net = _local_net()
    if not net:
        return {"available": False, "reason": "Could not determine local subnet",
                "hosts": []}

    hosts = []
    if ensure_native_bin():
        out = subprocess.run([NATIVE_BIN, net], capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                hosts.append({"ip": parts[0], "mac": parts[1],
                              "hostname": parts[2] if len(parts) > 2 else ""})
    else:
        # Pure-Python fallback: parallel ping sweep, then read ARP cache
        def ping(ip):
            subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                           capture_output=True)
        threads = [threading.Thread(target=ping,
                                    args=(str(ipaddress.ip_network(net)[i]),))
                   for i in range(1, 255)]
        for t in threads: t.start()
        for t in threads: t.join()
        for line in open("/proc/net/arp").read().splitlines()[1:]:
            cols = line.split()
            if cols and cols[3] != "00:00:00:00:00:00":
                try:
                    name = socket.gethostbyaddr(cols[0])[0]
                except Exception:
                    name = ""
                hosts.append({"ip": cols[0], "mac": cols[3], "hostname": name})

    return {"available": True, "subnet": net, "hosts": hosts}


# ---------------------------------------------------------------- portal check

PROBES = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://captive.apple.com/hotspot-detect.html",
]

def portal_check():
    findings, detected = [], False
    for url in PROBES:
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null",
                 "-w", "%{http_code} %{redirect_url}", "--max-time", "8", url],
                capture_output=True, text=True, timeout=10)
            code, _, redirect = r.stdout.partition(" ")
            redirect = redirect.strip()
            entry = {"probe": url, "status": code, "redirect": redirect}
            if code.startswith("30") and redirect:
                entry["verdict"] = "PORTAL DETECTED"
                detected = True
            elif code in ("204", "200"):
                entry["verdict"] = "clean"
            else:
                entry["verdict"] = "inconclusive"
            findings.append(entry)
        except Exception as e:
            findings.append({"probe": url, "verdict": f"error: {e}"})
    return {"captive_portal": detected, "findings": findings}


# ---------------------------------------------------------------- dashboard

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wi-Fi Recon Suite</title>
<style>
:root {
  --bg: #0d1117; --card: #161b22; --text: #e6edf3;
  --accent: #2f81f7; --danger: #f85149; --ok: #3fb950; --border: #30363d;
}
* { box-sizing: border-box; margin: 0; }
body {
  background: var(--bg); color: var(--text);
  font-family: "JetBrains Mono", monospace, sans-serif;
  min-height: 100vh; padding-bottom: 3rem;
}
header { text-align: center; padding: 2rem 1rem; border-bottom: 1px solid var(--border); }
header h1 { color: var(--accent); }
header p { color: #8b949e; margin-top: .5rem; font-size: .85rem; }
main { max-width: 900px; margin: 0 auto; padding: 1.5rem; display: grid; gap: 1.5rem; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
.card h2 { font-size: 1.05rem; margin-bottom: 1rem; color: var(--accent); }
button {
  background: var(--accent); color: #fff; border: 0; border-radius: 6px;
  padding: .55rem 1.2rem; font-family: inherit; cursor: pointer; font-size: .9rem;
}
button:hover { filter: brightness(1.15); }
button:disabled { opacity: .5; cursor: wait; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: .82rem; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--border); }
th { color: #8b949e; text-transform: uppercase; font-size: .7rem; }
.badge { padding: .15rem .5rem; border-radius: 4px; font-size: .72rem; }
.badge.ok { background: rgba(63,185,80,.15); color: var(--ok); }
.badge.danger { background: rgba(248,81,73,.15); color: var(--danger); }
.note { font-size: .85rem; color: #8b949e; margin-top: .75rem; white-space: pre-wrap; }
#status { position: fixed; bottom: 0; left: 0; right: 0; background: var(--card);
  border-top: 1px solid var(--border); padding: .5rem 1rem; font-size: .78rem; color: #8b949e; }
@media (max-width: 600px) { main { padding: .75rem; } }
</style>
</head>
<body>
<header>
  <h1>Wi-Fi Recon Suite</h1>
  <p>Authorized assessment of your own networks</p>
</header>
<main>
  <section class="card">
    <h2>Captive Portal Check</h2>
    <button id="btn-portal" onclick="checkPortal()">Run Check</button>
    <div id="portal-result" class="note"></div>
  </section>
  <section class="card">
    <h2>LAN Devices</h2>
    <button id="btn-lan" onclick="scanLan()">Scan Network</button>
    <table id="lan-table">
      <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th></tr></thead>
      <tbody></tbody>
    </table>
  </section>
  <section class="card">
    <h2>Wireless Networks</h2>
    <button id="btn-wifi" onclick="scanWireless()">Monitor Scan (30s)</button>
    <div id="wireless-note" class="note"></div>
    <table id="wifi-table">
      <thead><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>Encryption</th><th>Signal</th></tr></thead>
      <tbody></tbody>
    </table>
  </section>
</main>
<footer id="status">Ready.</footer>
<script>
const $ = (id) => document.getElementById(id);
const setStatus = (msg) => $("status").textContent = msg;
const btn = (id, busy) => $(id).disabled = busy;

async function api(path) {
  setStatus("Running " + path + " ...");
  const r = await fetch(path);
  setStatus("Done.");
  return r.json();
}

async function checkPortal() {
  btn("btn-portal", true);
  const div = $("portal-result");
  div.textContent = "Probing connectivity endpoints...";
  const data = await api("/api/check/portal");
  div.innerHTML = "";
  data.findings.forEach(f => {
    const p = document.createElement("div");
    const cls = f.verdict && f.verdict.includes("PORTAL") ? "danger" : "ok";
    p.innerHTML = '<span class="badge ' + cls + '">' + (f.verdict || "?") + '</span> '
                + f.probe + (f.redirect ? ' \u2192 ' + f.redirect : '');
    div.appendChild(p);
  });
  btn("btn-portal", false);
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
  btn("btn-lan", true);
  const data = await api("/api/scan/lan");
  if (!data.available) { setStatus(data.reason); btn("btn-lan", false); return; }
  fillTable("lan-table", data.hosts, ["ip", "mac", "hostname"]);
  setStatus("Found " + data.hosts.length + " devices on " + data.subnet);
  btn("btn-lan", false);
}

async function scanWireless() {
  btn("btn-wifi", true);
  const note = $("wireless-note");
  note.textContent = "Scanning for 30 seconds...";
  const data = await api("/api/scan/wireless");
  if (!data.available) { note.textContent = data.reason; btn("btn-wifi", false); return; }
  fillTable("wifi-table", data.networks,
            ["ssid", "bssid", "channel", "encryption", "power"]);
  note.textContent = "Found " + data.networks.length + " networks via " + data.interface;
  btn("btn-wifi", false);
}
</script>
</body>
</html>"""

# ---------------------------------------------------------------- flask app

app = Flask(__name__)

@app.route("/")
def index():
    return Response(HTML, mimetype="text/html")

@app.route("/api/scan/wireless")
def api_wireless():
    return jsonify(wireless_scan(30))

@app.route("/api/scan/lan")
def api_lan():
    return jsonify(lan_sweep())

@app.route("/api/check/portal")
def api_portal():
    return jsonify(portal_check())

if __name__ == "__main__":
    if os.name == "nt":
        sys.exit("Windows is not supported (needs raw sockets / aircrack).")
    print("[*] Wi-Fi Recon Suite")
    print("[*] Native C++ sweeper:", "compiled" if ensure_native_bin() else "using Python fallback")
    print("[*] Dashboard: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000)