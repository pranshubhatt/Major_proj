"""
Agentic Edge Intelligence IDS - Laptop Subscriber GUI
REST polling of /stats every second.

Sender ID format (confirmed from live data):
  pi3-pub-1-thermostat  (MQTT,  10.87.16.4)
  pi3-pub-2-smartbulb   (MQTT,  10.87.16.114)  ← malicious
  pi3-pub-3-TV          (AMQP,  10.87.16.242)
  pi3-pub-4-fridge      (CoAP,  10.87.16.121)
  pi3-pub-5-camera      (CoAP,  10.87.16.11)   ← malicious

Node A receives: MQTT (pub-1, pub-2) + AMQP (pub-3)
Node B receives: CoAP (pub-4, pub-5)
Failover: if A down → B also handles pub-1,2,3 via bridge
"""

import json
import logging
import queue
import threading
import time
import tkinter as tk
import urllib.request
import urllib.error
from typing import Any

import customtkinter as ctk

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("subscriber.log")],
)
log = logging.getLogger("Subscriber")

STAGE_LABELS = {1: "Cuckoo Filter", 2: "Random Forest", 3: "Isolation Forest"}
PROTO_COLORS  = {"MQTT": "#00d4ff", "AMQP": "#ffd700", "CoAP": "#a78bfa"}

# ── Pi3 node definitions ──────────────────────────────────────────────────────
# (display_name, ip, protocol, sender_id_prefix, is_malicious)
PI3_NODES = [
    ("Pi3-pub-1", "10.87.16.4",   "MQTT", "pi3-pub-1", False),
    ("Pi3-pub-2", "10.87.16.114", "MQTT", "pi3-pub-2", True),
    ("Pi3-pub-3", "10.87.16.242", "AMQP", "pi3-pub-3", False),
    ("Pi3-pub-4", "10.87.16.121", "CoAP", "pi3-pub-4", False),
    ("Pi3-pub-5", "10.87.16.11",  "CoAP", "pi3-pub-5", True),
]


def find_node_by_sender(sender_id: str) -> tuple | None:
    """
    Match a sender_id string (e.g. 'pi3-pub-2-smartbulb') to a Pi3 node.
    Returns (name, ip, proto, prefix, is_malicious) or None.
    """
    sid = sender_id.lower()
    for node in PI3_NODES:
        if node[3].lower() in sid:  # prefix match: 'pi3-pub-2' in 'pi3-pub-2-smartbulb'
            return node
    # Fallback: direct IP match
    for node in PI3_NODES:
        if node[1] in sid:
            return node
    return None


# ── REST Polling Client ───────────────────────────────────────────────────────
class RESTPoller:
    def __init__(self, data_q: queue.Queue, status_q: queue.Queue):
        self.data_q   = data_q
        self.status_q = status_q
        self.running  = False
        self._ip      = ""
        self._thread: threading.Thread | None = None

    def connect(self, ip: str) -> None:
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._ip     = ip
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def disconnect(self) -> None:
        self.running = False

    def _loop(self) -> None:
        url = f"http://{self._ip}:8000/stats"
        log.info(f"Polling {url}")
        self.status_q.put(("connecting", url))
        errors = 0
        while self.running:
            try:
                req = urllib.request.Request(url, headers={"Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    snap = json.loads(resp.read())
                    self.data_q.put(snap)
                    if errors > 0:
                        errors = 0
                        self.status_q.put(("connected", url))
                    elif errors == 0:
                        self.status_q.put(("connected", url))
            except urllib.error.URLError as e:
                errors += 1
                if errors == 1:
                    self.status_q.put(("error", f"Cannot reach {self._ip}:8000 — {e.reason}"))
                log.warning(f"Poll error: {e}")
            except Exception as e:
                errors += 1
                self.status_q.put(("error", f"{type(e).__name__}: {e}"))
                log.error(f"Poll error: {e}")
            time.sleep(1)


# ── Main Application ──────────────────────────────────────────────────────────
class SubscriberApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Agentic Edge IDS — Subscriber Dashboard")
        self.geometry("1500x960")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.data_q:   queue.Queue = queue.Queue()
        self.status_q: queue.Queue = queue.Queue()
        self.poller = RESTPoller(self.data_q, self.status_q)
        self.latest: dict[str, Any] = {}

        self.node_a_ip     = tk.StringVar(value="10.87.16.251")
        self.node_b_ip     = tk.StringVar(value="10.87.16.79")
        self.selected_node = tk.StringVar(value="A")

        self._build_ui()
        self.after(200, self._poll_ui)

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._build_top_bar()
        self._build_body()

    def _build_top_bar(self):
        top = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=0, height=60)
        top.grid(row=0, column=0, sticky="ew")
        top.grid_columnconfigure(1, weight=1)
        top.grid_propagate(False)

        ctk.CTkLabel(top, text="⚡ Agentic Edge Intelligence IDS",
                     font=("Helvetica", 18, "bold"), text_color="#00d4ff"
                     ).grid(row=0, column=0, padx=15, pady=10, sticky="w")

        gw = ctk.CTkFrame(top, fg_color="transparent")
        gw.grid(row=0, column=1, sticky="e", padx=10)

        ctk.CTkLabel(gw, text="Gateway:", font=("Helvetica", 12)).pack(side="left", padx=5)
        ctk.CTkRadioButton(gw, text="Node A", variable=self.selected_node, value="A",
                           command=self._on_switch, font=("Helvetica", 12)).pack(side="left", padx=5)
        ctk.CTkEntry(gw, textvariable=self.node_a_ip, width=130).pack(side="left", padx=(0, 10))
        ctk.CTkRadioButton(gw, text="Node B", variable=self.selected_node, value="B",
                           command=self._on_switch, font=("Helvetica", 12)).pack(side="left", padx=5)
        ctk.CTkEntry(gw, textvariable=self.node_b_ip, width=130).pack(side="left", padx=(0, 10))
        ctk.CTkButton(gw, text="Connect",    width=90, command=self._on_connect).pack(side="left", padx=5)
        ctk.CTkButton(gw, text="Disconnect", width=90, fg_color="#555",
                      command=self._on_disconnect).pack(side="left", padx=5)

        self.status_label = ctk.CTkLabel(top, text="⬤ Disconnected",
                                         font=("Helvetica", 12, "bold"), text_color="#ff6b6b")
        self.status_label.grid(row=0, column=2, padx=20, sticky="e")

    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)
        self._build_pi3_panel(body)
        self._build_metrics_panel(body)
        self._build_bottom_panels(body)

    def _build_pi3_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color="#0d1117", corner_radius=8)
        panel.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkLabel(panel, text="🔍 Sensor Nodes (Pi3) — Status based on live strike_memory from Pi4",
                     font=("Helvetica", 12, "bold"), text_color="#ffd700"
                     ).pack(anchor="w", padx=12, pady=(8, 4))

        row = ctk.CTkFrame(panel, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=(0, 8))

        self.node_lamps: dict[str, dict] = {}
        for name, ip, proto, prefix, is_mal in PI3_NODES:
            pcol = PROTO_COLORS.get(proto, "#aaa")
            card = ctk.CTkFrame(row, fg_color="#161b22", corner_radius=8)
            card.pack(side="left", expand=True, fill="x", padx=5)

            # Protocol badge at top
            ctk.CTkLabel(card, text=proto, font=("Helvetica", 9, "bold"),
                         text_color=pcol, fg_color="#0a0a0a",
                         corner_radius=4, width=55).pack(pady=(6, 0))

            lamp = ctk.CTkLabel(card, text="⬤", font=("Helvetica", 26), text_color="#555555")
            lamp.pack(pady=(2, 1))

            ctk.CTkLabel(card, text=name, font=("Helvetica", 11, "bold")).pack()
            ctk.CTkLabel(card, text=ip,   font=("Helvetica", 9), text_color="#888").pack()

            status_lbl  = ctk.CTkLabel(card, text="Unknown",
                                       font=("Helvetica", 10, "bold"), text_color="#888")
            status_lbl.pack(pady=(2, 1))

            strikes_lbl = ctk.CTkLabel(card, text="Strikes: —",
                                       font=("Helvetica", 9), text_color="#666")
            strikes_lbl.pack(pady=(0, 6))

            self.node_lamps[prefix] = {
                "lamp": lamp, "status": status_lbl, "strikes": strikes_lbl,
                "ip": ip, "proto": proto
            }

    def _build_metrics_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color="#0d1117", corner_radius=8)
        panel.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkLabel(panel, text="📊 Live Metrics",
                     font=("Helvetica", 12, "bold"), text_color="#ffd700"
                     ).pack(anchor="w", padx=12, pady=(8, 4))

        row = ctk.CTkFrame(panel, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=(0, 10))

        self.metric_vals: dict[str, ctk.CTkLabel] = {}
        cards = [
            ("Pkts/Sec",  "pps",    "#00d4ff"),
            ("Total In",  "total",  "#a8dadc"),
            ("MQTT Pkts", "mqtt",   "#00d4ff"),
            ("AMQP Pkts", "amqp",   "#ffd700"),
            ("CoAP Pkts", "coap",   "#a78bfa"),
            ("Benign",    "benign", "#5fba7d"),
            ("Malicious", "mal",    "#ff6b6b"),
            ("Det. Rate", "rate",   "#ffd700"),
            ("Blocked",   "blocks", "#ff8c42"),
            ("Uptime",    "uptime", "#b0b3b8"),
        ]
        for title, key, color in cards:
            c = ctk.CTkFrame(row, fg_color="#161b22", corner_radius=8)
            c.pack(side="left", expand=True, fill="x", padx=3)
            ctk.CTkLabel(c, text=title, font=("Helvetica", 8), text_color="#888").pack(pady=(5, 0))
            lbl = ctk.CTkLabel(c, text="—", font=("Helvetica", 15, "bold"), text_color=color)
            lbl.pack(pady=(0, 5))
            self.metric_vals[key] = lbl

    def _build_bottom_panels(self, parent):
        bottom = ctk.CTkFrame(parent, fg_color="transparent")
        bottom.grid(row=2, column=0, sticky="nsew")
        bottom.grid_columnconfigure(0, weight=2)
        bottom.grid_columnconfigure(1, weight=1)
        bottom.grid_rowconfigure(0, weight=1)

        # Threat feed (left)
        left = ctk.CTkFrame(bottom, fg_color="#0d1117", corner_radius=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="🎯 Threat Feed  (sender | protocol | attack | stage)",
                     font=("Helvetica", 12, "bold"), text_color="#ffd700"
                     ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 4))

        self.threat_box = ctk.CTkTextbox(left, font=("Courier New", 10),
                                         fg_color="#0a0a0a", text_color="#e0e0e0", corner_radius=6)
        self.threat_box.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.threat_box.configure(state="disabled")

        # Right column
        right = ctk.CTkFrame(bottom, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        right.grid_rowconfigure(0, weight=1)
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        # Quarantine
        qp = ctk.CTkFrame(right, fg_color="#0d1117", corner_radius=8)
        qp.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
        qp.grid_rowconfigure(1, weight=1)
        qp.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(qp, text="🚫 Active Quarantine",
                     font=("Helvetica", 12, "bold"), text_color="#ffd700"
                     ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 4))

        self.quarantine_box = ctk.CTkTextbox(qp, font=("Courier New", 10),
                                             fg_color="#0a0a0a", text_color="#ff8c42", corner_radius=6)
        self.quarantine_box.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.quarantine_box.configure(state="disabled")

        # Broker health
        bp = ctk.CTkFrame(right, fg_color="#0d1117", corner_radius=8)
        bp.grid(row=1, column=0, sticky="nsew", pady=(5, 0))

        ctk.CTkLabel(bp, text="📡 Broker Health",
                     font=("Helvetica", 12, "bold"), text_color="#ffd700"
                     ).pack(anchor="w", padx=12, pady=(8, 4))

        bf = ctk.CTkFrame(bp, fg_color="transparent")
        bf.pack(fill="x", padx=12, pady=(0, 10))

        self.broker_labels: dict[str, ctk.CTkLabel] = {}
        broker_defs = [
            ("mqtt",    "MQTT",    "#00d4ff"),
            ("amqp",    "AMQP",    "#ffd700"),
            ("coap",    "CoAP",    "#a78bfa"),
            ("zmq_pub", "ZMQ PUB", "#aaa"),
            ("zmq_sub", "ZMQ SUB", "#aaa"),
            ("bridge",  "Bridge",  "#aaa"),
        ]
        for key, label, col in broker_defs:
            r = ctk.CTkFrame(bf, fg_color="transparent")
            r.pack(fill="x", pady=2)
            ctk.CTkLabel(r, text=label, font=("Courier New", 10),
                         width=75, text_color=col).pack(side="left")
            lbl = ctk.CTkLabel(r, text="—", font=("Courier New", 10, "bold"), text_color="#555")
            lbl.pack(side="left")
            self.broker_labels[key] = lbl

    # ── Controls ──────────────────────────────────────────────────────────────
    def _get_ip(self) -> str:
        return (self.node_a_ip if self.selected_node.get() == "A" else self.node_b_ip).get().strip()

    def _on_connect(self):
        ip = self._get_ip()
        if ip:
            self.poller.connect(ip)

    def _on_disconnect(self):
        self.poller.disconnect()
        self.status_label.configure(text="⬤ Disconnected", text_color="#ff6b6b")

    def _on_switch(self):
        if self.poller.running:
            self.poller.connect(self._get_ip())

    # ── UI polling ────────────────────────────────────────────────────────────
    def _poll_ui(self):
        while True:
            try:
                kind, data = self.status_q.get_nowait()
                self._set_status(kind, data)
            except queue.Empty:
                break
        while True:
            try:
                snap = self.data_q.get_nowait()
                self.latest = snap
                self._update_ui(snap)
            except queue.Empty:
                break
        self.after(200, self._poll_ui)

    def _set_status(self, kind: str, data: str):
        if kind == "connecting":
            self.status_label.configure(text="⬤ Connecting…", text_color="#ffd700")
        elif kind == "connected":
            node = self.selected_node.get()
            self.status_label.configure(
                text=f"⬤ Connected → Node {node}  ({self._get_ip()})",
                text_color="#5fba7d")
        else:
            self.status_label.configure(
                text=f"⬤ {data.split(chr(10))[0][:55]}", text_color="#ff6b6b")

    # ── Data update ───────────────────────────────────────────────────────────
    def _update_ui(self, snap: dict):
        pkt = snap.get("packets", {})
        q   = snap.get("quarantine", {})
        thr = snap.get("threats", {})
        bh  = snap.get("broker_health", {})
        ing = pkt.get("ingested", {})

        self.metric_vals["pps"].configure(text=f"{pkt.get('packets_per_second', 0):.1f}")
        self.metric_vals["total"].configure(text=str(ing.get("total", 0)))
        self.metric_vals["mqtt"].configure(text=str(ing.get("mqtt", 0)))
        self.metric_vals["amqp"].configure(text=str(ing.get("amqp", 0)))
        self.metric_vals["coap"].configure(text=str(ing.get("coap", 0)))
        self.metric_vals["benign"].configure(text=str(pkt.get("benign", 0)))
        self.metric_vals["mal"].configure(text=str(pkt.get("malicious", 0)))
        self.metric_vals["rate"].configure(text=f"{pkt.get('detection_rate', 0):.1f}%")
        self.metric_vals["blocks"].configure(text=str(q.get("count", 0)))
        self.metric_vals["uptime"].configure(text=snap.get("uptime_human", "—"))

        self._update_lamps(q.get("active_blocks", {}), q.get("strike_memory", {}))
        self._update_threat_feed(thr.get("recent_feed", []))
        self._update_quarantine(q.get("active_blocks", {}))
        self._update_broker(bh)

    def _update_lamps(self, active_blocks: dict, strike_mem: dict):
        """
        Lamp logic based entirely on Pi4's own strike_memory and active_blocks.
        strike_memory is maintained by the Pi4 with forgiveness decay —
        so benign nodes' strikes drift towards 0 while malicious nodes stay high.

        Thresholds (STRIKE_THRESHOLD on Pi4 = 3.0):
          BLOCKED    : sender in active_blocks (Pi4 has issued iptables rule)
          SUSPICIOUS : strike >= 1.5  (halfway to quarantine, persistent threat)
          ALERT      : strike >= 0.5  (at least one detection, may be false positive)
          SAFE       : strike < 0.5   (forgiveness has cleared any noise)
        """
        # Build lookup: prefix → max strike value found in strike_memory
        prefix_strikes: dict[str, float] = {}
        for sender_id, strike_val in strike_mem.items():
            node = find_node_by_sender(sender_id)
            if node:
                prefix = node[3]   # e.g. "pi3-pub-2"
                prefix_strikes[prefix] = max(prefix_strikes.get(prefix, 0.0), strike_val)

        # Build set of blocked prefixes from active_blocks
        blocked_prefixes: set[str] = set()
        for sender_id in active_blocks:
            node = find_node_by_sender(sender_id)
            if node:
                blocked_prefixes.add(node[3])

        connected = bool(self.latest)
        for name, ip, proto, prefix, is_malicious in PI3_NODES:
            widgets = self.node_lamps[prefix]
            strikes = prefix_strikes.get(prefix, 0.0)

            if prefix in blocked_prefixes:
                color, status = "#ff4444", "🚫 BLOCKED"
            elif strikes >= 1.5:
                color, status = "#ff8c42", "⚠ SUSPICIOUS"
            elif strikes >= 0.5:
                color, status = "#ffdd00", "⚡ ALERT"
            elif connected:
                color, status = "#5fba7d", "✓ SAFE"
            else:
                color, status = "#555555", "Unknown"

            widgets["lamp"].configure(text_color=color)
            widgets["status"].configure(text=status, text_color=color)
            widgets["strikes"].configure(
                text=f"Strikes: {strikes:.1f}" if strikes else "Strikes: 0.0")

    def _update_threat_feed(self, feed: list):
        self.threat_box.configure(state="normal")
        self.threat_box.delete("1.0", "end")

        hdr = f"{'TIME':8}  {'SENDER':24}  {'PROTO':5}  {'ATTACK':22}  {'STAGE'}\n" + "─" * 90 + "\n"
        self.threat_box.insert("end", hdr)

        if not feed:
            self.threat_box.insert("end", "\n  No detections yet.\n")
        else:
            for t in feed:
                ts     = t.get("timestamp", "")
                ts     = ts.split("T")[1][:8] if "T" in ts else ts[:8]
                sender = t.get("sender_id", "?")[:24].ljust(24)
                attack = t.get("attack_type", "?")[:22].ljust(22)
                stage  = STAGE_LABELS.get(t.get("stage", 0), "?")

                # Look up protocol from sender_id
                node  = find_node_by_sender(t.get("sender_id", ""))
                proto = node[2] if node else "—"

                self.threat_box.insert(
                    "end", f"{ts}  {sender}  {proto:5}  {attack}  {stage}\n")

        self.threat_box.configure(state="disabled")

    def _update_quarantine(self, active_blocks: dict):
        self.quarantine_box.configure(state="normal")
        self.quarantine_box.delete("1.0", "end")

        if not active_blocks:
            self.quarantine_box.insert("end", "\n  No active blocks.\n")
        else:
            for sender_id, info in active_blocks.items():
                node = find_node_by_sender(sender_id)
                if node:
                    label = f"{node[0]} [{node[2]}]"
                else:
                    label = sender_id

                attack  = info.get("attack", "?")
                strikes = info.get("strikes", 0)
                expires = info.get("expires_at", "?")
                if "T" in str(expires):
                    expires = expires.split("T")[1][:8]

                self.quarantine_box.insert(
                    "end",
                    f"⛔ {label}\n"
                    f"   ID     : {sender_id}\n"
                    f"   Attack : {attack}\n"
                    f"   Strikes: {strikes}\n"
                    f"   Expires: {expires}\n\n"
                )
        self.quarantine_box.configure(state="disabled")

    def _update_broker(self, bh: dict):
        cmap = {
            "CONNECTED": "#5fba7d", "BOUND": "#5fba7d", "OK": "#5fba7d",
            "STARTING":  "#ffd700", "ERROR": "#ff6b6b", "N/A": "#555555",
        }
        for key, lbl in self.broker_labels.items():
            status = bh.get(key, "N/A")
            lbl.configure(text=status, text_color=cmap.get(status, "#aaaaaa"))


if __name__ == "__main__":
    app = SubscriberApp()
    app.mainloop()
