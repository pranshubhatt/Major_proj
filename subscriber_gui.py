"""
subscriber_gui.py -- IoT Threat Detection | Subscriber Dashboard
Version 3.0 -- Full symmetric protocol failover

ARCHITECTURE
------------
  NetworkLayer   -- 6 simultaneous listeners:
                     Node A: MQTT + AMQP + CoAP  (CoAP = failover for Pi3 4-5)
                     Node B: MQTT + AMQP + CoAP  (CoAP = primary for Pi3 4-5)

  PublisherState -- Holds runtime data per publisher.
                    Knows each publisher's PRIMARY gateway from
                    PUBLISHER_PRIMARY_GATEWAY dict. Compares every packet's
                    arriving gateway against that primary to detect failover.

  PublisherCard  -- Tkinter card widget, updated on main thread only.

  SubscriberApp  -- Root Tk window, sidebar, scrollable cards, status bar.

WHY BOTH NODES NEED ALL 3 PROTOCOL LISTENERS
---------------------------------------------
  Pi3 Nodes 1,2,3 -> primary: Node A (MQTT/AMQP) | failover: Node B (MQTT/AMQP)
  Pi3 Nodes 4,5   -> primary: Node B (CoAP)       | failover: Node A (CoAP)

  When Node B goes offline, Pi3 Nodes 4 & 5 automatically switch to Node A
  via CoAP (sensor_coap.py implements RFC 7252 gateway failover).
  The GUI must have a CoAP listener on Node A to catch those packets --
  otherwise Fridge and DoorCamera go invisible during a Node B outage.

  Symmetrically, Node B must have MQTT/AMQP for when Node A goes offline.

FAILOVER DETECTION LOGIC
-------------------------
  Old (buggy): compared current_gateway vs previous_gateway.
  New (correct): compares every packet.gateway against PUBLISHER_PRIMARY_GATEWAY.
    * Packet on primary   -> clear failover (handles recovery automatically)
    * Packet on secondary -> set failover_active + build descriptive message
  No Dismiss button needed -- alert disappears when primary comes back.

DATA INSIGHTS (from live_stream_data.csv schema)
-------------------------------------------------
  Displayed as rolling averages over the last 50 samples:
    Rate          -- flow rate (pkt/s)
    Tot size      -- total payload bytes
    Duration      -- flow duration (ms)
    Header_Length -- header size (bytes)
    IAT           -- inter-arrival time (s)
    flow_duration -- full flow lifespan (s)
    Protocol Type -- numeric (6=TCP, 17=UDP, etc.)
  Also shows: peak Rate, peak Tot size, protocol distribution, category.

THREAD SAFETY
-------------
  All 6 network threads ONLY call queue.put_nowait() -- never touch Tkinter.
  A root.after(100ms) loop drains the queue on the main thread only.

DEPENDENCIES
------------
  pip install paho-mqtt pika aiocoap
"""

from __future__ import annotations

import asyncio
import json
import queue
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime
from tkinter import ttk
from typing import Optional

# Optional protocol libraries -- GUI degrades gracefully if not installed
try:
    import paho.mqtt.client as mqtt_client
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False

try:
    import pika
    AMQP_AVAILABLE = True
except ImportError:
    AMQP_AVAILABLE = False

try:
    import aiocoap
    COAP_AVAILABLE = True
except ImportError:
    COAP_AVAILABLE = False


# =============================================================================
# SECTION 1 -- CONFIGURATION  (edit these before running)
# =============================================================================

# -- Node A -------------------------------------------------------------------
NODE_A_IP    = "10.87.16.251"
NODE_A_LABEL = "Node A"

NODE_A_MQTT_PORT  = 1883
NODE_A_MQTT_TOPIC = "iot/telemetry"       # real topic Pi3 nodes publish to

NODE_A_AMQP_PORT  = 5672
NODE_A_AMQP_QUEUE = "iot_telemetry"       # real queue Pi3 nodes publish to
NODE_A_AMQP_USER  = "edge_user"
NODE_A_AMQP_PASS  = "edge_pass"

# CoAP on Node A: receives Pi3 Nodes 4 & 5 when Node B fails over to Node A.
NODE_A_COAP_PORT     = 5683
NODE_A_COAP_RESOURCE = "iot/telemetry"

# -- Node B -------------------------------------------------------------------
NODE_B_IP    = "10.87.16.79"
NODE_B_LABEL = "Node B"

NODE_B_MQTT_PORT  = 1883
NODE_B_MQTT_TOPIC = "iot/telemetry"       # real topic Pi3 nodes publish to

NODE_B_AMQP_PORT  = 5672
NODE_B_AMQP_QUEUE = "iot_telemetry"       # real queue Pi3 nodes publish to
NODE_B_AMQP_USER  = "edge_user"
NODE_B_AMQP_PASS  = "edge_pass"

# CoAP on Node B: primary ingress for Pi3 Nodes 4 & 5.
NODE_B_COAP_PORT     = 5683
NODE_B_COAP_RESOURCE = "iot/telemetry"

# -- Publisher identity table -------------------------------------------------
# display_name -> sender_id  (must match "sender_id" field in JSON payload)
KNOWN_PUBLISHERS: dict[str, str] = {
    "Thermostat": "pi3-pub-1-thermostat",
    "SmartBulb":  "pi3-pub-2-smartbulb",
    "SmartTV":    "pi3-pub-3-TV",
    "Fridge":     "pi3-pub-4-fridge",
    "DoorCamera": "pi3-pub-5-camera",
}

# -- Primary gateway per publisher (GROUND TRUTH for failover detection) ------
# Pi3 Nodes 1-3 home to Node A; Pi3 Nodes 4-5 home to Node B.
# A packet arriving on the OTHER node means failover is active.
# Keys MUST match the actual sender_id values from the Pi3 JSON payloads.
# Confirmed from live data: pi3-pub-1-thermostat, pi3-pub-2-smartbulb, etc.
PUBLISHER_PRIMARY_GATEWAY: dict[str, str] = {
    "pi3-pub-1-thermostat": NODE_A_LABEL,   # Thermostat  -- Node A primary (MQTT)
    "pi3-pub-2-smartbulb":  NODE_A_LABEL,   # SmartBulb   -- Node A primary (MQTT)
    "pi3-pub-3-TV":         NODE_A_LABEL,   # SmartTV     -- Node A primary (AMQP)
    "pi3-pub-4-fridge":     NODE_B_LABEL,   # Fridge      -- Node B primary (CoAP)
    "pi3-pub-5-camera":     NODE_B_LABEL,   # DoorCamera  -- Node B primary (CoAP)
}

# -- UI behaviour -------------------------------------------------------------
POLL_INTERVAL_MS  = 100   # ms between GUI queue drains
MAX_PAYLOAD_LINES = 5     # recent payloads shown per card
RECONNECT_DELAY_S = 5     # backoff between listener reconnect attempts
INSIGHTS_WINDOW   = 50    # rolling sample window size


# =============================================================================
# SECTION 2 -- DESIGN TOKENS
# =============================================================================

PALETTE = {
    "bg":            "#0d1117",
    "surface":       "#161b22",
    "surface2":      "#1c2230",
    "border":        "#30363d",
    "border_hi":     "#58a6ff",
    "text":          "#e6edf3",
    "text_muted":    "#8b949e",
    "text_dim":      "#484f58",
    "accent_blue":   "#58a6ff",
    "accent_green":  "#3fb950",
    "accent_amber":  "#d29922",
    "accent_red":    "#f85149",
    "accent_purple": "#bc8cff",
    "accent_teal":   "#39d353",   # MQTT badge colour
    "accent_orange": "#f0883e",   # AMQP badge colour
    "accent_coap":   "#a371f7",   # CoAP badge colour
    "tag_node_a":    "#0d419d",   # Node A header background
    "tag_node_b":    "#3d1f7a",   # Node B header background
    "tag_failover":  "#6e1a1a",   # Failover banner background
    "sidebar":       "#010409",
    "input_bg":      "#21262d",
    "btn_primary":   "#238636",
    "btn_hover":     "#2ea043",
}

FONT_BIG     = ("Courier New", 14, "bold")
FONT_HEADER  = ("Courier New", 10, "bold")
FONT_BODY    = ("Courier New",  9)
FONT_SMALL   = ("Courier New",  8)
FONT_TAG     = ("Courier New",  8, "bold")
FONT_MONO    = ("Courier New",  8)
FONT_SIDEBAR = ("Courier New",  9, "bold")


# =============================================================================
# SECTION 3 -- INCOMING PACKET MODEL
# =============================================================================

class IncomingPacket:
    """
    Normalised wrapper created by network threads, consumed on main thread.
    sender_id is extracted from the JSON payload's "sender_id" field --
    this must be set by the Pi3 publisher scripts.
    """
    __slots__ = ("sender_id", "gateway", "protocol", "raw_payload", "received_at")

    def __init__(self, raw: dict, gateway: str, protocol: str) -> None:
        self.sender_id   = str(raw.get("sender_id", raw.get("device_id", "unknown")))
        self.gateway     = gateway    # "Node A" or "Node B"
        self.protocol    = protocol   # "MQTT", "AMQP", or "CoAP"
        self.raw_payload = raw
        self.received_at = datetime.now()


# =============================================================================
# SECTION 4 -- NETWORK LAYER  (background threads, zero Tkinter access)
# =============================================================================

class BaseListener:
    """
    Abstract base for all protocol listeners.
    Subclasses implement _run_loop(); call self._deliver(raw_dict) on each packet.
    _supervised_loop() wraps _run_loop() with exponential-backoff retry.
    """

    def __init__(self, gateway: str, protocol: str,
                 incoming_queue: queue.Queue, status_cb) -> None:
        self.gateway     = gateway
        self.protocol    = protocol
        self._queue      = incoming_queue
        self._status_cb  = status_cb          # callable(gateway, protocol, status_str)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._supervised_loop,
            name=f"{self.gateway}-{self.protocol}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _deliver(self, raw: dict) -> None:
        """Thread-safe push to shared queue. Silent drop if full (flood guard)."""
        try:
            self._queue.put_nowait(IncomingPacket(raw, self.gateway, self.protocol))
        except queue.Full:
            pass

    def _set_status(self, s: str) -> None:
        self._status_cb(self.gateway, self.protocol, s)

    def _supervised_loop(self) -> None:
        """Retry _run_loop() with exponential backoff on any exception."""
        backoff = 1
        while not self._stop_event.is_set():
            try:
                self._run_loop()
                backoff = 1
            except Exception as exc:
                self._set_status(f"ERR:{type(exc).__name__}")
                time.sleep(min(backoff, 60))
                backoff = min(backoff * 2, 60)

    def _run_loop(self) -> None:
        raise NotImplementedError


# -- MQTT listener -------------------------------------------------------------

class MQTTListener(BaseListener):
    """paho-mqtt subscriber with automatic reconnect."""

    def __init__(self, host: str, port: int, topic: str,
                 gateway: str, incoming_queue: queue.Queue,
                 status_cb, client_id: str) -> None:
        super().__init__(gateway, "MQTT", incoming_queue, status_cb)
        self.host      = host
        self.port      = port
        self.topic     = topic
        self.client_id = client_id

    def _run_loop(self) -> None:
        if not MQTT_AVAILABLE:
            self._set_status("paho-mqtt missing")
            time.sleep(3600)
            return
        self._set_status("Connecting...")
        # paho-mqtt v2 API (VERSION2 avoids deprecation warning)
        c = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2, self.client_id)

        def on_connect(client, userdata, connect_flags, reason_code, properties):
            if reason_code == 0:
                client.subscribe(self.topic)
                self._set_status("Connected")
            else:
                self._set_status(f"Refused rc={reason_code}")

        def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
            if reason_code != 0:
                self._set_status("Disconnected")

        def on_message(client, userdata, msg):
            try:
                self._deliver(json.loads(msg.payload.decode("utf-8")))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        c.on_connect    = on_connect
        c.on_disconnect = on_disconnect
        c.on_message    = on_message
        c.connect(self.host, self.port, keepalive=30)
        c.loop_forever()
        self._set_status("Disconnected")
        time.sleep(RECONNECT_DELAY_S)


# -- AMQP listener -------------------------------------------------------------

class AMQPListener(BaseListener):
    """pika RabbitMQ consumer with automatic reconnect."""

    def __init__(self, host: str, port: int, queue_name: str,
                 username: str, password: str,
                 gateway: str, incoming_queue: queue.Queue,
                 status_cb) -> None:
        super().__init__(gateway, "AMQP", incoming_queue, status_cb)
        self.host       = host
        self.port       = port
        self.queue_name = queue_name
        self.username   = username
        self.password   = password

    def _run_loop(self) -> None:
        if not AMQP_AVAILABLE:
            self._set_status("pika missing")
            time.sleep(3600)
            return
        self._set_status("Connecting...")
        creds  = pika.PlainCredentials(self.username, self.password)
        params = pika.ConnectionParameters(
            host=self.host, port=self.port, virtual_host="/",
            credentials=creds, heartbeat=30,
            blocked_connection_timeout=10, connection_attempts=1,
        )
        conn = pika.BlockingConnection(params)
        ch   = conn.channel()
        ch.queue_declare(queue=self.queue_name, durable=True, passive=True)
        ch.basic_qos(prefetch_count=5)
        self._set_status("Connected")

        def cb(channel, method, properties, body):
            try:
                self._deliver(json.loads(body.decode("utf-8")))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        ch.basic_consume(queue=self.queue_name, on_message_callback=cb, auto_ack=True)
        while not self._stop_event.is_set():
            conn.process_data_events(time_limit=0.5)
        conn.close()
        self._set_status("Disconnected")


# -- CoAP bridge via REST /stats  ----------------------------------------------

class CoAPStatsBridge(BaseListener):
    """
    Replaces aiocoap Observe for CoAP telemetry.

    WHY this approach:
      The Pi4 CoAP server is a RECEIVE endpoint (Pi3s POST to it).
      It does NOT expose an ObservableResource, so RFC 7641 Observe
      always fails with 4.04 or connection error.

      Instead this bridge polls /stats (REST) on the Pi4 every second,
      tracks the delta in packets.ingested.coap, and creates synthetic
      IncomingPacket objects for the CoAP Pi3 nodes (Fridge, DoorCamera).

    Failover handling:
      Normally polls Node B (primary for CoAP nodes).
      If Node B /stats becomes unreachable AND Node A reports CoAP packets,
      packets are delivered with gateway=Node A so the card shows failover.
    """

    # CoAP Pi3 nodes (sender_id, display) -- match KNOWN_PUBLISHERS exactly
    COAP_SENDERS = [
        "pi3-pub-4-fridge",
        "pi3-pub-5-camera",
    ]

    def __init__(self, primary_host: str, secondary_host: str,
                 primary_gateway: str, secondary_gateway: str,
                 incoming_queue: queue.Queue, status_cb) -> None:
        # Register under the primary gateway label for the status bar
        super().__init__(primary_gateway, "CoAP", incoming_queue, status_cb)
        self.primary_host     = primary_host
        self.secondary_host   = secondary_host
        self.primary_gateway  = primary_gateway
        self.secondary_gateway = secondary_gateway

        self._last_coap:  int         = -1
        self._seen_ts:    set[str]    = set()
        self._round_idx:  int         = 0

    def _run_loop(self) -> None:
        """Poll Node B /stats; fall back to Node A if B is down."""
        self._set_status("Connecting...")

        while not self._stop_event.is_set():
            snap, gw = self._fetch_stats(self.primary_host)

            if snap is None:
                # Primary (Node B) unreachable -- try secondary (Node A)
                snap, gw = self._fetch_stats(self.secondary_host)
                if snap is not None:
                    gw = self.secondary_gateway   # packets arrived via failover

            if snap is not None:
                self._set_status("Connected")
                self._process(snap, gw)
            else:
                self._set_status("Disconnected")

            time.sleep(1)

    def _fetch_stats(self, host: str):
        """Return (snapshot_dict, gateway_label) or (None, None) on error."""
        url = f"http://{host}:8000/stats"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                return json.loads(resp.read()), self.primary_gateway
        except Exception:
            return None, None

    def _process(self, snap: dict, gateway: str) -> None:
        """Synthesise IncomingPacket objects from /stats delta."""
        coap_now = snap.get("packets", {}).get("ingested", {}).get("coap", 0)

        # --- Benign CoAP packets: distribute new count delta round-robin ------
        if self._last_coap >= 0 and coap_now > self._last_coap:
            delta = coap_now - self._last_coap
            n     = len(self.COAP_SENDERS)
            for i in range(delta):
                sender = self.COAP_SENDERS[self._round_idx % n]
                self._round_idx += 1
                self._deliver({
                    "sender_id": sender,
                    "protocol":  "CoAP",
                    "gateway":   gateway,
                })
        self._last_coap = coap_now

        # --- Malicious CoAP entries from threat feed --------------------------
        feed = snap.get("threats", {}).get("recent_feed", [])
        for entry in feed:
            ts  = entry.get("timestamp", "")
            sid = entry.get("sender_id", "")
            if sid in self.COAP_SENDERS and ts not in self._seen_ts:
                self._seen_ts.add(ts)
                self._deliver({
                    "sender_id":   sid,
                    "protocol":    "CoAP",
                    "gateway":     gateway,
                    "attack_type": entry.get("attack_type", ""),
                    "category":    entry.get("category", ""),
                    "stage":       entry.get("stage", 0),
                })


# -- Network Layer Orchestrator ------------------------------------------------

class NetworkLayer:
    """
    Owns and starts all 6 listeners (3 protocols x 2 nodes).

    Listener map
    ------------
    Node A / MQTT  -- normal ingress for Pi3 Nodes 1-3
    Node A / AMQP  -- normal ingress for Pi3 Nodes 1-3
    Node A / CoAP  -- FAILOVER ingress for Pi3 Nodes 4-5 (when Node B down)
    Node B / MQTT  -- FAILOVER ingress for Pi3 Nodes 1-3 (when Node A down)
    Node B / AMQP  -- FAILOVER ingress for Pi3 Nodes 1-3 (when Node A down)
    Node B / CoAP  -- normal ingress for Pi3 Nodes 4-5

    All 6 run simultaneously -- the failover detection logic in PublisherState
    decides what is normal vs. what is a failover condition.
    """

    def __init__(self) -> None:
        self.incoming_queue: queue.Queue = queue.Queue(maxsize=2000)
        # Both nodes now have all 3 protocols in the status dict
        self.connection_status: dict[str, dict[str, str]] = {
            NODE_A_LABEL: {"MQTT": "Idle", "AMQP": "Idle", "CoAP": "Idle"},
            NODE_B_LABEL: {"MQTT": "Idle", "AMQP": "Idle", "CoAP": "Idle"},
        }
        self._lock = threading.Lock()
        self._listeners: list[BaseListener] = []

    def _on_status(self, gateway: str, protocol: str, status: str) -> None:
        with self._lock:
            self.connection_status[gateway][protocol] = status

    def get_status_snapshot(self) -> dict[str, dict[str, str]]:
        with self._lock:
            return {g: dict(p) for g, p in self.connection_status.items()}

    def start_all(self) -> None:
        """Instantiate and start all listeners."""
        listeners: list[BaseListener] = [
            # == NODE A ========================================================
            MQTTListener(
                host=NODE_A_IP, port=NODE_A_MQTT_PORT, topic=NODE_A_MQTT_TOPIC,
                gateway=NODE_A_LABEL, incoming_queue=self.incoming_queue,
                status_cb=self._on_status, client_id="SubGUI_NodeA_MQTT",
            ),
            AMQPListener(
                host=NODE_A_IP, port=NODE_A_AMQP_PORT, queue_name=NODE_A_AMQP_QUEUE,
                username=NODE_A_AMQP_USER, password=NODE_A_AMQP_PASS,
                gateway=NODE_A_LABEL, incoming_queue=self.incoming_queue,
                status_cb=self._on_status,
            ),
            # == NODE B ========================================================
            MQTTListener(
                host=NODE_B_IP, port=NODE_B_MQTT_PORT, topic=NODE_B_MQTT_TOPIC,
                gateway=NODE_B_LABEL, incoming_queue=self.incoming_queue,
                status_cb=self._on_status, client_id="SubGUI_NodeB_MQTT",
            ),
            AMQPListener(
                host=NODE_B_IP, port=NODE_B_AMQP_PORT, queue_name=NODE_B_AMQP_QUEUE,
                username=NODE_B_AMQP_USER, password=NODE_B_AMQP_PASS,
                gateway=NODE_B_LABEL, incoming_queue=self.incoming_queue,
                status_cb=self._on_status,
            ),
            # == CoAP bridge (polls /stats, covers both nodes + failover) ======
            # Primary = Node B (Fridge + DoorCamera); falls back to Node A.
            CoAPStatsBridge(
                primary_host=NODE_B_IP,   secondary_host=NODE_A_IP,
                primary_gateway=NODE_B_LABEL, secondary_gateway=NODE_A_LABEL,
                incoming_queue=self.incoming_queue,
                status_cb=self._on_status,
            ),
        ]
        for lst in listeners:
            lst.start()
            self._listeners.append(lst)

    def stop_all(self) -> None:
        for lst in self._listeners:
            lst.stop()


# =============================================================================
# SECTION 5 -- DATA INSIGHTS ENGINE
# =============================================================================

# Fields from live_stream_data.csv displayed as rolling averages.
# Mapping: payload_key -> (display_label, format_string)
INSIGHT_FIELDS: dict[str, tuple[str, str]] = {
    "Rate":          ("Flow Rate",   "{:.2f} p/s"),
    "Tot size":      ("Tot Size",    "{:.0f} B"),
    "Duration":      ("Duration",    "{:.1f} ms"),
    "Header_Length": ("Hdr Len",     "{:.0f} B"),
    "IAT":           ("IAT",         "{:.5f} s"),
    "flow_duration": ("Flow Dur",    "{:.3f} s"),
}

# Numeric Protocol Type -> human name
PROTO_TYPE_NAMES: dict[int, str] = {
    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6",
}


class InsightsEngine:
    """
    Rolling-window statistics for one publisher.
    Methods called only on main thread (inside PublisherState.ingest()).
    """

    def __init__(self) -> None:
        self._samples: deque[dict[str, float]] = deque(maxlen=INSIGHTS_WINDOW)
        self.averages:      dict[str, float] = {}
        self.proto_dist:    dict[str, int]   = {}
        self.max_rate:      float = 0.0
        self.max_tot_size:  float = 0.0
        self.last_category: str   = "—"
        self.last_label:    str   = "—"

    def feed(self, payload: dict) -> None:
        """Extract numeric fields from payload and recompute averages."""
        # Navigate nested packet_data if present (bridge-wrapped packets)
        inner = payload.get("packet_data", {})

        sample: dict[str, float] = {}
        for key in list(INSIGHT_FIELDS.keys()) + ["Protocol Type"]:
            v = payload.get(key)
            if v is None:
                v = inner.get(key)
            if v is not None:
                try:
                    sample[key] = float(v)
                except (TypeError, ValueError):
                    pass

        if sample:
            self._samples.append(sample)

        # Capture category / label if present
        cat = payload.get("category") or inner.get("category")
        lbl = payload.get("label")    or inner.get("label")
        if cat:
            self.last_category = str(cat)
        if lbl:
            self.last_label = str(lbl)

        self._recompute()

    def _recompute(self) -> None:
        if not self._samples:
            return
        # Rolling averages
        avgs: dict[str, float] = {}
        for key in INSIGHT_FIELDS:
            vals = [s[key] for s in self._samples if key in s]
            if vals:
                avgs[key] = sum(vals) / len(vals)
        self.averages = avgs

        # Peak tracking
        rates = [s["Rate"] for s in self._samples if "Rate" in s]
        sizes = [s["Tot size"] for s in self._samples if "Tot size" in s]
        if rates:
            self.max_rate     = max(self.max_rate, max(rates))
        if sizes:
            self.max_tot_size = max(self.max_tot_size, max(sizes))

        # Protocol distribution over the window
        dist: dict[str, int] = {}
        for s in self._samples:
            if "Protocol Type" in s:
                pt   = int(s["Protocol Type"])
                name = PROTO_TYPE_NAMES.get(pt, f"Type-{pt}")
                dist[name] = dist.get(name, 0) + 1
        self.proto_dist = dist

    def format_text(self, ppm: float, total: int,
                    mqtt: int, amqp: int, coap: int,
                    failover: bool) -> str:
        """Return a multi-line string for the insights label widget."""
        lines: list[str] = [
            f" Total pkts   : {total}",
            f" Pkts/min     : {ppm:.1f}",
            f" via MQTT     : {mqtt}",
            f" via AMQP     : {amqp}",
            f" via CoAP     : {coap}",
            f" Failover     : {'YES' if failover else 'No'}",
            "",
        ]
        a = self.averages
        for key, (label, fmt) in INSIGHT_FIELDS.items():
            if key in a:
                lines.append(f" Avg {label:<10}: {fmt.format(a[key])}")
        if self.max_rate:
            lines.append(f" Peak Rate    : {self.max_rate:.2f} p/s")
        if self.max_tot_size:
            lines.append(f" Peak Size    : {self.max_tot_size:.0f} B")
        if self.proto_dist:
            lines.append("")
            lines.append(" Proto dist:")
            for name, cnt in sorted(self.proto_dist.items(), key=lambda x: -x[1]):
                lines.append(f"   {name:<8}: {cnt}")
        if self.last_category != "—":
            lines.append("")
            lines.append(f" Category     : {self.last_category}")
        return "\n".join(lines)


# =============================================================================
# SECTION 6 -- PUBLISHER STATE MODEL
# =============================================================================

class PublisherState:
    """
    Complete runtime state for one publisher. Mutated ONLY on the main thread.

    Failover detection
    ------------------
    self.primary_gateway is set once at init from PUBLISHER_PRIMARY_GATEWAY.
    Every ingest() call checks pkt.gateway against this primary:
      Match    -> we are on primary; clear any active failover flag
      Mismatch -> we are on secondary; set failover flag + message

    This correctly handles:
      * Initial packet (no "previous" state needed)
      * Automatic recovery when primary comes back online
      * Both directions: Node A -> Node B AND Node B -> Node A
    """

    def __init__(self, display_name: str, sender_id: str) -> None:
        self.display_name    = display_name
        self.sender_id       = sender_id
        self.primary_gateway = PUBLISHER_PRIMARY_GATEWAY.get(sender_id, NODE_A_LABEL)

        # Traffic counters
        self.total_packets: int = 0
        self.mqtt_packets:  int = 0
        self.amqp_packets:  int = 0
        self.coap_packets:  int = 0

        # Current routing state
        self.current_gateway:  Optional[str]      = None
        self.last_packet_time: Optional[datetime] = None
        self.last_protocol:    Optional[str]       = None

        # Failover state -- determined by primary_gateway comparison
        self.failover_active:  bool = False
        self.failover_message: str  = ""

        # Packets-per-minute: timestamps of last 120 packets (2-min buffer)
        self._ppm_times:    deque[float] = deque(maxlen=120)
        self.packets_per_min: float      = 0.0

        # Recent payload ring buffer
        self.recent_payloads: deque[str] = deque(maxlen=MAX_PAYLOAD_LINES)

        # Data insights
        self.insights = InsightsEngine()

    def ingest(self, pkt: IncomingPacket) -> None:
        """Process one packet. Must be called from the main Tkinter thread."""
        self.total_packets   += 1
        self.last_packet_time = pkt.received_at
        self.last_protocol    = pkt.protocol
        now_ts                = time.time()

        # Protocol counters
        if pkt.protocol == "MQTT":
            self.mqtt_packets += 1
        elif pkt.protocol == "AMQP":
            self.amqp_packets += 1
        elif pkt.protocol == "CoAP":
            self.coap_packets += 1

        # -- Correct failover detection -----------------------------------------
        # Compare this packet's gateway against the publisher's known primary.
        # This is the ground-truth check -- independent of session history.
        prev_gateway         = self.current_gateway
        self.current_gateway = pkt.gateway

        if pkt.gateway != self.primary_gateway:
            # Packet arrived on the non-primary gateway
            if not self.failover_active:
                # Transition: normal -> failover (first packet on secondary)
                self.failover_active  = True
                self.failover_message = (
                    f"FAILOVER DETECTED\n"
                    f"  Primary gateway ({self.primary_gateway}) appears offline.\n"
                    f"  Traffic rerouted to {pkt.gateway} via {pkt.protocol}."
                )
        else:
            # Packet arrived on the primary gateway
            if self.failover_active:
                # Transition: failover -> normal (primary came back)
                self.failover_active  = False
                self.failover_message = ""

        # Compact single-line payload entry with timestamp + protocol tag
        ts    = pkt.received_at.strftime("%H:%M:%S")
        short = json.dumps(pkt.raw_payload, separators=(",", ":"))
        if len(short) > 110:
            short = short[:107] + "..."
        self.recent_payloads.appendleft(f"[{ts}|{pkt.protocol[0]}] {short}")

        # Feed insights engine
        self.insights.feed(pkt.raw_payload)

        # Packets-per-minute (sliding 60 s window)
        self._ppm_times.append(now_ts)
        cutoff = now_ts - 60.0
        self.packets_per_min = sum(1 for t in self._ppm_times if t >= cutoff)


# =============================================================================
# SECTION 7 -- PUBLISHER CARD WIDGET
# =============================================================================

class PublisherCard(tk.Frame):
    """
    Self-contained card widget for one publisher.

    Layout
    ------
    +-- Header bar: [name] [primary hint] [id] ......... [PROTO] [GATEWAY] --+
    |  (Failover banner -- shown only when failover_active is True)          |
    |  Stats row: total | pkt/min | protocol | last seen | gw | counters ... |
    +-- Separator -------------------------------------------------------+  |
    |  RECENT PAYLOADS (Text box, 6 lines)     | DATA INSIGHTS (Label)   |  |
    +-- Bottom accent line ----------------------------------------------+--+

    update_display() is the ONLY public method. Always call from main thread.
    """

    def __init__(self, parent: tk.Widget, state: PublisherState) -> None:
        super().__init__(
            parent,
            bg=PALETTE["surface"],
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
        )
        self.state = state
        self._alert_packed = False
        self._build()
        self.update_display()

    # -- Construction ----------------------------------------------------------

    def _build(self) -> None:
        """Build all sub-widgets. Called once at card creation time."""

        # == Header bar ========================================================
        hdr = tk.Frame(self, bg="#1a2233", pady=7, padx=14)
        hdr.pack(fill="x")
        self._hdr_frame = hdr

        # Publisher display name (large, left-aligned)
        tk.Label(
            hdr,
            text=f"  {self.state.display_name.upper()}",
            font=FONT_BIG, fg=PALETTE["accent_blue"],
            bg="#1a2233", anchor="w",
        ).pack(side="left")

        # Primary gateway annotation (static hint)
        tk.Label(
            hdr,
            text=f"  primary:{self.state.primary_gateway}",
            font=FONT_SMALL, fg=PALETTE["text_dim"], bg="#1a2233",
        ).pack(side="left", padx=4)

        # sender_id (static, dimmed)
        tk.Label(
            hdr,
            text=f"  id:{self.state.sender_id}",
            font=FONT_SMALL, fg=PALETTE["text_muted"], bg="#1a2233",
        ).pack(side="left", padx=4)

        # Gateway badge (right-aligned, dynamic colour)
        self._gw_badge = tk.Label(
            hdr, text="-- WAITING --", font=FONT_TAG,
            fg="#fff", bg=PALETTE["text_dim"], padx=8, pady=2,
        )
        self._gw_badge.pack(side="right", padx=(6, 0))

        # Protocol badge (right-aligned, dynamic colour)
        self._proto_badge = tk.Label(
            hdr, text="--", font=FONT_TAG,
            fg="#fff", bg=PALETTE["text_dim"], padx=6, pady=2,
        )
        self._proto_badge.pack(side="right")

        # == Failover alert banner (hidden until failover_active) ==============
        self._alert_frame = tk.Frame(
            self, bg=PALETTE["tag_failover"], padx=14, pady=8
        )
        # NOTE: NOT packed here -- packed dynamically in update_display()

        self._alert_lbl = tk.Label(
            self._alert_frame,
            text="", font=FONT_HEADER,
            fg="#ffcccc", bg=PALETTE["tag_failover"],
            justify="left", anchor="w",
        )
        self._alert_lbl.pack(side="left", fill="x", expand=True)

        # == Stats row =========================================================
        stats = tk.Frame(self, bg=PALETTE["surface"], padx=14, pady=8)
        stats.pack(fill="x")

        def col(label: str, var: tk.StringVar, fg=PALETTE["text"]):
            """Helper: create a (label, value) column in the stats row."""
            c = tk.Frame(stats, bg=PALETTE["surface"])
            c.pack(side="left", padx=13)
            tk.Label(
                c, text=label, font=FONT_SMALL,
                fg=PALETTE["text_muted"], bg=PALETTE["surface"],
            ).pack(anchor="w")
            tk.Label(
                c, textvariable=var, font=FONT_HEADER,
                fg=fg, bg=PALETTE["surface"],
            ).pack(anchor="w")

        self._v_total = tk.StringVar(value="0")
        self._v_ppm   = tk.StringVar(value="0.0")
        self._v_proto = tk.StringVar(value="--")
        self._v_ts    = tk.StringVar(value="--")
        self._v_gw    = tk.StringVar(value="--")
        self._v_mqtt  = tk.StringVar(value="0")
        self._v_amqp  = tk.StringVar(value="0")
        self._v_coap  = tk.StringVar(value="0")
        self._v_rate  = tk.StringVar(value="--")
        self._v_size  = tk.StringVar(value="--")

        col("TOTAL PKTS",   self._v_total, PALETTE["accent_green"])
        col("PKT/MIN",      self._v_ppm,   PALETTE["accent_blue"])
        col("PROTOCOL",     self._v_proto)
        col("LAST SEEN",    self._v_ts)
        col("GATEWAY",      self._v_gw,    PALETTE["accent_blue"])
        col("via MQTT",     self._v_mqtt)
        col("via AMQP",     self._v_amqp)
        col("via CoAP",     self._v_coap,  PALETTE["accent_coap"])
        col("AVG RATE",     self._v_rate,  PALETTE["text_muted"])
        col("AVG TOT SIZE", self._v_size,  PALETTE["text_muted"])

        # == Separator =========================================================
        tk.Frame(self, bg=PALETTE["border"], height=1).pack(fill="x")

        # == Lower panel: payload viewer + insights ============================
        lower = tk.Frame(self, bg=PALETTE["surface"], padx=14, pady=8)
        lower.pack(fill="x")

        # Left: recent payloads (mono text box, read-only)
        pl = tk.Frame(lower, bg=PALETTE["surface"])
        pl.pack(side="left", fill="both", expand=True)
        tk.Label(
            pl, text="RECENT PAYLOADS", font=FONT_SMALL,
            fg=PALETTE["text_muted"], bg=PALETTE["surface"], anchor="w",
        ).pack(anchor="w")
        self._payload_box = tk.Text(
            pl, height=6, font=FONT_MONO,
            bg=PALETTE["surface2"], fg=PALETTE["accent_green"],
            insertbackground=PALETTE["accent_green"],
            selectbackground=PALETTE["border_hi"],
            relief="flat", wrap="none", state="disabled",
            cursor="arrow", borderwidth=0,
        )
        self._payload_box.pack(fill="x", pady=2)

        # Right: data insights panel
        ins = tk.Frame(lower, bg=PALETTE["surface2"], width=265, padx=10, pady=6)
        ins.pack(side="right", fill="y", padx=(14, 0))
        ins.pack_propagate(False)
        tk.Label(
            ins, text="DATA INSIGHTS", font=FONT_SMALL,
            fg=PALETTE["text_muted"], bg=PALETTE["surface2"],
        ).pack(anchor="w")
        self._insights_lbl = tk.Label(
            ins, text="", font=FONT_MONO,
            fg=PALETTE["text"], bg=PALETTE["surface2"],
            justify="left", anchor="nw",
        )
        self._insights_lbl.pack(fill="both", expand=True)

        # Bottom accent line
        tk.Frame(self, bg=PALETTE["accent_blue"], height=2).pack(
            fill="x", side="bottom"
        )

    # -- Update (main thread only) ---------------------------------------------

    def update_display(self) -> None:
        """Refresh every widget from self.state. Must be on main thread."""
        s = self.state

        # Stats StringVars
        self._v_total.set(str(s.total_packets))
        self._v_ppm.set(f"{s.packets_per_min:.1f}")
        self._v_proto.set(s.last_protocol or "--")
        self._v_gw.set(s.current_gateway  or "--")
        self._v_mqtt.set(str(s.mqtt_packets))
        self._v_amqp.set(str(s.amqp_packets))
        self._v_coap.set(str(s.coap_packets))
        if s.last_packet_time:
            self._v_ts.set(s.last_packet_time.strftime("%H:%M:%S"))

        # Rolling averages from insights engine
        a = s.insights.averages
        self._v_rate.set(f"{a['Rate']:.2f} p/s" if "Rate" in a else "--")
        self._v_size.set(f"{a['Tot size']:.0f} B" if "Tot size" in a else "--")

        # Gateway badge
        if s.current_gateway == NODE_A_LABEL:
            self._gw_badge.config(
                text=f"  {NODE_A_LABEL.upper()}  ",
                bg=PALETTE["tag_node_a"],
            )
        elif s.current_gateway == NODE_B_LABEL:
            self._gw_badge.config(
                text=f"  {NODE_B_LABEL.upper()}  ",
                bg=PALETTE["tag_node_b"],
            )
        else:
            self._gw_badge.config(text="-- WAITING --", bg=PALETTE["text_dim"])

        # Protocol badge
        _proto_bg = {
            "MQTT": PALETTE["accent_teal"],
            "AMQP": PALETTE["accent_orange"],
            "CoAP": PALETTE["accent_coap"],
        }
        self._proto_badge.config(
            text=s.last_protocol or "--",
            bg=_proto_bg.get(s.last_protocol, PALETTE["text_dim"]),
        )

        # Failover banner -- show/hide based on failover_active
        if s.failover_active:
            self._alert_lbl.config(text=f"  {s.failover_message}")
            if not self._alert_packed:
                # Insert after header (index 0 child = hdr)
                self._alert_frame.pack(fill="x", after=self._hdr_frame)
                self._alert_packed = True
            self.config(
                highlightbackground=PALETTE["accent_red"],
                highlightthickness=2,
            )
        else:
            if self._alert_packed:
                self._alert_frame.pack_forget()
                self._alert_packed = False
            self.config(
                highlightbackground=PALETTE["border"],
                highlightthickness=1,
            )

        # Payload text box
        self._payload_box.config(state="normal")
        self._payload_box.delete("1.0", "end")
        for line in s.recent_payloads:
            self._payload_box.insert("end", line + "\n")
        self._payload_box.config(state="disabled")

        # Insights label
        self._insights_lbl.config(text=s.insights.format_text(
            ppm=s.packets_per_min,
            total=s.total_packets,
            mqtt=s.mqtt_packets,
            amqp=s.amqp_packets,
            coap=s.coap_packets,
            failover=s.failover_active,
        ))


# =============================================================================
# SECTION 8 -- STATUS BAR  (6 connection indicators)
# =============================================================================

class StatusBar(tk.Frame):
    """
    Bottom bar with one indicator per listener (6 total).
    Colour coding: green=Connected/Observing, amber=Idle/Connecting, red=Error.
    """

    _KEYS = [
        (NODE_A_LABEL, "MQTT"),
        (NODE_A_LABEL, "AMQP"),
        (NODE_A_LABEL, "CoAP"),   # <- now present on both nodes
        (NODE_B_LABEL, "MQTT"),
        (NODE_B_LABEL, "AMQP"),
        (NODE_B_LABEL, "CoAP"),
    ]

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent, bg=PALETTE["sidebar"], pady=4)
        self._labels: dict[str, tk.Label] = {}

        for gateway, proto in self._KEYS:
            key = f"{gateway}/{proto}"
            box = tk.Frame(self, bg=PALETTE["sidebar"])
            box.pack(side="left", padx=7)
            tk.Label(
                box, text=f"{gateway} {proto}:", font=FONT_SMALL,
                fg=PALETTE["text_dim"], bg=PALETTE["sidebar"],
            ).pack(side="left")
            lbl = tk.Label(
                box, text="Idle", font=FONT_SMALL,
                fg=PALETTE["text_dim"], bg=PALETTE["sidebar"],
            )
            lbl.pack(side="left", padx=2)
            self._labels[key] = lbl

        self._pkt_var = tk.StringVar(value="Pkts: 0")
        tk.Label(
            self, textvariable=self._pkt_var, font=FONT_SMALL,
            fg=PALETTE["text_muted"], bg=PALETTE["sidebar"],
        ).pack(side="right", padx=12)

    def update_status(self, gateway: str, proto: str, status: str) -> None:
        lbl = self._labels.get(f"{gateway}/{proto}")
        if not lbl:
            return
        if status in ("Connected", "Observing"):
            colour = PALETTE["accent_green"]
        elif status in ("Idle", "Connecting..."):
            colour = PALETTE["accent_amber"]
        else:
            colour = PALETTE["accent_red"]
        lbl.config(text=status, fg=colour)

    def set_total(self, n: int) -> None:
        self._pkt_var.set(f"Pkts: {n:,}")


# =============================================================================
# SECTION 9 -- SIDEBAR  (publisher selector)
# =============================================================================

class Sidebar(tk.Frame):
    """
    Left panel: logo, per-publisher checkboxes annotated with [A]/[B] primary,
    custom sender_id entry, Apply button.
    """

    def __init__(self, parent: tk.Widget, on_apply) -> None:
        super().__init__(parent, bg=PALETTE["sidebar"], width=235, padx=14, pady=14)
        self.pack_propagate(False)
        self._on_apply  = on_apply
        self._checkvars: dict[str, tk.BooleanVar] = {}
        self._build()

    def _build(self) -> None:
        # Logo
        tk.Label(
            self, text="  IoT-IDS",
            font=("Courier New", 13, "bold"),
            fg=PALETTE["accent_blue"], bg=PALETTE["sidebar"],
        ).pack(anchor="w", pady=(0, 2))
        tk.Label(
            self, text="Subscriber Monitor  v3.0",
            font=FONT_SMALL, fg=PALETTE["text_muted"], bg=PALETTE["sidebar"],
        ).pack(anchor="w")

        tk.Frame(self, bg=PALETTE["border"], height=1).pack(fill="x", pady=10)

        tk.Label(
            self, text="MONITOR PUBLISHERS",
            font=FONT_SIDEBAR, fg=PALETTE["text_muted"], bg=PALETTE["sidebar"],
        ).pack(anchor="w", pady=(0, 6))

        # One checkbox per known publisher, labelled with [A] or [B] primary
        for display_name, sender_id in KNOWN_PUBLISHERS.items():
            var     = tk.BooleanVar(value=True)
            primary = PUBLISHER_PRIMARY_GATEWAY.get(sender_id, "?")
            tag     = "[A]" if primary == NODE_A_LABEL else "[B]"
            self._checkvars[display_name] = var
            tk.Checkbutton(
                self,
                text=f"{tag}  {display_name}",
                variable=var,
                font=FONT_BODY,
                fg=PALETTE["text"],
                bg=PALETTE["sidebar"],
                activebackground=PALETTE["sidebar"],
                activeforeground=PALETTE["accent_blue"],
                selectcolor=PALETTE["input_bg"],
                relief="flat",
                cursor="hand2",
            ).pack(anchor="w", pady=2)

        tk.Frame(self, bg=PALETTE["border"], height=1).pack(fill="x", pady=10)

        tk.Label(
            self, text="CUSTOM SENDER ID",
            font=FONT_SIDEBAR, fg=PALETTE["text_muted"], bg=PALETTE["sidebar"],
        ).pack(anchor="w", pady=(0, 4))

        self._custom = tk.Entry(
            self, font=FONT_BODY,
            bg=PALETTE["input_bg"], fg=PALETTE["text_dim"],
            insertbackground=PALETTE["accent_blue"],
            relief="flat", borderwidth=4,
        )
        self._custom.pack(fill="x", pady=(0, 4))
        _PH = "e.g. pi3-node-6"
        self._custom.insert(0, _PH)

        def fi(e):
            if self._custom.get() == _PH:
                self._custom.delete(0, "end")
                self._custom.config(fg=PALETTE["text"])

        def fo(e):
            if not self._custom.get():
                self._custom.insert(0, _PH)
                self._custom.config(fg=PALETTE["text_dim"])

        self._custom.bind("<FocusIn>",  fi)
        self._custom.bind("<FocusOut>", fo)

        tk.Frame(self, bg=PALETTE["sidebar"]).pack(expand=True, fill="y")  # spacer

        tk.Button(
            self,
            text="  APPLY FILTER",
            font=FONT_SIDEBAR,
            fg="#fff", bg=PALETTE["btn_primary"],
            activebackground=PALETTE["btn_hover"],
            activeforeground="#fff",
            relief="flat", cursor="hand2", pady=8,
            command=self._click,
        ).pack(fill="x", pady=4)

        tk.Label(
            self,
            text="[A] = Node A primary\n[B] = Node B primary",
            font=FONT_SMALL, fg=PALETTE["text_dim"],
            bg=PALETTE["sidebar"], justify="center",
        ).pack()

    def _click(self) -> None:
        selected = [n for n, v in self._checkvars.items() if v.get()]
        custom   = self._custom.get().strip()
        if custom and custom != "e.g. pi3-node-6":
            selected.append(f"__custom__{custom}")
        self._on_apply(selected)

    def default_selection(self) -> list[str]:
        return list(KNOWN_PUBLISHERS.keys())


# =============================================================================
# SECTION 10 -- MAIN APPLICATION
# =============================================================================

class SubscriberApp:
    """
    Wires together NetworkLayer, PublisherStates, PublisherCards,
    Sidebar, and StatusBar. Runs the root.after() dispatch loop.
    """

    def __init__(self) -> None:
        # Root window
        self.root = tk.Tk()
        self.root.title("IoT-IDS Subscriber Monitor v3.0")
        self.root.geometry("1400x880")
        self.root.minsize(1000, 640)
        self.root.configure(bg=PALETTE["bg"])

        # State tables keyed by sender_id
        self._states: dict[str, PublisherState] = {}
        self._cards:  dict[str, PublisherCard]  = {}
        self._display_to_id: dict[str, str]     = dict(KNOWN_PUBLISHERS)
        self._total_pkts = 0

        # Network layer
        self.network = NetworkLayer()

        # Build UI
        self._build_ui()

        # Start all 6 listener threads
        self.network.start_all()

        # Default: all 5 known publishers selected
        self._apply_filter(self.sidebar.default_selection())

        # Begin dispatch loop
        self._dispatch()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- UI construction -------------------------------------------------------

    def _build_ui(self) -> None:
        # Sidebar
        self.sidebar = Sidebar(self.root, on_apply=self._apply_filter)
        self.sidebar.pack(side="left", fill="y")
        tk.Frame(self.root, bg=PALETTE["border"], width=1).pack(side="left", fill="y")

        # Right panel
        right = tk.Frame(self.root, bg=PALETTE["bg"])
        right.pack(side="left", fill="both", expand=True)

        # Top bar
        topbar = tk.Frame(right, bg=PALETTE["sidebar"], pady=8, padx=14)
        topbar.pack(fill="x")
        tk.Label(
            topbar, text="LIVE TELEMETRY MONITOR",
            font=("Courier New", 11, "bold"),
            fg=PALETTE["text"], bg=PALETTE["sidebar"],
        ).pack(side="left")
        self._clock = tk.Label(
            topbar, text="", font=FONT_SMALL,
            fg=PALETTE["text_muted"], bg=PALETTE["sidebar"],
        )
        self._clock.pack(side="right")
        tk.Frame(right, bg=PALETTE["border"], height=1).pack(fill="x")

        # Scrollable card canvas
        wrap = tk.Frame(right, bg=PALETTE["bg"])
        wrap.pack(fill="both", expand=True)

        self._canvas = tk.Canvas(
            wrap, bg=PALETTE["bg"], highlightthickness=0, bd=0
        )
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self._container = tk.Frame(self._canvas, bg=PALETTE["bg"])
        self._cwin = self._canvas.create_window(
            (0, 0), window=self._container, anchor="nw"
        )
        self._container.bind(
            "<Configure>",
            lambda e: self._canvas.configure(
                scrollregion=self._canvas.bbox("all")
            ),
        )
        self._canvas.bind(
            "<Configure>",
            lambda e: self._canvas.itemconfig(self._cwin, width=e.width),
        )
        self._canvas.bind_all(
            "<MouseWheel>",
            lambda e: self._canvas.yview_scroll(int(-1 * e.delta / 120), "units"),
        )
        self._canvas.bind_all("<Button-4>",
            lambda e: self._canvas.yview_scroll(-1, "units"))
        self._canvas.bind_all("<Button-5>",
            lambda e: self._canvas.yview_scroll(1, "units"))

        # Status bar
        self.status_bar = StatusBar(right)
        self.status_bar.pack(fill="x", side="bottom")

    # -- Filter ----------------------------------------------------------------

    def _apply_filter(self, selected_names: list[str]) -> None:
        """Create/show cards for selected publishers; hide deselected ones."""
        active_ids: set[str] = set()

        for name in selected_names:
            if name.startswith("__custom__"):
                sid   = name[len("__custom__"):]
                dname = sid
                self._display_to_id[sid] = sid
            else:
                sid   = self._display_to_id.get(name)
                dname = name
            if not sid:
                continue
            active_ids.add(sid)
            if sid not in self._states:
                state = PublisherState(dname, sid)
                card  = PublisherCard(self._container, state)
                self._states[sid] = state
                self._cards[sid]  = card

        for sid, card in self._cards.items():
            if sid in active_ids:
                card.pack(fill="x", padx=12, pady=6)
            else:
                card.pack_forget()

    # -- Dispatch loop (main thread) -------------------------------------------

    def _dispatch(self) -> None:
        """
        Called every POLL_INTERVAL_MS via root.after().
        Drains up to 50 packets per tick; updates clock and status bar.
        """
        self._clock.config(text=datetime.now().strftime("  %Y-%m-%d  %H:%M:%S"))

        # Refresh all 6 connection indicators
        snap = self.network.get_status_snapshot()
        for gw, protos in snap.items():
            for proto, status in protos.items():
                self.status_bar.update_status(gw, proto, status)

        # Drain queue
        budget = 50
        while budget > 0:
            try:
                pkt: IncomingPacket = self.network.incoming_queue.get_nowait()
            except queue.Empty:
                break

            #print(f"[DEBUG] pkt sender_id={pkt.sender_id!r}, known={list(self._states.keys())}")
            budget -= 1
            self._total_pkts += 1
            sid = pkt.sender_id
            if sid in self._states:
                self._states[sid].ingest(pkt)
                self._cards[sid].update_display()
        
        self.status_bar.set_total(self._total_pkts)
        self.root.after(POLL_INTERVAL_MS, self._dispatch)

    # -- Shutdown --------------------------------------------------------------

    def _on_close(self) -> None:
        self.network.stop_all()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    app = SubscriberApp()
    app.run()


# =============================================================================
# AGENT PATCH NOTES
# =============================================================================
#
# BOTH agent_A.py and agent_B.py need these changes:
#
# 1. ADD CoAP to Node A's protocol list (protocol_listeners.py factory):
#    In agent_A.py start_ingestion_agent():
#      protocols = ["mqtt", "amqp", "coap"]   # was ["mqtt", "amqp"]
#
# 2. ADD MQTT + AMQP to Node B's protocol list (already has CoAP):
#    In agent_B.py start_ingestion_agent():
#      protocols = ["coap", "mqtt", "amqp"]   # add mqtt + amqp
#
# 3. ADD SafePacketObservableResource to BOTH agents:
#
#    class SafePacketObservableResource(aiocoap.resource.ObservableResource):
#        def __init__(self, loop):
#            super().__init__()
#            self._loop    = loop
#            self._payload = b"{}"
#
#        def notify(self, payload_bytes: bytes) -> None:
#            self._payload = payload_bytes
#            self._loop.call_soon_threadsafe(self.updated_state)
#
#        async def render_get(self, request):
#            return aiocoap.Message(payload=self._payload, content_format=50)
#
# 4. In _serve() on BOTH agents, register the observable resource:
#    site.add_resource(["iot", "telemetry", "safe"], _coap_safe_resource)
#
# 5. In start_detection_agent() SAFE branch on BOTH agents,
#    republish via all 3 protocols:
#      _mqtt_safe_pub.publish("iot/telemetry/safe", safe_bytes)
#      amqp_channel.basic_publish(..., routing_key="iot_telemetry_safe", body=safe_bytes)
#      if _coap_safe_resource: _coap_safe_resource.notify(safe_bytes)
#
# FAILOVER ROUTING SUMMARY:
#   Pi3 1-3  normally publish MQTT/AMQP to Node A.
#            On Node A failure, sensor script switches to Node B MQTT/AMQP.
#            GUI Node B MQTT/AMQP listeners catch these -- failover detected.
#
#   Pi3 4-5  normally publish CoAP to Node B.
#            On Node B failure, sensor_coap.py switches to Node A CoAP.
#            GUI Node A CoAP listener catches these -- failover detected.
#
#   PUBLISHER_PRIMARY_GATEWAY is the single source of truth for both cases.
#
# =============================================================================
