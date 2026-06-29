"""
Real-Time Packet Capture Service
=================================
Sniffs live network traffic using Scapy, tracks flows by 5-tuple,
computes the same 20 CICIDS-2017 flow features the model was trained on,
runs inference, stores alerts, and broadcasts via WebSocket.

Environment variables:
  CAPTURE_INTERFACE   — network interface to sniff (default: auto-detect)
  CAPTURE_ENABLED     — "true"/"false" (default: true)
  FLOW_TIMEOUT        — seconds of inactivity before flushing a flow (default: 10)
  FLOW_MAX_PACKETS    — max packets per flow before early flush (default: 200)
"""

import os
import time
import math
import asyncio
import logging
import statistics
import threading
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger("capture")

# ── Config ────────────────────────────────────────────────────────────────────
CAPTURE_ENABLED   = os.getenv("CAPTURE_ENABLED", "true").lower() == "true"
_iface_env        = os.getenv("CAPTURE_INTERFACE", "").strip()
CAPTURE_INTERFACE = _iface_env if _iface_env else None   # None = Scapy auto-detect
FLOW_TIMEOUT      = int(os.getenv("FLOW_TIMEOUT", 10))     # seconds idle before flush
FLOW_MAX_PACKETS  = int(os.getenv("FLOW_MAX_PACKETS", 200))

# ── Flow key type: (src_ip, dst_ip, src_port, dst_port, protocol) ────────────
FlowKey = Tuple[str, str, int, int, str]


# ── Per-packet record inside a flow ──────────────────────────────────────────
class PacketRecord:
    __slots__ = ("length", "timestamp", "direction", "flags")

    def __init__(self, length: int, timestamp: float, direction: str, flags: int = 0):
        self.length    = length
        self.timestamp = timestamp
        self.direction = direction   # "fwd" or "bwd"
        self.flags     = flags


# ── Flow accumulator ─────────────────────────────────────────────────────────
class Flow:
    def __init__(self, key: FlowKey, first_ts: float):
        self.key      = key
        self.start_ts = first_ts
        self.last_ts  = first_ts
        self.packets: List[PacketRecord] = []

    def add(self, rec: PacketRecord):
        self.packets.append(rec)
        self.last_ts = rec.timestamp

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.last_ts) > FLOW_TIMEOUT

    @property
    def is_full(self) -> bool:
        return len(self.packets) >= FLOW_MAX_PACKETS


# ── Feature computation (CICIDS-2017 compatible) ──────────────────────────────

def _safe_stat(values, fn, default=0.0):
    try:
        return fn(values) if values else default
    except Exception:
        return default


def compute_flow_features(flow: Flow, dst_port: int) -> Dict[str, float]:
    """
    Compute the 20 CICIDS-2017 features from a completed Flow object.
    Returns a dict matching the model's expected feature names exactly.
    """
    pkts = flow.packets
    if not pkts:
        return {}

    duration_us = max((flow.last_ts - flow.start_ts) * 1_000_000, 1.0)

    fwd  = [p for p in pkts if p.direction == "fwd"]
    bwd  = [p for p in pkts if p.direction == "bwd"]

    fwd_lengths = [p.length for p in fwd]
    bwd_lengths = [p.length for p in bwd]

    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)
    total_bytes     = total_fwd_bytes + total_bwd_bytes

    # Inter-arrival times (IAT) for ALL packets
    timestamps = sorted(p.timestamp for p in pkts)
    iats = [(timestamps[i+1] - timestamps[i]) * 1e6
            for i in range(len(timestamps)-1)]   # in microseconds

    fwd_ts = sorted(p.timestamp for p in fwd)
    fwd_iats = [(fwd_ts[i+1] - fwd_ts[i]) * 1e6
                for i in range(len(fwd_ts)-1)]

    features = {
        "Destination Port":              float(dst_port),
        "Flow Duration":                 duration_us,

        "Total Fwd Packets":             float(len(fwd)),
        "Total Backward Packets":        float(len(bwd)),
        "Total Length of Fwd Packets":   float(total_fwd_bytes),
        "Total Length of Bwd Packets":   float(total_bwd_bytes),

        "Fwd Packet Length Max":         float(_safe_stat(fwd_lengths, max)),
        "Fwd Packet Length Min":         float(_safe_stat(fwd_lengths, min)),
        "Fwd Packet Length Mean":        float(_safe_stat(fwd_lengths, statistics.mean)),
        "Fwd Packet Length Std":         float(_safe_stat(fwd_lengths,
                                               lambda x: statistics.stdev(x) if len(x) > 1 else 0.0)),

        "Bwd Packet Length Max":         float(_safe_stat(bwd_lengths, max)),
        "Bwd Packet Length Min":         float(_safe_stat(bwd_lengths, min)),
        "Bwd Packet Length Mean":        float(_safe_stat(bwd_lengths, statistics.mean)),

        "Flow Bytes/s":                  total_bytes / (duration_us / 1e6),
        "Flow Packets/s":                len(pkts)   / (duration_us / 1e6),

        "Flow IAT Mean":                 float(_safe_stat(iats, statistics.mean)),
        "Flow IAT Std":                  float(_safe_stat(iats,
                                               lambda x: statistics.stdev(x) if len(x) > 1 else 0.0)),
        "Flow IAT Max":                  float(_safe_stat(iats, max)),
        "Flow IAT Min":                  float(_safe_stat(iats, min)),

        "Fwd IAT Total":                 float(sum(fwd_iats)),
    }

    # Clamp inf / nan to a large finite value so the model never receives NaN
    return {k: (v if math.isfinite(v) else 0.0) for k, v in features.items()}


# ── Shared event loop reference for cross-thread async calls ─────────────────
_loop: Optional[asyncio.AbstractEventLoop] = None


def _schedule_async(coro):
    """Schedule a coroutine on the main event loop from a background thread."""
    if _loop and not _loop.is_closed():
        asyncio.run_coroutine_threadsafe(coro, _loop)


# ── Alert handler (runs in background thread, schedules async DB write) ──────
def _handle_flow(flow: Flow, dst_port: int, src_ip: str, dst_ip: str):
    """Called when a flow is ready to be analyzed. Runs in capture thread."""
    features = compute_flow_features(flow, dst_port)
    if not features:
        return

    # Import here to avoid circular imports at module level
    from services.ml_service import predict
    try:
        anomaly_score, attack_type, risk_score, severity, is_anomaly, shap_vals = predict(features)
    except Exception as e:
        logger.warning(f"[capture] predict() failed: {e}")
        return

    _schedule_async(_store_and_broadcast(
        src_ip, dst_ip, dst_port, flow.key[4],
        features, anomaly_score, attack_type, risk_score, severity, is_anomaly, shap_vals,
    ))


async def _store_and_broadcast(
    src_ip, dst_ip, dst_port, protocol,
    features, anomaly_score, attack_type, risk_score, severity, is_anomaly, shap_vals
):
    """Async: persist to DB + broadcast over WebSocket."""
    from database import SessionLocal
    from db_models.db_models import Alert, FlowRecord
    from routers.ws import manager

    db = SessionLocal()
    try:
        alert = Alert(
            anomaly_score=anomaly_score,
            attack_type=attack_type,
            risk_score=risk_score,
            severity=severity,
            raw_features=features,
            shap_values=shap_vals,
        )
        db.add(alert)
        db.flush()   # get alert.id before adding FlowRecord

        flow_rec = FlowRecord(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=features.get("Destination Port", 0),   # approximation
            dst_port=dst_port,
            protocol=protocol,
            features=features,
            alert_id=alert.id,
        )
        db.add(flow_rec)
        db.commit()
        db.refresh(alert)

        logger.info(
            f"[capture] {src_ip} → {dst_ip}:{dst_port}  "
            f"{attack_type}  risk={risk_score:.1f}  sev={severity}"
        )

        # WebSocket broadcast — only push high/medium or all anomalies
        await manager.broadcast({
            "type": "new_alert",
            "payload": {
                "id":            alert.id,
                "src_ip":        src_ip,
                "dst_ip":        dst_ip,
                "dst_port":      dst_port,
                "attack_type":   attack_type,
                "anomaly_score": round(anomaly_score, 4),
                "risk_score":    round(risk_score, 2),
                "severity":      severity,
                "is_anomaly":    is_anomaly,
                "timestamp":     alert.timestamp.isoformat() if alert.timestamp else None,
            },
        })
    except Exception as e:
        db.rollback()
        logger.error(f"[capture] DB/broadcast error: {e}")
    finally:
        db.close()


# ── Flow Table (keyed by 5-tuple) ─────────────────────────────────────────────
class FlowTable:
    def __init__(self):
        self._flows: Dict[FlowKey, Flow] = {}
        self._lock  = threading.Lock()

    def process_packet(self, key: FlowKey, rec: PacketRecord, dst_port: int,
                       src_ip: str, dst_ip: str, force_flush: bool = False):
        with self._lock:
            if key not in self._flows:
                self._flows[key] = Flow(key, rec.timestamp)
            flow = self._flows[key]
            flow.add(rec)

            if flow.is_full or force_flush:
                self._flush(key, dst_port, src_ip, dst_ip)

    def flush_expired(self):
        with self._lock:
            expired_keys = [k for k, f in self._flows.items() if f.is_expired]
            for k in expired_keys:
                dst_port = k[3]
                src_ip   = k[0]
                dst_ip   = k[1]
                self._flush(k, dst_port, src_ip, dst_ip)

    def _flush(self, key: FlowKey, dst_port: int, src_ip: str, dst_ip: str):
        """Must be called with self._lock held."""
        flow = self._flows.pop(key, None)
        if flow and len(flow.packets) >= 2:    # skip trivially short flows
            threading.Thread(
                target=_handle_flow,
                args=(flow, dst_port, src_ip, dst_ip),
                daemon=True,
            ).start()

    @property
    def active_count(self) -> int:
        return len(self._flows)


# ── Global state (exposed so the /capture/status endpoint can read it) ────────
_flow_table       = FlowTable()
_packets_seen     = 0
_packets_lock     = threading.Lock()
_flows_flushed    = 0
_capture_running  = False
_capture_thread: Optional[threading.Thread] = None
_interface_used   = None


# ── Scapy packet handler ──────────────────────────────────────────────────────
def _on_pkt(pkt):
    global _packets_seen
    try:
        from scapy.layers.inet import IP, TCP, UDP

        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto  = "OTHER"
        sport  = 0
        dport  = 0
        flags  = 0
        length = len(pkt)

        if pkt.haslayer(TCP):
            t     = pkt[TCP]
            sport = t.sport
            dport = t.dport
            flags = int(t.flags)
            proto = "TCP"
        elif pkt.haslayer(UDP):
            u     = pkt[UDP]
            sport = u.sport
            dport = u.dport
            proto = "UDP"

        key = (src_ip, dst_ip, sport, dport, proto)

        rec = PacketRecord(
            length    = length,
            timestamp = time.time(),
            direction = "fwd",    # from capture perspective all pkts are fwd
            flags     = flags,
        )

        # FIN=0x01, RST=0x04 — flush immediately on TCP teardown
        is_fin_rst = proto == "TCP" and (flags & 0x01 or flags & 0x04)

        _packets_seen += 1
        _flow_table.process_packet(key, rec, dport, src_ip, dst_ip,
                                   force_flush=is_fin_rst)

    except Exception as e:
        logger.debug(f"[capture] pkt handler error: {e}")


# ── Expiry loop (runs in its own daemon thread) ───────────────────────────────
def _expiry_loop():
    while _capture_running:
        time.sleep(2)
        _flow_table.flush_expired()


# ── Main capture thread ───────────────────────────────────────────────────────
def _capture_loop(iface: Optional[str]):
    global _capture_running, _interface_used
    try:
        from scapy.all import sniff, conf

        # Choose interface
        if iface:
            _interface_used = iface
        else:
            _interface_used = conf.iface   # Scapy auto-detects

        logger.info(f"[capture] Starting live capture on interface: {_interface_used}")

        # BPF filter: only IP traffic (excludes ARP, broadcast noise)
        sniff(
            iface   = _interface_used,
            filter  = "ip",
            prn     = _on_pkt,
            store   = False,           # don't buffer in memory
            stop_filter = lambda _: not _capture_running,
        )
    except ImportError:
        logger.error("[capture] scapy not installed. Run: pip install scapy")
        _capture_running = False
    except PermissionError:
        logger.error("[capture] Permission denied. Run with sudo/admin or add NET_RAW capability.")
        _capture_running = False
    except Exception as e:
        logger.error(f"[capture] Fatal error: {e}")
        _capture_running = False


# ── Public API ────────────────────────────────────────────────────────────────
async def start_capture(loop: asyncio.AbstractEventLoop = None):
    """
    Start the capture service. Call once from lifespan startup.
    Accepts the running event loop so cross-thread async calls work safely.
    """
    global _capture_running, _capture_thread, _loop

    if not CAPTURE_ENABLED:
        logger.info("[capture] CAPTURE_ENABLED=false — live capture disabled.")
        return

    _loop = loop or asyncio.get_event_loop()
    _capture_running = True

    # Expiry thread
    threading.Thread(target=_expiry_loop, daemon=True, name="ids-expiry").start()

    # Capture thread
    _capture_thread = threading.Thread(
        target=_capture_loop,
        args=(CAPTURE_INTERFACE,),
        daemon=True,
        name="ids-capture",
    )
    _capture_thread.start()
    logger.info("[capture] Capture service started.")


def stop_capture():
    """Signal the capture thread to stop."""
    global _capture_running
    _capture_running = False
    logger.info("[capture] Capture service stopped.")


def get_capture_status() -> dict:
    """Return current capture statistics for the /capture/status endpoint."""
    return {
        "running":         _capture_running,
        "interface":       _interface_used,
        "packets_seen":    _packets_seen,
        "active_flows":    _flow_table.active_count,
        "capture_enabled": CAPTURE_ENABLED,
    }
