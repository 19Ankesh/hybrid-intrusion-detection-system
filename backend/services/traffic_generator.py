"""
Insider Threat — Autonomous Behaviour Simulator
================================================
Replaces the network-flow traffic generator with a user-behaviour simulator
that mimics the kind of activity logged by a CERT/UEBA system.

Generates realistic employee activity records (one "session" per tick) and
runs them through the actual XGBoost + Isolation Forest pipeline.

Environment variables:
  TRAFFIC_GEN_ENABLED  — "true"/"false"   (default: true)
  TRAFFIC_GEN_INTERVAL — seconds between ticks  (default: 2)
  TRAFFIC_GEN_BURST    — sessions per tick       (default: 2)
"""

import os, math, time, random, asyncio, logging, threading
from datetime import datetime, timezone
from typing import Dict, Tuple

logger = logging.getLogger("traffic_gen")

GEN_ENABLED  = os.getenv("TRAFFIC_GEN_ENABLED",  "true").lower() == "true"
GEN_INTERVAL = float(os.getenv("TRAFFIC_GEN_INTERVAL", "2"))
GEN_BURST    = int(os.getenv("TRAFFIC_GEN_BURST", "2"))

_running = False
_loop: asyncio.AbstractEventLoop = None

# ── Employee roster (stable identities) ───────────────────────────────────────
EMPLOYEES = [
    {"id": "EMP001", "name": "Alice Johnson",    "dept": "Finance"},
    {"id": "EMP002", "name": "Bob Martinez",     "dept": "Engineering"},
    {"id": "EMP003", "name": "Carol Lee",        "dept": "HR"},
    {"id": "EMP004", "name": "David Kim",        "dept": "IT Admin"},
    {"id": "EMP005", "name": "Eva Patel",        "dept": "Legal"},
    {"id": "EMP006", "name": "Frank Osei",       "dept": "Sales"},
    {"id": "EMP007", "name": "Grace Chen",       "dept": "Finance"},
    {"id": "EMP008", "name": "Hank Williams",    "dept": "Engineering"},
    {"id": "EMP009", "name": "Iris Nakamura",    "dept": "Marketing"},
    {"id": "EMP010", "name": "Jake Thompson",    "dept": "IT Admin"},
    {"id": "EMP011", "name": "Karen Obi",        "dept": "Legal"},
    {"id": "EMP012", "name": "Leo Fernandez",    "dept": "Sales"},
    {"id": "EMP013", "name": "Mia Johansson",    "dept": "HR"},
    {"id": "EMP014", "name": "Nate Gupta",       "dept": "Finance"},
    {"id": "EMP015", "name": "Olivia Brown",     "dept": "Engineering"},
]

# ── Behaviour profiles (mean, std) per feature ────────────────────────────────
PROFILES = {
    # ── Normal employee ────────────────────────────────────────────────────────
    "BENIGN": {
        "weight": 60,
        "features": {
            "logon_count_day":           (3,    1),
            "logon_after_hours":         (0,    0.3),
            "failed_logon_count":        (0.2,  0.5),
            "files_accessed_count":      (25,   12),
            "sensitive_files_count":     (1,    1),
            "usb_events_count":          (0.1,  0.3),
            "email_sent_external_count": (2,    2),
            "email_attachment_mb":       (0.5,  0.8),
            "http_upload_mb":            (10,   8),
            "unique_systems_accessed":   (2,    1),
            "logon_hour_deviation":      (0.5,  0.4),
            "activity_duration_mins":    (420,  60),
            "print_jobs_count":          (1,    1),
            "clipboard_events_count":    (5,    4),
            "remote_access_mins":        (0,    5),
        },
    },
    # ── Data Exfiltration ─────────────────────────────────────────────────────
    "DATA_EXFILTRATION": {
        "weight": 12,
        "features": {
            "logon_count_day":           (4,    2),
            "logon_after_hours":         (2,    1),
            "failed_logon_count":        (0.3,  0.5),
            "files_accessed_count":      (180,  60),
            "sensitive_files_count":     (35,   15),
            "usb_events_count":          (4,    2),
            "email_sent_external_count": (20,   8),
            "email_attachment_mb":       (80,   30),
            "http_upload_mb":            (500,  200),
            "unique_systems_accessed":   (3,    2),
            "logon_hour_deviation":      (2,    1),
            "activity_duration_mins":    (600,  80),
            "print_jobs_count":          (15,   8),
            "clipboard_events_count":    (120,  50),
            "remote_access_mins":        (10,   15),
        },
    },
    # ── Privilege Abuse ───────────────────────────────────────────────────────
    "PRIVILEGE_ABUSE": {
        "weight": 10,
        "features": {
            "logon_count_day":           (6,    2),
            "logon_after_hours":         (1,    1),
            "failed_logon_count":        (5,    3),
            "files_accessed_count":      (120,  50),
            "sensitive_files_count":     (50,   20),
            "usb_events_count":          (1,    1),
            "email_sent_external_count": (5,    4),
            "email_attachment_mb":       (5,    5),
            "http_upload_mb":            (30,   20),
            "unique_systems_accessed":   (12,   5),
            "logon_hour_deviation":      (3,    1.5),
            "activity_duration_mins":    (500,  100),
            "print_jobs_count":          (3,    3),
            "clipboard_events_count":    (30,   20),
            "remote_access_mins":        (60,   40),
        },
    },
    # ── Sabotage ──────────────────────────────────────────────────────────────
    "SABOTAGE": {
        "weight": 9,
        "features": {
            "logon_count_day":           (2,    1),
            "logon_after_hours":         (3,    1),
            "failed_logon_count":        (1,    1),
            "files_accessed_count":      (60,   30),
            "sensitive_files_count":     (20,   10),
            "usb_events_count":          (2,    1),
            "email_sent_external_count": (3,    3),
            "email_attachment_mb":       (3,    4),
            "http_upload_mb":            (20,   15),
            "unique_systems_accessed":   (8,    4),
            "logon_hour_deviation":      (4,    2),
            "activity_duration_mins":    (240,  80),
            "print_jobs_count":          (2,    2),
            "clipboard_events_count":    (20,   15),
            "remote_access_mins":        (120,  60),
        },
    },
    # ── Malicious Insider ─────────────────────────────────────────────────────
    "MALICIOUS_INSIDER": {
        "weight": 9,
        "features": {
            "logon_count_day":           (8,    3),
            "logon_after_hours":         (4,    2),
            "failed_logon_count":        (3,    2),
            "files_accessed_count":      (300,  100),
            "sensitive_files_count":     (80,   30),
            "usb_events_count":          (6,    3),
            "email_sent_external_count": (30,   12),
            "email_attachment_mb":       (120,  50),
            "http_upload_mb":            (800,  300),
            "unique_systems_accessed":   (18,   6),
            "logon_hour_deviation":      (5,    2),
            "activity_duration_mins":    (700,  100),
            "print_jobs_count":          (25,   10),
            "clipboard_events_count":    (200,  80),
            "remote_access_mins":        (180,  80),
        },
    },
}

_NAMES   = list(PROFILES.keys())
_WEIGHTS = [PROFILES[k]["weight"] for k in _NAMES]


def _sample(mean: float, std: float) -> float:
    if std == 0:
        return max(0.0, mean)
    return max(0.0, random.gauss(mean, std))


def generate_session() -> Tuple[Dict[str, float], str, Dict]:
    """
    Returns (features_dict, profile_name, employee_info).
    """
    profile_name = random.choices(_NAMES, weights=_WEIGHTS, k=1)[0]
    profile      = PROFILES[profile_name]
    employee     = random.choice(EMPLOYEES)

    features: Dict[str, float] = {}
    for feat, (mean, std) in profile["features"].items():
        features[feat] = round(_sample(mean, std), 4)

    return features, profile_name, employee


# ── Shared loop ───────────────────────────────────────────────────────────────
def _schedule(coro):
    if _loop and not _loop.is_closed():
        asyncio.run_coroutine_threadsafe(coro, _loop)


# ── Persist + broadcast one session ──────────────────────────────────────────
async def _process_session(features, profile_name, employee):
    from services.ml_service import predict
    from database import SessionLocal
    from db_models.db_models import Alert, FlowRecord
    from routers.ws import manager

    try:
        anomaly_score, attack_type, risk_score, severity, is_anomaly, shap_vals = predict(features)
    except Exception as e:
        logger.warning(f"[traffic_gen] predict() failed: {e}")
        return

    db = SessionLocal()
    try:
        alert = Alert(
            anomaly_score = anomaly_score,
            attack_type   = attack_type,
            risk_score    = risk_score,
            severity      = severity,
            raw_features  = features,
            shap_values   = shap_vals,
            employee_id   = employee["id"],
            employee_name = employee["name"],
            department    = employee["dept"],
        )
        db.add(alert)
        db.flush()

        # Store behaviour log as a "flow" record (keeps DB schema intact)
        flow_rec = FlowRecord(
            src_ip    = employee["id"],          # reuse field for employee ID
            dst_ip    = employee["dept"],         # reuse field for department
            src_port  = 0,
            dst_port  = 0,
            protocol  = "USER_SESSION",
            features  = features,
            alert_id  = alert.id,
        )
        db.add(flow_rec)
        db.commit()
        db.refresh(alert)

        logger.info(
            f"[traffic_gen] {employee['name']} ({employee['dept']})  "
            f"profile={profile_name}  classified={attack_type}  "
            f"risk={risk_score:.1f}  sev={severity}"
        )

        await manager.broadcast({
            "type": "new_alert",
            "payload": {
                "id":            alert.id,
                "employee_id":   employee["id"],
                "employee_name": employee["name"],
                "department":    employee["dept"],
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
        logger.error(f"[traffic_gen] DB/broadcast error: {e}")
    finally:
        db.close()


# ── Background thread ─────────────────────────────────────────────────────────
def _gen_loop():
    logger.info(f"[traffic_gen] Starting — interval={GEN_INTERVAL}s  burst={GEN_BURST}")
    while _running:
        try:
            for _ in range(GEN_BURST):
                features, profile_name, employee = generate_session()
                _schedule(_process_session(features, profile_name, employee))
        except Exception as e:
            logger.error(f"[traffic_gen] Loop error: {e}")
        time.sleep(GEN_INTERVAL)
    logger.info("[traffic_gen] Stopped.")


# ── Public API ────────────────────────────────────────────────────────────────
async def start_traffic_gen(loop: asyncio.AbstractEventLoop = None):
    global _running, _loop
    if not GEN_ENABLED:
        logger.info("[traffic_gen] TRAFFIC_GEN_ENABLED=false — disabled.")
        return
    _loop    = loop or asyncio.get_event_loop()
    _running = True
    threading.Thread(target=_gen_loop, daemon=True, name="ids-traffic-gen").start()
    logger.info("[traffic_gen] Insider-threat behaviour simulator started.")


def stop_traffic_gen():
    global _running
    _running = False
