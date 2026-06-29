"""Detection router — single + bulk CSV"""
import io, csv
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List

from database import get_db
from db_models.db_models import Alert, Log
from schemas.schemas import DetectRequest, DetectResponse
from services.auth_service import get_current_user
from services.ml_service import predict, DEMO_FEATURE_COLS

router = APIRouter()


def _store_alert(db, features, anomaly_score, attack_type, risk_score, severity, shap_vals):
    alert = Alert(
        anomaly_score=anomaly_score,
        attack_type=attack_type,
        risk_score=risk_score,
        severity=severity,
        raw_features=features,
        shap_values=shap_vals,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/", response_model=DetectResponse)
def detect_single(
    req: DetectRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    anomaly_score, attack_type, risk_score, severity, is_anomaly, shap_vals = predict(req.features)
    alert = _store_alert(db, req.features, anomaly_score, attack_type, risk_score, severity, shap_vals)

    db.add(Log(
        user_id=current_user.get("id"),
        action="DETECT",
        detail=f"attack={attack_type} risk={risk_score:.1f}",
    ))
    db.commit()

    return DetectResponse(
        alert_id=alert.id,
        anomaly_score=float(anomaly_score),
        attack_type=attack_type,
        risk_score=float(risk_score),
        severity=severity,
        is_anomaly=bool(is_anomaly),
        timestamp=alert.timestamp,
    )


@router.post("/upload-csv")
async def detect_bulk(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files accepted")

    content = await file.read()
    reader  = csv.DictReader(io.StringIO(content.decode("utf-8")))
    results = []

    for row in reader:
        try:
            features = {k.strip(): float(v) for k, v in row.items() if k.strip() in DEMO_FEATURE_COLS}
            if not features:
                continue
            anomaly_score, attack_type, risk_score, severity, is_anomaly, shap_vals = predict(features)
            alert = _store_alert(db, features, anomaly_score, attack_type, risk_score, severity, shap_vals)
            results.append({
                "alert_id": alert.id, "attack_type": attack_type,
                "risk_score": risk_score, "severity": severity, "is_anomaly": is_anomaly,
            })
        except Exception as e:
            results.append({"error": str(e), "row": dict(row)})

    db.add(Log(
        user_id=current_user.get("id"),
        action="BULK_UPLOAD",
        detail=f"Processed {len(results)} rows from {file.filename}",
    ))
    db.commit()

    return {"processed": len(results), "results": results}


# ── Simulation endpoints (Insider-Threat behaviour profiles) ──────────────────
# "Data Exfiltration" scenario: bulk file copy + heavy external email
EXFIL_FEATURES = {
    "logon_count_day":           4.0,
    "logon_after_hours":         2.0,
    "failed_logon_count":        0.0,
    "files_accessed_count":      220.0,
    "sensitive_files_count":     48.0,
    "usb_events_count":          6.0,
    "email_sent_external_count": 28.0,
    "email_attachment_mb":       110.0,
    "http_upload_mb":            750.0,
    "unique_systems_accessed":   3.0,
    "logon_hour_deviation":      2.5,
    "activity_duration_mins":    660.0,
    "print_jobs_count":          18.0,
    "clipboard_events_count":    145.0,
    "remote_access_mins":        12.0,
}

# "Privilege Abuse" scenario: many failed logins + lateral movement
PRIV_ABUSE_FEATURES = {
    "logon_count_day":           8.0,
    "logon_after_hours":         1.0,
    "failed_logon_count":        9.0,
    "files_accessed_count":      140.0,
    "sensitive_files_count":     65.0,
    "usb_events_count":          1.0,
    "email_sent_external_count": 6.0,
    "email_attachment_mb":       4.0,
    "http_upload_mb":            35.0,
    "unique_systems_accessed":   18.0,
    "logon_hour_deviation":      3.5,
    "activity_duration_mins":    540.0,
    "print_jobs_count":          4.0,
    "clipboard_events_count":    45.0,
    "remote_access_mins":        90.0,
}


@router.post("/simulate-dos", response_model=DetectResponse)
def simulate_dos(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Simulate a Data Exfiltration insider threat event."""
    anomaly_score, attack_type, risk_score, severity, is_anomaly, shap_vals = predict(EXFIL_FEATURES)
    alert = _store_alert(db, EXFIL_FEATURES, anomaly_score, attack_type, risk_score, severity, shap_vals)
    db.add(Log(user_id=current_user.get("id"), action="SIMULATE_EXFIL", detail="Data Exfiltration simulation triggered"))
    db.commit()
    return DetectResponse(
        alert_id=alert.id, anomaly_score=float(anomaly_score),
        attack_type=attack_type, risk_score=float(risk_score),
        severity=severity, is_anomaly=bool(is_anomaly), timestamp=alert.timestamp,
    )


@router.post("/simulate-anomaly", response_model=DetectResponse)
def simulate_anomaly(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Simulate a Privilege Abuse insider threat event."""
    anomaly_score, attack_type, risk_score, severity, is_anomaly, shap_vals = predict(PRIV_ABUSE_FEATURES)
    alert = _store_alert(db, PRIV_ABUSE_FEATURES, anomaly_score, attack_type, risk_score, severity, shap_vals)
    db.add(Log(user_id=current_user.get("id"), action="SIMULATE_PRIV_ABUSE", detail="Privilege Abuse simulation triggered"))
    db.commit()
    return DetectResponse(
        alert_id=alert.id, anomaly_score=float(anomaly_score),
        attack_type=attack_type, risk_score=float(risk_score),
        severity=severity, is_anomaly=bool(is_anomaly), timestamp=alert.timestamp,
    )
