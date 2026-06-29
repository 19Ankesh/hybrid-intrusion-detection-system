"""Data router — alerts, logs, stats (Insider Threat Edition)"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List
from datetime import datetime, timedelta

from database import get_db
from db_models.db_models import Alert, Log
from schemas.schemas import AlertOut, LogOut, StatsResponse
from services.auth_service import get_current_user, require_admin
from services.ml_service import get_feature_importance

router = APIRouter()


@router.get("/alerts", response_model=List[AlertOut])
def get_alerts(
    skip: int = 0,
    limit: int = Query(100, le=500),
    severity: str = None,
    db: Session = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    q = db.query(Alert)
    if severity:
        q = q.filter(Alert.severity == severity)
    return q.order_by(Alert.timestamp.desc()).offset(skip).limit(limit).all()


@router.get("/logs", response_model=List[LogOut])
def get_logs(
    skip: int = 0,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    return db.query(Log).order_by(Log.timestamp.desc()).offset(skip).limit(limit).all()


@router.get("/stats", response_model=StatsResponse)
def get_stats(
    db: Session = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    alerts = db.query(Alert).all()

    if not alerts:
        return StatsResponse(
            total_alerts=0,
            total_anomalies=0,
            attack_distribution={},
            severity_counts={"Low": 0, "Medium": 0, "High": 0},
            hourly_timeline=[{"hour": f"{h:02d}:00", "count": 0} for h in range(24)],
            feature_importance=get_feature_importance(),
            anomaly_scores=[],
            risk_scores=[],
            department_breakdown={},
            top_risky_employees=[],
            last_updated=datetime.utcnow(),
        )

    total_alerts    = len(alerts)
    total_anomalies = sum(1 for a in alerts if a.anomaly_score < 0)

    attack_dist:   dict = {}
    severity_counts = {"Low": 0, "Medium": 0, "High": 0}
    dept_breakdown: dict = {}

    # Per-employee: track total risk score and alert count for leaderboard
    emp_risk: dict = {}   # employee_id -> {name, dept, total_risk, count}

    for a in alerts:
        attack_dist[a.attack_type] = attack_dist.get(a.attack_type, 0) + 1
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

        # Department breakdown (only for threat events)
        if a.attack_type != "BENIGN" and a.department:
            dept_breakdown[a.department] = dept_breakdown.get(a.department, 0) + 1

        # Top risky employees (average risk score, attacks only)
        if a.employee_id and a.attack_type != "BENIGN":
            if a.employee_id not in emp_risk:
                emp_risk[a.employee_id] = {
                    "employee_id":   a.employee_id,
                    "employee_name": a.employee_name or a.employee_id,
                    "department":    a.department or "Unknown",
                    "total_risk":    0.0,
                    "count":         0,
                }
            emp_risk[a.employee_id]["total_risk"] += a.risk_score
            emp_risk[a.employee_id]["count"]      += 1

    # Hourly timeline (last 24 hours)
    now    = datetime.utcnow()
    hourly = {}
    for i in range(24):
        h = (now - timedelta(hours=23 - i)).strftime("%H:00")
        hourly[h] = 0
    for a in alerts:
        if a.timestamp:
            h = a.timestamp.strftime("%H:00")
            if h in hourly:
                hourly[h] += 1
    hourly_timeline = [{"hour": k, "count": v} for k, v in hourly.items()]

    anomaly_scores = [round(a.anomaly_score, 4) for a in alerts[-200:]]
    risk_scores    = [round(a.risk_score, 2)    for a in alerts[-200:]]

    # Top 10 risky employees sorted by average risk score
    top_employees = sorted(
        [
            {
                "employee_id":   v["employee_id"],
                "employee_name": v["employee_name"],
                "department":    v["department"],
                "avg_risk":      round(v["total_risk"] / v["count"], 1),
                "incident_count": v["count"],
            }
            for v in emp_risk.values()
        ],
        key=lambda x: x["avg_risk"],
        reverse=True,
    )[:10]

    return StatsResponse(
        total_alerts=total_alerts,
        total_anomalies=total_anomalies,
        attack_distribution=attack_dist,
        severity_counts=severity_counts,
        hourly_timeline=hourly_timeline,
        feature_importance=get_feature_importance(),
        anomaly_scores=anomaly_scores,
        risk_scores=risk_scores,
        department_breakdown=dept_breakdown,
        top_risky_employees=top_employees,
        last_updated=datetime.utcnow(),
    )


@router.get("/metrics")
def get_metrics(_: dict = Depends(get_current_user)):
    import json, os
    path = os.path.join(os.path.dirname(__file__), "..", "models", "metrics.json")
    path = os.path.abspath(path)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    # Models not yet trained — return empty structure so dashboard shows "not available"
    return {
        "xgboost": {
            "accuracy": 0, "precision": 0, "recall": 0, "f1": 0,
            "confusion_matrix": [],
            "classes": ["BENIGN", "DATA_EXFILTRATION", "MALICIOUS_INSIDER",
                        "PRIVILEGE_ABUSE", "SABOTAGE"],
            "not_trained": True,
        },
        "isolation_forest": {
            "accuracy": 0, "precision": 0, "recall": 0, "f1": 0,
            "confusion_matrix": [],
            "classes": ["Normal", "Insider Threat"],
            "not_trained": True,
        },
    }
