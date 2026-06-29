"""SQLAlchemy ORM Models"""
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, ForeignKey, Enum, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from database import Base


class UserRole(str, enum.Enum):
    admin   = "admin"
    analyst = "analyst"


class User(Base):
    __tablename__ = "users"

    id       = Column(Integer, primary_key=True, index=True)
    username = Column(String(50),  unique=True, index=True, nullable=False)
    email    = Column(String(120), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)
    role     = Column(Enum(UserRole), default=UserRole.analyst, nullable=False)
    created  = Column(DateTime(timezone=True), server_default=func.now())

    logs = relationship("Log", back_populates="user_rel")


class Alert(Base):
    __tablename__ = "alerts"

    id             = Column(Integer, primary_key=True, index=True)
    anomaly_score  = Column(Float, nullable=False)
    attack_type    = Column(String(100), nullable=False, default="BENIGN")
    risk_score     = Column(Float, nullable=False)
    severity       = Column(String(20), nullable=False, default="Low")   # Low/Medium/High
    raw_features   = Column(JSON)          # original input features
    shap_values    = Column(JSON)          # SHAP explanation payload
    timestamp      = Column(DateTime(timezone=True), server_default=func.now())
    # ── Insider threat identity fields ────────────────────────────────────────
    employee_id    = Column(String(20),  nullable=True, index=True)   # e.g. "EMP001"
    employee_name  = Column(String(100), nullable=True)               # e.g. "Alice Johnson"
    department     = Column(String(80),  nullable=True, index=True)   # e.g. "Finance"


class Log(Base):
    __tablename__ = "logs"

    id        = Column(Integer, primary_key=True, index=True)
    user_id   = Column(Integer, ForeignKey("users.id"), nullable=True)
    action    = Column(String(255), nullable=False)
    detail    = Column(String(500))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    user_rel  = relationship("User", back_populates="logs")


class FlowRecord(Base):
    """
    Raw network flow captured in real time.
    Each FlowRecord may produce at most one Alert (nullable FK).
    Provides forensic traceability: alert → flow → src/dst.
    """
    __tablename__ = "flows"

    id        = Column(Integer, primary_key=True, index=True)
    src_ip    = Column(String(45), nullable=False, index=True)
    dst_ip    = Column(String(45), nullable=False, index=True)
    src_port  = Column(Integer,   nullable=False)
    dst_port  = Column(Integer,   nullable=False)
    protocol  = Column(String(20), nullable=False, default="TCP")
    features  = Column(JSON)                                # 20 CICIDS features
    alert_id  = Column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    alert = relationship("Alert", backref="flow_records")
