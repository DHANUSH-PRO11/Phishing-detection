"""
SQLAlchemy ORM Models for Persisted URL Scans.

Maintains complete historical records of submitted URLs, features,
explanations, model probability, and risk scores.
"""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    Index,
)
from backend.app.db.database import Base


class ScanRecord(Base):
    """Database entity storing historical URL scan results."""

    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()), nullable=False)
    url = Column(String(2048), nullable=False)
    normalized_url = Column(String(2048), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    
    # Prediction & Risk
    status = Column(String(64), nullable=False, index=True)
    is_phishing = Column(Boolean, nullable=False, default=False)
    is_inconclusive = Column(Boolean, nullable=False, default=False)
    risk_score = Column(Integer, nullable=False, index=True)
    risk_category = Column(String(32), nullable=False, index=True)
    model_probability = Column(Float, nullable=False)
    model_name = Column(String(128), nullable=False)

    # JSON Serialized Payload Components
    components_json = Column(Text, nullable=False)
    explanations_json = Column(Text, nullable=False)
    features_json = Column(Text, nullable=False)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )

    __table_args__ = (
        Index("idx_status_created", "status", "created_at"),
        Index("idx_risk_category_created", "risk_category", "created_at"),
    )
