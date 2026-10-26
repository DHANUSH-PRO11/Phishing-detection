"""
Database CRUD and Real Aggregate Analytics.

Handles persistence, retrieval, filtering, pagination, deletion, and
dynamic statistical aggregations computed from real stored scan records.
"""

from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import func, desc, asc, case
from sqlalchemy.orm import Session

from backend.app.db.models import ScanRecord
from backend.app.schemas.scan import ScanResponse


def create_scan_record(db: Session, scan: ScanResponse) -> ScanRecord:
    """Persists a new URL scan result to the database."""
    record = ScanRecord(
        scan_id=str(uuid.uuid4()),
        url=scan.url,
        normalized_url=scan.normalized_url,
        domain=scan.components.domain or scan.components.netloc,
        status=scan.status,
        is_phishing=scan.is_phishing,
        is_inconclusive=scan.is_inconclusive,
        risk_score=scan.risk.final_risk_score,
        risk_category=scan.risk.risk_category,
        model_probability=scan.risk.model_probability,
        model_name=scan.model_name,
        components_json=json.dumps(scan.components.model_dump()),
        explanations_json=json.dumps([e.model_dump() for e in scan.explanations]),
        features_json=json.dumps(scan.features),
        created_at=datetime.now(timezone.utc),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_scan_by_id(db: Session, scan_id: str) -> Optional[ScanRecord]:
    """Finds an individual scan record by its unique UUID scan_id."""
    return db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()


def list_scans(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    search: Optional[str] = None,
    status: Optional[str] = None,
    risk_category: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> Tuple[List[ScanRecord], int]:
    """
    Returns filtered, searched, paginated scan history and total count.
    """
    query = db.query(ScanRecord)

    # 1. Search filter across URL, domain
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            (ScanRecord.url.ilike(search_term)) |
            (ScanRecord.domain.ilike(search_term))
        )

    # 2. Status filter
    if status:
        query = query.filter(ScanRecord.status == status)

    # 3. Risk Category filter
    if risk_category:
        query = query.filter(ScanRecord.risk_category == risk_category)

    total_count = query.count()

    # 4. Sorting with strict column whitelisting (prevents reflection/injection exceptions)
    allowed_columns = {
        "created_at": ScanRecord.created_at,
        "risk_score": ScanRecord.risk_score,
        "url": ScanRecord.url,
        "domain": ScanRecord.domain,
        "status": ScanRecord.status,
        "risk_category": ScanRecord.risk_category,
        "model_probability": ScanRecord.model_probability,
    }
    sort_column = allowed_columns.get(str(sort_by).lower(), ScanRecord.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(asc(sort_column))
    else:
        query = query.order_by(desc(sort_column))

    records = query.offset(skip).limit(limit).all()
    return records, total_count


def delete_scan_by_id(db: Session, scan_id: str) -> bool:
    """Deletes a scan record by its scan_id."""
    record = get_scan_by_id(db, scan_id)
    if not record:
        return False
    db.delete(record)
    db.commit()
    return True


def get_aggregate_statistics(db: Session) -> Dict[str, Any]:
    """
    Computes real aggregate statistics directly from persisted records.
    Never uses hardcoded or fabricated statistics.
    """
    summary = (
        db.query(
            func.count(ScanRecord.id).label("total"),
            func.coalesce(func.sum(case((ScanRecord.is_phishing == True, 1), else_=0)), 0).label("phishing"),
            func.coalesce(func.sum(case((ScanRecord.is_inconclusive == True, 1), else_=0)), 0).label("inconclusive"),
            func.coalesce(func.avg(ScanRecord.risk_score), 0.0).label("avg_risk"),
        )
        .first()
    )

    total_scans = int(summary.total or 0) if summary else 0

    if total_scans == 0:
        return {
            "total_scans": 0,
            "phishing_detected_count": 0,
            "legitimate_count": 0,
            "inconclusive_count": 0,
            "average_risk_score": 0.0,
            "status_distribution": {},
            "risk_category_distribution": {},
            "recent_scans_timeline": [],
            "top_flagged_domains": [],
        }

    phishing_count = int(summary.phishing or 0)
    inconclusive_count = int(summary.inconclusive or 0)
    legitimate_count = max(0, total_scans - phishing_count - inconclusive_count)
    avg_risk = float(summary.avg_risk or 0.0)

    # Status distribution
    status_counts = (
        db.query(ScanRecord.status, func.count(ScanRecord.id))
        .group_by(ScanRecord.status)
        .all()
    )
    status_dist = {status: count for status, count in status_counts}

    # Risk category distribution
    cat_counts = (
        db.query(ScanRecord.risk_category, func.count(ScanRecord.id))
        .group_by(ScanRecord.risk_category)
        .all()
    )
    cat_dist = {cat: count for cat, count in cat_counts}

    # Top high-risk domains
    top_flagged = (
        db.query(ScanRecord.domain, func.count(ScanRecord.id).label("count"))
        .filter(ScanRecord.is_phishing == True)
        .group_by(ScanRecord.domain)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )
    top_domains = [{"domain": d, "count": c} for d, c in top_flagged if d]

    # Recent scans timeline (last 10 scans)
    recent = (
        db.query(ScanRecord)
        .order_by(desc(ScanRecord.created_at))
        .limit(10)
        .all()
    )
    timeline = [
        {
            "scan_id": r.scan_id,
            "domain": r.domain,
            "status": r.status,
            "risk_score": r.risk_score,
            "timestamp": r.created_at.isoformat() if r.created_at else None,
        }
        for r in recent
    ]

    return {
        "total_scans": total_scans,
        "phishing_detected_count": phishing_count,
        "legitimate_count": max(0, legitimate_count),
        "inconclusive_count": inconclusive_count,
        "average_risk_score": round(float(avg_risk), 2),
        "status_distribution": status_dist,
        "risk_category_distribution": cat_dist,
        "recent_scans_timeline": timeline,
        "top_flagged_domains": top_domains,
    }
