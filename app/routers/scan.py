from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import ScanListItem, ScanRequest, ScanResult, ScanStats
from app.services.detection_engine import analyze_message

router = APIRouter(prefix="/scans", tags=["Phishing Detection"])


@router.post("/analyze", response_model=ScanResult, status_code=status.HTTP_201_CREATED)
def analyze_scan(
    payload: ScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Run phishing analysis on submitted content.

    - Runs 4-category detection engine (links, urgency, impersonation, credentials)
    - Classifies as SAFE / SUSPICIOUS / DANGEROUS
    - Persists result to database (multi-tenant: tied to current user)
    - Returns full analysis with indicators and recommendation

    Future: queue AI/LLM analysis as background task here.
    """
    analysis = analyze_message(payload.content)

    scan = Scan(
        user_id=current_user.id,
        content=payload.content,
        content_preview=payload.content[:200],
        risk_level=analysis["risk_level"],
        risk_score=analysis["risk_score"],
        detection_results=analysis["detection_results"],
        flagged_categories=analysis["flagged_categories"],
        scan_duration_ms=analysis["scan_duration_ms"],
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:200],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    return ScanResult(
        id=scan.id,
        risk_level=scan.risk_level,
        risk_score=scan.risk_score,
        flagged_categories=scan.flagged_categories or [],
        detection_results=scan.detection_results or {},
        content_preview=scan.content_preview,
        scan_duration_ms=scan.scan_duration_ms or 0,
        created_at=scan.created_at,
        recommendation=analysis["recommendation"],
        platform=analysis.get("platform"),
    )


@router.get("/", response_model=List[ScanListItem])
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    risk_level: Optional[str] = Query(None, pattern="^(SAFE|SUSPICIOUS|DANGEROUS)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List scan history for the current user.
    - Multi-tenant: only returns scans belonging to current_user
    - Supports pagination (skip/limit) and risk_level filter
    """
    query = db.query(Scan).filter(Scan.user_id == current_user.id)
    if risk_level:
        query = query.filter(Scan.risk_level == risk_level)
    scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    return [
        ScanListItem(
            id=s.id,
            risk_level=s.risk_level,
            risk_score=s.risk_score,
            flagged_categories=s.flagged_categories or [],
            content_preview=s.content_preview or "",
            created_at=s.created_at,
        )
        for s in scans
    ]


@router.get("/stats", response_model=ScanStats)
def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Aggregate scan statistics for the current user.
    Returns counts by risk level, threat type breakdown, and risk distribution %.
    """
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).all()
    total = len(scans)

    counts = {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 0}
    threat_breakdown = {
        "Suspicious Links": 0,
        "Urgency Language": 0,
        "Impersonation Attempt": 0,
        "Credential Harvesting": 0,
    }

    for scan in scans:
        counts[scan.risk_level] = counts.get(scan.risk_level, 0) + 1
        for cat in (scan.flagged_categories or []):
            if cat in threat_breakdown:
                threat_breakdown[cat] += 1

    risk_distribution = {
        k: round(v / total * 100, 1) if total > 0 else 0.0
        for k, v in counts.items()
    }

    return ScanStats(
        total=total,
        safe=counts["SAFE"],
        suspicious=counts["SUSPICIOUS"],
        dangerous=counts["DANGEROUS"],
        threat_breakdown=threat_breakdown,
        risk_distribution=risk_distribution,
    )


@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve a single scan result by ID.
    Enforces ownership — users can only retrieve their own scans.
    """
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    from app.services.detection_engine import build_recommendation
    recommendation = build_recommendation(scan.risk_level, scan.flagged_categories or [])

    return ScanResult(
        id=scan.id,
        risk_level=scan.risk_level,
        risk_score=scan.risk_score,
        flagged_categories=scan.flagged_categories or [],
        detection_results=scan.detection_results or {},
        content_preview=scan.content_preview or "",
        scan_duration_ms=scan.scan_duration_ms or 0,
        created_at=scan.created_at,
        recommendation=recommendation,
    )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a scan. Only the owning user can delete their scans."""
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


@router.delete("/", status_code=status.HTTP_204_NO_CONTENT)
def delete_all_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete ALL scans for the current user."""
    db.query(Scan).filter(Scan.user_id == current_user.id).delete()
    db.commit()