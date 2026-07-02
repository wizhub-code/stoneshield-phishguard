"""
Email Scanning Router
Pro & Enterprise plan feature.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.email_scan import EmailScan
from app.models.user import User
from app.models.subscription import Subscription, PLANS
from app.schemas.email_scan import EmailScanRequest, EmailScanResult, EmailScanListItem
from app.services.email_engine import analyze_email

router = APIRouter(prefix="/email-scans", tags=["Email Scanning"])


def check_email_access(user: User, db: Session):
    """Verify user has a plan that includes email scanning."""
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    plan_name = sub.plan if sub else user.plan
    plan = PLANS.get(plan_name, PLANS["free"])
    if not plan["email_scanning"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Email scanning requires Pro or Enterprise plan",
                "current_plan": plan_name,
                "upgrade_url": "/api/v1/subscriptions/plans",
            }
        )
    return sub


@router.post("/analyze", response_model=EmailScanResult, status_code=status.HTTP_201_CREATED)
def analyze_email_endpoint(
    payload: EmailScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Analyze an email for phishing threats.

    Supports:
    - Raw email paste (headers + body)
    - Structured input (sender, subject, body separately)

    Detects:
    - All standard phishing patterns
    - Spoofed sender addresses
    - Lookalike domains
    - Reply-to mismatches
    - Suspicious subject lines
    - Free email impersonation

    Requires: Pro or Enterprise plan
    """
    check_email_access(current_user, db)

    analysis = analyze_email(
        raw_content=payload.raw_content,
        sender_email=payload.sender_email,
        sender_name=payload.sender_name,
        subject=payload.subject,
        reply_to=payload.reply_to,
    )

    email_scan = EmailScan(
        user_id=current_user.id,
        sender_email=analysis.get("sender_email"),
        sender_name=analysis.get("sender_name"),
        sender_domain=analysis.get("sender_domain"),
        reply_to=analysis.get("reply_to"),
        subject=analysis.get("subject"),
        raw_content=payload.raw_content,
        content_preview=payload.raw_content[:200],
        risk_level=analysis["risk_level"],
        risk_score=analysis["risk_score"],
        detection_results=analysis["detection_results"],
        flagged_categories=analysis["flagged_categories"],
        email_specific_flags=analysis["email_specific_flags"],
        platform=analysis.get("platform"),
        scan_duration_ms=analysis["scan_duration_ms"],
    )
    db.add(email_scan)
    db.commit()
    db.refresh(email_scan)

    return EmailScanResult(
        id=email_scan.id,
        risk_level=email_scan.risk_level,
        risk_score=email_scan.risk_score,
        flagged_categories=email_scan.flagged_categories or [],
        detection_results=email_scan.detection_results or {},
        email_specific_flags=analysis["email_specific_flags"],
        sender_email=email_scan.sender_email,
        sender_name=email_scan.sender_name,
        sender_domain=email_scan.sender_domain,
        reply_to=email_scan.reply_to,
        subject=email_scan.subject,
        platform=email_scan.platform,
        content_preview=email_scan.content_preview or "",
        scan_duration_ms=email_scan.scan_duration_ms or 0,
        created_at=email_scan.created_at,
        recommendation=analysis["recommendation"],
    )


@router.get("/", response_model=List[EmailScanListItem])
def list_email_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all email scans for the current user."""
    check_email_access(current_user, db)
    scans = (
        db.query(EmailScan)
        .filter(EmailScan.user_id == current_user.id)
        .order_by(EmailScan.created_at.desc())
        .offset(skip).limit(limit).all()
    )
    return [
        EmailScanListItem(
            id=s.id,
            risk_level=s.risk_level,
            risk_score=s.risk_score,
            sender_email=s.sender_email,
            subject=s.subject,
            flagged_categories=s.flagged_categories or [],
            content_preview=s.content_preview or "",
            created_at=s.created_at,
        )
        for s in scans
    ]


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_email_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(EmailScan).filter(EmailScan.id == scan_id, EmailScan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Email scan not found")
    db.delete(scan)
    db.commit()
