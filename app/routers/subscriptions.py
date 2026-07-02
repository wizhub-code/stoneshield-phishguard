"""
Subscription & Payment Router
Stripe-ready architecture. Currently runs in simulation mode.
Connect Stripe by adding STRIPE_SECRET_KEY to .env
"""
from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.config import settings
from app.models.user import User
from app.models.subscription import Subscription, PLANS
from app.schemas.subscription import PlanOut, SubscriptionOut, UpgradeRequest, CheckoutSession

router = APIRouter(prefix="/subscriptions", tags=["Subscriptions & Billing"])


def get_or_create_subscription(user: User, db: Session) -> Subscription:
    """Get existing subscription or create a free one."""
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    if not sub:
        sub = Subscription(
            user_id=user.id,
            plan="free",
            status="active",
            scans_used_this_month=0,
            usage_reset_date=datetime.utcnow() + timedelta(days=30),
        )
        db.add(sub)
        db.commit()
        db.refresh(sub)
    return sub


@router.get("/plans", response_model=List[PlanOut])
def list_plans():
    """List all available subscription plans and pricing."""
    return [
        PlanOut(
            id=plan_id,
            name=details["name"],
            price_monthly=details["price_monthly"],
            price_yearly=details["price_yearly"],
            scans_per_month=details["scans_per_month"],
            api_keys_allowed=details["api_keys_allowed"],
            email_scanning=details["email_scanning"],
            priority_support=details["priority_support"],
            features=details["features"],
        )
        for plan_id, details in PLANS.items()
    ]


@router.get("/me", response_model=SubscriptionOut)
def get_my_subscription(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current user's subscription details and usage."""
    sub = get_or_create_subscription(current_user, db)
    return SubscriptionOut(
        id=sub.id,
        plan=sub.plan,
        status=sub.status,
        billing_cycle=sub.billing_cycle,
        scans_used_this_month=sub.scans_used_this_month,
        scans_remaining=sub.scans_remaining,
        scans_limit=sub.scans_limit,
        current_period_end=sub.current_period_end,
        cancel_at_period_end=sub.cancel_at_period_end,
        plan_details=sub.plan_details,
        created_at=sub.created_at,
    )


@router.post("/upgrade", response_model=CheckoutSession)
def upgrade_plan(
    payload: UpgradeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Initiate a plan upgrade.

    In production: creates a Stripe checkout session and returns the URL.
    Currently: returns a simulation response showing how it will work.

    To activate Stripe:
    1. Add STRIPE_SECRET_KEY to your .env file
    2. pip install stripe
    3. Replace the simulation block below with real Stripe API calls
    """
    if payload.plan not in PLANS:
        raise HTTPException(status_code=400, detail=f"Invalid plan. Choose from: {list(PLANS.keys())}")

    if payload.plan == "free":
        raise HTTPException(status_code=400, detail="Cannot upgrade to free plan. Use /downgrade instead.")

    plan = PLANS[payload.plan]
    price = plan["price_yearly"] if payload.billing_cycle == "yearly" else plan["price_monthly"]

    # ── Stripe Integration Point ──────────────────────────────────────────
    # Uncomment and fill in when ready to go live with payments:
    #
    # import stripe
    # stripe.api_key = settings.STRIPE_SECRET_KEY
    #
    # price_id = settings.STRIPE_PRICE_IDS[payload.plan][payload.billing_cycle]
    #
    # session = stripe.checkout.Session.create(
    #     customer_email=current_user.email,
    #     payment_method_types=["card"],
    #     line_items=[{"price": price_id, "quantity": 1}],
    #     mode="subscription",
    #     success_url=f"{settings.FRONTEND_URL}/dashboard?upgraded=true",
    #     cancel_url=f"{settings.FRONTEND_URL}/dashboard?cancelled=true",
    #     metadata={"user_id": current_user.id, "plan": payload.plan},
    # )
    # return CheckoutSession(checkout_url=session.url, plan=payload.plan, price=price)
    # ─────────────────────────────────────────────────────────────────────

    # Simulation mode (remove when Stripe is connected)
    return CheckoutSession(
        checkout_url=f"https://checkout.stripe.com/simulation?plan={payload.plan}&price={price}&user={current_user.id}",
        plan=payload.plan,
        price=price,
    )


@router.post("/simulate-upgrade")
def simulate_upgrade(
    payload: UpgradeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    DEV ONLY — Simulate a successful plan upgrade without Stripe.
    Use this to test Pro/Enterprise features locally.
    Remove this endpoint before going to production.
    """
    if payload.plan not in PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    sub = get_or_create_subscription(current_user, db)
    sub.plan = payload.plan
    sub.status = "active"
    sub.billing_cycle = payload.billing_cycle
    sub.current_period_start = datetime.utcnow()
    sub.current_period_end = datetime.utcnow() + timedelta(days=30 if payload.billing_cycle == "monthly" else 365)

    current_user.plan = payload.plan
    db.commit()

    return {
        "message": f"✅ Simulated upgrade to {payload.plan} plan successful",
        "plan": payload.plan,
        "features": PLANS[payload.plan]["features"],
        "note": "This is a simulation. Remove /simulate-upgrade before production.",
    }


@router.post("/cancel")
def cancel_subscription(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cancel subscription at end of billing period."""
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    if not sub or sub.plan == "free":
        raise HTTPException(status_code=400, detail="No active paid subscription to cancel")

    sub.cancel_at_period_end = True
    db.commit()

    return {
        "message": "Subscription will be cancelled at end of current billing period",
        "cancels_at": sub.current_period_end,
    }
