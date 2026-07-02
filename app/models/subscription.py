import uuid
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


# ─── Plan Definitions ────────────────────────────────────────────────────────

PLANS = {
    "free": {
        "name": "Free",
        "price_monthly": 0,
        "price_yearly": 0,
        "scans_per_month": 100,
        "api_keys_allowed": 1,
        "email_scanning": False,
        "priority_support": False,
        "features": ["Basic phishing detection", "WhatsApp & Facebook detection", "Scan history (30 days)", "1 API key"],
    },
    "pro": {
        "name": "Pro",
        "price_monthly": 9.99,
        "price_yearly": 99.99,
        "scans_per_month": 5000,
        "api_keys_allowed": 5,
        "email_scanning": True,
        "priority_support": False,
        "features": ["Everything in Free", "5,000 scans/month", "Email scanning", "5 API keys", "Scan history (1 year)", "CSV export"],
    },
    "enterprise": {
        "name": "Enterprise",
        "price_monthly": 49.99,
        "price_yearly": 499.99,
        "scans_per_month": -1,  # unlimited
        "api_keys_allowed": -1,  # unlimited
        "email_scanning": True,
        "priority_support": True,
        "features": ["Everything in Pro", "Unlimited scans", "Unlimited API keys", "Priority support", "Custom integrations", "Team management", "Dedicated account manager"],
    },
}


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, unique=True, index=True)

    plan = Column(String, default="free")               # free | pro | enterprise
    status = Column(String, default="active")           # active | cancelled | past_due | trialing

    # Stripe integration fields (populated when Stripe is connected)
    stripe_customer_id = Column(String, nullable=True)
    stripe_subscription_id = Column(String, nullable=True)
    stripe_price_id = Column(String, nullable=True)

    # Billing cycle
    billing_cycle = Column(String, default="monthly")   # monthly | yearly
    current_period_start = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)
    cancel_at_period_end = Column(Boolean, default=False)

    # Usage tracking
    scans_used_this_month = Column(Integer, default=0)
    usage_reset_date = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="subscription")

    @property
    def plan_details(self):
        return PLANS.get(self.plan, PLANS["free"])

    @property
    def scans_limit(self):
        return self.plan_details["scans_per_month"]

    @property
    def is_unlimited(self):
        return self.scans_limit == -1

    @property
    def scans_remaining(self):
        if self.is_unlimited:
            return -1
        return max(0, self.scans_limit - self.scans_used_this_month)

    def __repr__(self):
        return f"<Subscription user={self.user_id} plan={self.plan} status={self.status}>"
