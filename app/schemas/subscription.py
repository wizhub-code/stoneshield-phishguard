from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel


class PlanOut(BaseModel):
    id: str
    name: str
    price_monthly: float
    price_yearly: float
    scans_per_month: int
    api_keys_allowed: int
    email_scanning: bool
    priority_support: bool
    features: List[str]


class SubscriptionOut(BaseModel):
    id: str
    plan: str
    status: str
    billing_cycle: str
    scans_used_this_month: int
    scans_remaining: int
    scans_limit: int
    current_period_end: Optional[datetime]
    cancel_at_period_end: bool
    plan_details: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


class UpgradeRequest(BaseModel):
    plan: str           # pro | enterprise
    billing_cycle: str = "monthly"  # monthly | yearly


class CheckoutSession(BaseModel):
    checkout_url: str
    plan: str
    price: float
