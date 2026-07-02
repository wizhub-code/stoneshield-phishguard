"""
Stoneshield PhishGuard — Phishing Detection Engine
====================================================
Pattern-based detection with weighted scoring across 6 threat categories.
Includes dedicated WhatsApp and Facebook phishing detection modules.
Architecture is designed to be extended with AI/ML models in future versions.
"""

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


# ─── Detection Rule Definition ───────────────────────────────────────────────

@dataclass
class DetectionRule:
    label: str
    weight: int
    patterns: List[str]


# ─── Detection Rules ─────────────────────────────────────────────────────────

DETECTION_RULES: Dict[str, DetectionRule] = {

    # ── 1. Suspicious Links ──────────────────────────────────────────────────
    "suspicious_links": DetectionRule(
        label="Suspicious Links",
        weight=35,
        patterns=[
            r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"https?://[^\s]*(paypa[l1]|bank0f|g00gle|amaz[o0]n|micros0ft|netf[l1]ix|app[l1]e|wh4tsapp|whatsap|faceb00k|faceboook)[^\s]*",
            r"https?://(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|is\.gd|ow\.ly|short\.link|wa\.me\/[^\s]{20,})/\S+",
            r"https?://[^\s]+\.(?:xyz|top|tk|ml|ga|cf|click|download|zip|ng|online)[^\s\"']*",
            r"(?:click here|verify here|login here|confirm here|access here|tap here|open here)\s*:?\s*https?://",
            r"https?://[^\s]{80,}",
            r"https?://[^\s]*[-_](?:secure|verify|login|account|update|confirm|winner|prize|claim)[^\s]*",
        ],
    ),

    # ── 2. Urgency Language ──────────────────────────────────────────────────
    "urgency_language": DetectionRule(
        label="Urgency Language",
        weight=25,
        patterns=[
            r"\b(?:urgent|urgently|immediately|right away|asap|act now|hurry)\b",
            r"\bexpires?\s+(?:in\s+\d+\s+(?:hour|minute|day)|today|soon|tonight|now)\b",
            r"\b(?:within\s+\d+\s+(?:hours?|minutes?|days?))\b",
            r"\b(?:limited time|last chance|final notice|final warning|deadline|don.t miss)\b",
            r"\byour\s+(?:account|whatsapp|facebook|profile)\s+(?:will\s+be|has\s+been)\s+(?:suspended|blocked|disabled|deleted|locked|banned|compromised|terminated)\b",
            r"\bverify\s+(?:your\s+)?(?:account|identity|number|phone|email|whatsapp|facebook)\s+(?:now|immediately|today)\b",
            r"\bfailure\s+to\s+(?:comply|respond|verify|confirm|update)\s+will\s+(?:result|lead)\b",
            r"\b(?:you\s+have\s+(?:won|been\s+selected|been\s+chosen)|congratulations\s+you\s+(?:won|have\s+won))\b",
            r"\b(?:claim\s+(?:your\s+)?(?:prize|reward|gift|money|cash|winnings)\s+(?:now|immediately|today))\b",
        ],
    ),

    # ── 3. Impersonation ─────────────────────────────────────────────────────
    "impersonation": DetectionRule(
        label="Impersonation Attempt",
        weight=30,
        patterns=[
            r"\b(?:paypal|pay\.pal)\b",
            r"\b(?:bank\s+of\s+america|chase\s+bank|wells\s+fargo|citibank|hsbc|barclays|lloyds|access\s+bank|gtbank|zenith\s+bank|first\s+bank|uba\s+bank|fidelity\s+bank)\b",
            r"\b(?:microsoft|apple|google)\s*(?:security|account|team|support|id|inc)?\b",
            r"\b(?:amazon|netflix|spotify|mtn|airtel|glo|9mobile)\s*(?:security|billing|account|order|subscription|team)?\b",
            r"\b(?:whatsapp\s+(?:team|support|security|official|headquarters|inc|ltd))\b",
            r"\b(?:facebook\s+(?:team|support|security|official|headquarters|inc|meta))\b",
            r"\b(?:meta\s+(?:team|support|security|official|platforms))\b",
            r"\b(?:irs|internal\s+revenue|tax\s+(?:authority|department|office)|firs|federal\s+inland\s+revenue)\b",
            r"\bdear\s+(?:valued\s+)?(?:customer|account.holder|member|user|client|friend|winner)\b",
            r"\b(?:this\s+is|we\s+are|message\s+from)\s+(?:whatsapp|facebook|meta|paypal|amazon|microsoft|apple|google|your\s+bank)\b",
            r"\b(?:official\s+(?:whatsapp|facebook|meta|google|microsoft)\s+(?:team|notification|message|alert))\b",
        ],
    ),

    # ── 4. Credential Harvesting ─────────────────────────────────────────────
    "credential_harvesting": DetectionRule(
        label="Credential Harvesting",
        weight=40,
        patterns=[
            r"\benter\s+(?:your\s+)?(?:password|username|login\s+credentials|credentials|pin|otp|code|verification\s+code)\b",
            r"\bprovide\s+(?:your\s+)?(?:card\s+number|cvv|ssn|social\s+security|routing\s+number|account\s+number|bvn|nin)\b",
            r"\bconfirm\s+(?:your\s+)?(?:password|identity|credentials|banking\s+details|payment\s+information|otp)\b",
            r"\bupdate\s+(?:your\s+)?(?:payment|billing|credit\s+card|bank(?:ing)?)\s+(?:info(?:rmation)?|details?)\b",
            r"\b(?:your\s+)?password\s+(?:has\s+expired|needs?\s+to\s+be\s+(?:updated|reset|changed)|must\s+be\s+reset)\b",
            r"\b(?:re.?enter|re.?type|re.?input)\s+(?:your\s+)?(?:password|credentials|otp|pin|code)\b",
            r"\bverify\s+(?:your\s+)?(?:credit\s+card|debit\s+card|payment\s+method|billing\s+information|bvn|nin|identity)\b",
            r"\b(?:send|share|provide|give)\s+(?:us\s+)?(?:your\s+)?(?:otp|one.time.password|verification\s+code|pin|password)\b",
            r"\b(?:do\s+not\s+share\s+this\s+code\s+with\s+anyone)\b",
        ],
    ),

    # ── 5. WhatsApp Phishing ─────────────────────────────────────────────────
    "whatsapp_phishing": DetectionRule(
        label="WhatsApp Phishing",
        weight=38,
        patterns=[
            # Account takeover
            r"\b(?:your\s+whatsapp\s+(?:account|number)\s+(?:has\s+been|will\s+be)\s+(?:banned|suspended|blocked|deleted|deactivated))\b",
            r"\b(?:whatsapp\s+(?:account\s+)?verification\s+(?:code|otp|number))\b",
            r"\b(?:verify\s+your\s+whatsapp\s+(?:account|number|phone))\b",
            r"\b(?:your\s+whatsapp\s+(?:has\s+expired|subscription|premium|plus|gold|pro))\b",

            # Fake prizes and rewards
            r"\b(?:whatsapp\s+(?:anniversary|birthday|lucky\s+draw|lottery|giveaway|promo(?:tion)?))\b",
            r"\b(?:you\s+have\s+been\s+(?:selected|chosen)\s+(?:by\s+whatsapp|as\s+a\s+whatsapp))\b",
            r"\b(?:whatsapp\s+is\s+giving\s+(?:away|out|free))\b",
            r"\b(?:forward\s+this\s+(?:message|to)\s+\d+\s+(?:contacts|people|friends|groups))\b",
            r"\b(?:share\s+(?:this\s+)?(?:message|link)\s+(?:with|to)\s+\d+\s+(?:contacts|people|friends|groups))\b",

            # Fake WhatsApp support
            r"\b(?:whatsapp\s+support\s+(?:team|center|helpdesk))\b",
            r"\b(?:whatsapp\s+(?:official|headquarters|team)\s+(?:is\s+contacting|has\s+contacted|hereby\s+inform))\b",

            # OTP scams
            r"\b(?:send\s+(?:me|us)\s+(?:the\s+)?(?:6.digit|otp|verification)\s+code\s+(?:sent|you\s+received))\b",
            r"\b(?:whatsapp\s+sent\s+you\s+a\s+(?:code|otp|verification))\b",

            # Fake WhatsApp links
            r"https?://[^\s]*whatsapp[^\s]*(?:verify|login|secure|prize|claim|free|gold|plus|pro)[^\s]*",
            r"https?://(?:whatsap{1,3}|wh4tsapp|whats-app)[^\s]*",
        ],
    ),

    # ── 6. Facebook Phishing ─────────────────────────────────────────────────
    "facebook_phishing": DetectionRule(
        label="Facebook Phishing",
        weight=38,
        patterns=[
            # Account threats
            r"\b(?:your\s+facebook\s+(?:account|page|profile)\s+(?:has\s+been|will\s+be)\s+(?:disabled|suspended|banned|deleted|removed|blocked|restricted))\b",
            r"\b(?:facebook\s+(?:account\s+)?(?:disabled|suspended|banned|violation|policy\s+violation))\b",
            r"\b(?:your\s+(?:page|account)\s+(?:has\s+violated|violates)\s+(?:facebook|meta|our)\s+(?:community\s+standards|terms|policies))\b",

            # Fake verification / badge
            r"\b(?:get\s+(?:your\s+)?(?:facebook\s+)?(?:blue\s+)?(?:verified\s+badge|checkmark|verification))\b",
            r"\b(?:facebook\s+(?:page\s+)?verification\s+(?:form|process|request|team))\b",
            r"\b(?:verify\s+your\s+(?:facebook\s+)?(?:page|account|identity)\s+(?:now|today|immediately))\b",

            # Fake login pages
            r"https?://[^\s]*(?:faceb[o0]{1,2}k|face-book|fb-login|facebook-verify|facebook-secure)[^\s]*",
            r"https?://[^\s]*(?:login\.facebook|secure\.facebook|verify\.facebook)[^\s]*(?!\.com\b)",

            # Marketplace scams
            r"\b(?:facebook\s+marketplace\s+(?:buyer|seller|payment|shipping|escrow))\b",
            r"\b(?:i\s+(?:am|will)\s+(?:pay|send|transfer)\s+(?:you\s+)?(?:via|through|using)\s+(?:facebook\s+pay|meta\s+pay))\b",

            # Fake Meta/Facebook support
            r"\b(?:meta\s+(?:support|security|team|official)\s+(?:has|is|will))\b",
            r"\b(?:facebook\s+(?:support|security|team|official|helpdesk)\s+(?:has\s+detected|is\s+contacting|hereby\s+informs?))\b",

            # Friend request / impersonation scams
            r"\b(?:i\s+(?:found|saw|noticed)\s+your\s+(?:facebook|fb)\s+(?:profile|account|page))\b",
            r"\b(?:(?:add|follow|accept)\s+me\s+on\s+(?:facebook|fb)\s+(?:for|to\s+get|to\s+claim))\b",

            # Fake giveaways
            r"\b(?:facebook\s+(?:anniversary|birthday|giveaway|lottery|lucky\s+draw|promo(?:tion)?))\b",
            r"\b(?:mark\s+zuckerberg\s+(?:is\s+giving|giving\s+away|has\s+approved))\b",
        ],
    ),
}


# ─── Platform Detection ───────────────────────────────────────────────────────

def detect_platform(content: str) -> Optional[str]:
    """
    Detect which platform the phishing message is targeting.
    Returns platform name or None if generic.
    """
    content_lower = content.lower()

    whatsapp_signals = ["whatsapp", "wa.me", "whatsap", "wapp"]
    facebook_signals = ["facebook", "fb.com", "meta", "messenger", "marketplace", "zuckerberg"]

    wa_score = sum(1 for s in whatsapp_signals if s in content_lower)
    fb_score = sum(1 for s in facebook_signals if s in content_lower)

    if wa_score > 0 and fb_score > 0:
        return "WhatsApp & Facebook"
    elif wa_score > 0:
        return "WhatsApp"
    elif fb_score > 0:
        return "Facebook"
    return None


# ─── Risk Classification ─────────────────────────────────────────────────────

def classify_risk(score: int) -> str:
    if score < 20:
        return "SAFE"
    elif score < 55:
        return "SUSPICIOUS"
    else:
        return "DANGEROUS"


def build_recommendation(risk_level: str, flagged: List[str], platform: Optional[str] = None) -> str:
    platform_note = f" (Platform targeted: {platform})" if platform else ""

    if risk_level == "SAFE":
        return "No significant phishing indicators found. This message appears legitimate."

    elif risk_level == "SUSPICIOUS":
        cats = ", ".join(flagged) if flagged else "unknown patterns"
        if platform == "WhatsApp":
            return (
                f"This message shows WhatsApp phishing patterns ({cats}){platform_note}. "
                "WhatsApp will NEVER ask for your OTP or verification code. "
                "Do not click any links or share any codes."
            )
        elif platform == "Facebook":
            return (
                f"This message shows Facebook phishing patterns ({cats}){platform_note}. "
                "Facebook will NEVER contact you through Messenger to verify your account. "
                "Do not click any links or provide login details."
            )
        return (
            f"This message shows suspicious patterns ({cats}). "
            "Do not click links or provide personal information. Verify the sender through official channels."
        )

    else:
        cats = ", ".join(flagged) if flagged else "multiple categories"
        if platform == "WhatsApp":
            return (
                f"HIGH RISK — WhatsApp phishing attack detected{platform_note}. "
                "This is a scam. WhatsApp will NEVER ask for your OTP, password, or payment. "
                "Do NOT share any codes, click any links, or forward this message. "
                "Block and report the sender immediately."
            )
        elif platform == "Facebook":
            return (
                f"HIGH RISK — Facebook phishing attack detected{platform_note}. "
                "This is a scam. Facebook/Meta will NEVER message you asking for your password or payment. "
                "Do NOT click any links or enter your credentials anywhere. "
                "Report this to Facebook and block the sender."
            )
        elif platform == "WhatsApp & Facebook":
            return (
                f"HIGH RISK — Multi-platform phishing attack detected targeting WhatsApp and Facebook{platform_note}. "
                "This message is designed to steal your accounts. Do NOT interact with it. "
                "Block the sender and report immediately on both platforms."
            )
        return (
            f"HIGH RISK — Strong phishing indicators detected in: {cats}. "
            "Do NOT click any links, provide credentials, or respond. "
            "Report this message to your IT/security team immediately."
        )


# ─── Main Detection Function ─────────────────────────────────────────────────

def analyze_message(content: str) -> dict:
    """
    Run all detection rules against content.
    Includes WhatsApp and Facebook specific phishing detection.
    Returns a structured result dict ready for DB storage and API response.
    """
    start = time.time()
    detection_results = {}
    total_score = 0
    max_possible = sum(r.weight for r in DETECTION_RULES.values())
    flagged_categories = []

    # Detect platform context
    platform = detect_platform(content)

    for key, rule in DETECTION_RULES.items():
        match_count = 0
        matches = []

        for pattern in rule.patterns:
            found = re.findall(pattern, content, flags=re.IGNORECASE)
            if found:
                match_count += len(found)
                for m in found[:2]:
                    if isinstance(m, tuple):
                        m = " ".join(m).strip()
                    truncated = m[:80] + "…" if len(m) > 80 else m
                    if truncated not in matches:
                        matches.append(truncated)

        category_score = min(match_count * rule.weight, rule.weight)
        total_score += category_score

        detection_results[key] = {
            "label": rule.label,
            "score": category_score,
            "match_count": match_count,
            "matches": matches[:3],
        }

        if match_count > 0:
            flagged_categories.append(rule.label)

    # Normalize to 0–100
    risk_score = min(round((total_score / max_possible) * 100), 100)
    risk_level = classify_risk(risk_score)
    duration_ms = round((time.time() - start) * 1000)

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "detection_results": detection_results,
        "flagged_categories": flagged_categories,
        "platform": platform,
        "scan_duration_ms": duration_ms,
        "recommendation": build_recommendation(risk_level, flagged_categories, platform),
    }