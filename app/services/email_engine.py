"""
Stoneshield PhishGuard — Email Phishing Detection Engine
=========================================================
Analyzes raw email content for phishing indicators including:
- Spoofed sender addresses
- Mismatched reply-to domains
- Email header anomalies
- Suspicious attachments
- All existing phishing patterns
"""

import re
import time
from typing import Dict, List, Optional, Tuple
from app.services.detection_engine import analyze_message, classify_risk, build_recommendation


# ─── Email Header Parser ──────────────────────────────────────────────────────

def parse_email_headers(raw_content: str) -> dict:
    """
    Extract key email metadata from raw email text or structured input.
    Handles both raw email format and plain pasted email content.
    """
    headers = {
        "from_email": None,
        "from_name": None,
        "from_domain": None,
        "reply_to": None,
        "reply_to_domain": None,
        "subject": None,
        "return_path": None,
    }

    # Extract From field
    from_match = re.search(r'[Ff]rom:\s*(?:"?([^"<\n]+)"?\s*)?<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?', raw_content)
    if from_match:
        headers["from_name"] = from_match.group(1).strip() if from_match.group(1) else None
        headers["from_email"] = from_match.group(2).strip().lower()
        headers["from_domain"] = headers["from_email"].split("@")[-1] if headers["from_email"] else None

    # Extract Reply-To
    reply_match = re.search(r'[Rr]eply-[Tt]o:\s*<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?', raw_content)
    if reply_match:
        headers["reply_to"] = reply_match.group(1).strip().lower()
        headers["reply_to_domain"] = headers["reply_to"].split("@")[-1]

    # Extract Subject
    subject_match = re.search(r'[Ss]ubject:\s*(.+?)(?:\n|$)', raw_content)
    if subject_match:
        headers["subject"] = subject_match.group(1).strip()

    # Extract Return-Path
    return_match = re.search(r'[Rr]eturn-[Pp]ath:\s*<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?', raw_content)
    if return_match:
        headers["return_path"] = return_match.group(1).strip().lower()

    return headers


# ─── Email-Specific Detection Rules ──────────────────────────────────────────

EMAIL_FLAGS = {
    "spoofed_sender": {
        "label": "Spoofed Sender",
        "patterns": [
            # Sender claims to be major brand but domain doesn't match
            (r'\b(?:paypal|amazon|microsoft|apple|google|facebook|whatsapp|bank)\b', r'@(?!paypal\.com|amazon\.com|microsoft\.com|apple\.com|google\.com|facebook\.com|whatsapp\.com)'),
            # Sender name contains trusted brand but email is different
        ],
        "severity": "high",
    },
    "domain_mismatch": {
        "label": "Domain Mismatch",
        "severity": "high",
    },
    "suspicious_subject": {
        "label": "Suspicious Subject Line",
        "patterns": [
            r'\b(?:urgent|action required|verify|suspended|compromised|winner|prize|claim|unusual activity)\b',
            r'\b(?:your account|security alert|important notice|final warning|billing issue)\b',
            r'\[(?:urgent|spam|external|caution)\]',
        ],
        "severity": "medium",
    },
    "no_sender_domain": {
        "label": "Missing Sender Information",
        "severity": "medium",
    },
    "free_email_impersonation": {
        "label": "Free Email Impersonation",
        "patterns": [
            r'(?:paypal|amazon|microsoft|apple|google|facebook|irs|bank).*@(?:gmail|yahoo|hotmail|outlook|protonmail)\.com',
        ],
        "severity": "high",
    },
    "lookalike_domain": {
        "label": "Lookalike Domain",
        "patterns": [
            r'@[a-zA-Z0-9\-]*(?:paypa[l1]|amaz[o0]n|micros[o0]ft|app[l1]e|g[o0]{2}gle|faceb[o0]{2}k|whatsap+)[a-zA-Z0-9\-]*\.',
            r'@[a-zA-Z0-9\-]*(?:secure|verify|login|account|support|helpdesk|billing)[a-zA-Z0-9\-]*\.',
        ],
        "severity": "high",
    },
}


def check_email_flags(headers: dict, raw_content: str) -> Tuple[List[dict], int]:
    """
    Run email-specific checks beyond content analysis.
    Returns list of flags and bonus risk score.
    """
    flags = []
    bonus_score = 0

    from_email = headers.get("from_email", "")
    from_domain = headers.get("from_domain", "")
    reply_to_domain = headers.get("reply_to_domain")
    subject = headers.get("subject", "") or ""

    # Check 1: Free email provider impersonating a brand
    if from_email:
        for pattern in EMAIL_FLAGS["free_email_impersonation"]["patterns"]:
            if re.search(pattern, from_email, re.IGNORECASE):
                flags.append({"flag": "free_email_impersonation", "label": "Free Email Impersonation", "detail": f"Brand name in address using free email: {from_email}", "severity": "high"})
                bonus_score += 25
                break

    # Check 2: Lookalike domain
    if from_email:
        for pattern in EMAIL_FLAGS["lookalike_domain"]["patterns"]:
            if re.search(pattern, from_email, re.IGNORECASE):
                flags.append({"flag": "lookalike_domain", "label": "Lookalike Domain", "detail": f"Suspicious sender domain: {from_domain}", "severity": "high"})
                bonus_score += 25
                break

    # Check 3: Reply-to domain mismatch
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        flags.append({"flag": "domain_mismatch", "label": "Reply-To Domain Mismatch", "detail": f"Sent from {from_domain} but replies go to {reply_to_domain}", "severity": "high"})
        bonus_score += 20

    # Check 4: Suspicious subject line
    if subject:
        for pattern in EMAIL_FLAGS["suspicious_subject"]["patterns"]:
            if re.search(pattern, subject, re.IGNORECASE):
                flags.append({"flag": "suspicious_subject", "label": "Suspicious Subject Line", "detail": f'Subject: "{subject}"', "severity": "medium"})
                bonus_score += 10
                break

    # Check 5: No sender info at all
    if not from_email:
        flags.append({"flag": "no_sender", "label": "No Sender Information", "detail": "Email has no identifiable sender address", "severity": "medium"})
        bonus_score += 10

    return flags, min(bonus_score, 40)


# ─── Main Email Analysis Function ────────────────────────────────────────────

def analyze_email(
    raw_content: str,
    sender_email: Optional[str] = None,
    sender_name: Optional[str] = None,
    subject: Optional[str] = None,
    reply_to: Optional[str] = None,
) -> dict:
    """
    Full email phishing analysis.
    Combines content analysis + email-specific header checks.
    """
    start = time.time()

    # Build full content string for analysis
    # If sender/subject provided directly, prepend as headers
    header_block = ""
    if sender_email:
        header_block += f"From: {sender_name or ''} <{sender_email}>\n"
    if reply_to:
        header_block += f"Reply-To: {reply_to}\n"
    if subject:
        header_block += f"Subject: {subject}\n"

    full_content = header_block + "\n" + raw_content if header_block else raw_content

    # Parse headers from content
    headers = parse_email_headers(full_content)

    # Override with directly provided values
    if sender_email:
        headers["from_email"] = sender_email.lower()
        headers["from_domain"] = sender_email.split("@")[-1].lower()
        headers["from_name"] = sender_name
    if reply_to:
        headers["reply_to"] = reply_to.lower()
        headers["reply_to_domain"] = reply_to.split("@")[-1].lower()
    if subject:
        headers["subject"] = subject

    # Run base content analysis
    base_result = analyze_message(full_content)

    # Run email-specific checks
    email_flags, bonus_score = check_email_flags(headers, full_content)

    # Combine scores
    combined_score = min(base_result["risk_score"] + bonus_score, 100)
    risk_level = classify_risk(combined_score)

    # Build email-specific recommendation
    all_flagged = base_result["flagged_categories"] + [f["label"] for f in email_flags]
    recommendation = _build_email_recommendation(risk_level, all_flagged, email_flags, headers)

    duration_ms = round((time.time() - start) * 1000)

    return {
        "risk_level": risk_level,
        "risk_score": combined_score,
        "detection_results": base_result["detection_results"],
        "flagged_categories": base_result["flagged_categories"],
        "email_specific_flags": email_flags,
        "platform": base_result.get("platform"),
        "sender_email": headers.get("from_email"),
        "sender_name": headers.get("from_name"),
        "sender_domain": headers.get("from_domain"),
        "reply_to": headers.get("reply_to"),
        "subject": headers.get("subject"),
        "scan_duration_ms": duration_ms,
        "recommendation": recommendation,
    }


def _build_email_recommendation(risk_level: str, flagged: List[str], email_flags: List[dict], headers: dict) -> str:
    if risk_level == "SAFE":
        return "This email appears legitimate. No significant phishing indicators detected."

    high_severity = [f for f in email_flags if f.get("severity") == "high"]
    sender = headers.get("from_email", "unknown sender")

    if risk_level == "SUSPICIOUS":
        msg = f"This email shows suspicious patterns. "
        if high_severity:
            msg += f"Warning: {high_severity[0]['label']} detected from {sender}. "
        msg += "Do not click links or provide personal information. Verify the sender by contacting them through official channels."
        return msg

    # DANGEROUS
    msg = f"HIGH RISK — This email is likely a phishing attack. "
    if high_severity:
        issues = ", ".join(f["label"] for f in high_severity)
        msg += f"Critical issues: {issues}. "
    msg += f"Do NOT reply, click any links, or open attachments. Delete this email immediately and report it to your IT/security team."
    return msg
