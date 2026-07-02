"""
Stoneshield PhishGuard — Test Suite
=====================================
Run with: pytest tests/ -v
"""

import pytest
from app.services.detection_engine import analyze_message, classify_risk


# ─── Detection Engine Tests ──────────────────────────────────────────────────

class TestDetectionEngine:

    def test_safe_message(self):
        msg = "Hi Sarah, the Q3 planning meeting is at 2pm Thursday. Please review the agenda."
        result = analyze_message(msg)
        assert result["risk_level"] == "SAFE"
        assert result["risk_score"] < 20
        assert result["flagged_categories"] == []

    def test_dangerous_phishing(self):
        msg = (
            "URGENT: Your PayPal account has been compromised! "
            "Click here to verify: http://paypa1-secure.xyz/verify "
            "Enter your password immediately or your account will be deleted. "
            "Dear Customer, failure to comply will result in permanent suspension."
        )
        result = analyze_message(msg)
        assert result["risk_level"] == "DANGEROUS"
        assert result["risk_score"] >= 55
        assert len(result["flagged_categories"]) > 0

    def test_suspicious_message(self):
        msg = (
            "Your account expires soon. Please verify your email to keep access. "
            "This is a reminder from your bank."
        )
        result = analyze_message(msg)
        assert result["risk_level"] in ("SUSPICIOUS", "DANGEROUS")
        assert result["risk_score"] >= 20

    def test_credential_harvesting_detected(self):
        msg = "Please enter your password and confirm your credit card details to update billing information."
        result = analyze_message(msg)
        assert "Credential Harvesting" in result["flagged_categories"]

    def test_impersonation_detected(self):
        msg = "This is Microsoft Security team. We detected unusual activity on your account."
        result = analyze_message(msg)
        assert "Impersonation Attempt" in result["flagged_categories"]

    def test_suspicious_link_detected(self):
        msg = "Click here to verify: http://paypa1-secure.xyz/login?token=abc"
        result = analyze_message(msg)
        assert "Suspicious Links" in result["flagged_categories"]

    def test_urgency_language_detected(self):
        msg = "URGENT: Act now or your account will be suspended within 24 hours."
        result = analyze_message(msg)
        assert "Urgency Language" in result["flagged_categories"]

    def test_ip_based_url(self):
        msg = "Verify here: http://192.168.1.1/login"
        result = analyze_message(msg)
        assert "Suspicious Links" in result["flagged_categories"]

    def test_result_structure(self):
        result = analyze_message("Hello world")
        assert "risk_level" in result
        assert "risk_score" in result
        assert "detection_results" in result
        assert "flagged_categories" in result
        assert "scan_duration_ms" in result
        assert "recommendation" in result
        assert isinstance(result["risk_score"], int)
        assert 0 <= result["risk_score"] <= 100


# ─── Risk Classification Tests ───────────────────────────────────────────────

class TestClassification:

    def test_safe_range(self):
        for score in [0, 10, 19]:
            assert classify_risk(score) == "SAFE"

    def test_suspicious_range(self):
        for score in [20, 35, 54]:
            assert classify_risk(score) == "SUSPICIOUS"

    def test_dangerous_range(self):
        for score in [55, 75, 100]:
            assert classify_risk(score) == "DANGEROUS"


# ─── Password Hashing Tests ───────────────────────────────────────────────────

class TestSecurity:

    def test_password_hash_and_verify(self):
        from app.core.security import hash_password, verify_password
        pw = "SecurePassword123"
        hashed = hash_password(pw)
        assert hashed != pw
        assert verify_password(pw, hashed)
        assert not verify_password("wrongpassword", hashed)

    def test_different_hashes_for_same_password(self):
        from app.core.security import hash_password
        pw = "SamePassword"
        # bcrypt generates different salts each time
        assert hash_password(pw) != hash_password(pw)

    def test_create_and_decode_token(self):
        from app.core.security import create_access_token, decode_token
        token = create_access_token({"sub": "user-123"})
        payload = decode_token(token)
        assert payload["sub"] == "user-123"

    def test_invalid_token_raises(self):
        from app.core.security import decode_token
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            decode_token("invalid.token.here")
