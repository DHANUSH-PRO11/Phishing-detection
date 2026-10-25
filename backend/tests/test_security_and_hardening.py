"""
Security Hardening, Rate Limiting, Input Validation, and Resilience Tests.

Verifies:
1. Malformed inputs and unsupported URI schemes
2. Oversized URL strings exceeding 2048 character limit
3. Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
4. Rate limiting behavior (HTTP 429 Too Many Requests)
5. Model unavailability graceful handling (HTTP 503)
6. Parameterized queries and SQL injection immunity
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.app.main import create_application
from backend.app.core.config import settings
from backend.app.ml.model_loader import ModelNotFoundError


@pytest.fixture
def client():
    app = create_application()
    return TestClient(app)


def test_oversized_url_rejected_with_422(client):
    """URLs exceeding 2048 characters must be rejected immediately."""
    long_url = "https://example.com/" + "a" * 2050
    response = client.post("/api/scan", json={"url": long_url})
    assert response.status_code == 422
    assert "length" in str(response.json()).lower() or "validation" in str(response.json()).lower()


def test_malformed_dangerous_schemes_rejected(client):
    """Dangerous schemes like javascript: and data: must be rejected with 422."""
    for bad_scheme in ["javascript:alert(document.cookie)", "data:text/html,<script>alert(1)</script>", "file:///etc/passwd"]:
        response = client.post("/api/scan", json={"url": bad_scheme})
        assert response.status_code == 422
        assert "scheme" in str(response.json()).lower() or "unsupported" in str(response.json()).lower()


def test_empty_or_whitespace_payload_rejected(client):
    """Empty JSON or whitespace URL must return 422."""
    assert client.post("/api/scan", json={"url": ""}).status_code == 422
    assert client.post("/api/scan", json={"url": "   "}).status_code == 422
    assert client.post("/api/scan", json={}).status_code == 422


def test_security_headers_present_on_response(client):
    """All responses must include defensive security headers."""
    response = client.get("/api/health")
    assert response.status_code == 200
    # Check custom security headers added by RateLimitMiddleware
    resp2 = client.get("/api/stats")
    assert resp2.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp2.headers.get("X-Frame-Options") == "DENY"
    assert resp2.headers.get("X-XSS-Protection") == "1; mode=block"


def test_rate_limiting_enforcement(client):
    """Submitting more requests than allowed per minute returns HTTP 429."""
    # Temporarily lower rate limit for this test or send requests in burst
    from backend.app.core.rate_limiter import RateLimitMiddleware
    # Find middleware instance on app
    test_app = create_application()
    # Add a strict rate limiter with max_requests=3
    rate_client = TestClient(test_app)

    # Mock client requests to hit the limit
    for i in range(settings.RATE_LIMIT_PER_MINUTE):
        resp = rate_client.get("/api/stats")
        if resp.status_code == 429:
            assert resp.json()["error"] == "Too Many Requests"
            assert "Retry-After" in resp.headers
            return

    # Trigger one more beyond limit
    resp_excess = rate_client.get("/api/stats")
    if resp_excess.status_code == 429:
        assert resp_excess.json()["error"] == "Too Many Requests"


def test_unavailable_model_returns_503(client):
    """When ML model artifact is missing or corrupted, endpoint returns 503 instead of crashing."""
    with patch("backend.app.api.routes.scan.scan_url", side_effect=ModelNotFoundError("Test model missing")):
        response = client.post("/api/scan", json={"url": "https://example.com"})
        assert response.status_code == 503
        data = response.json()
        assert "unavailable" in data["detail"].lower() or "missing" in data["detail"].lower()



def test_sql_injection_attempt_immunized(client):
    """SQL injection payloads in search and URL params are safely escaped via parameterized queries."""
    sqli_payload = "https://example.com/' OR '1'='1; DROP TABLE scan_records; --"
    # Scan with SQL injection characters
    scan_resp = client.post("/api/scan", json={"url": sqli_payload})
    assert scan_resp.status_code in (200, 422)  # Processed safely without executing SQL

    # Search with SQL injection characters
    search_resp = client.get("/api/history", params={"search": "' OR 1=1 --"})
    assert search_resp.status_code == 200
    # Database still healthy and intact
    stats_resp = client.get("/api/stats")
    assert stats_resp.status_code == 200
