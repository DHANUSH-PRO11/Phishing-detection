"""
Integration Tests for FastAPI Backend REST Endpoints.

Tests:
1. Root & Health Check Endpoints (/ and /api/health)
2. URL Scanning Endpoint (/api/scan) with Legitimate and Phishing Payloads
3. Input Validation & Error Handling (Unsupported Schemes, Empty Strings)
4. Historical Records & Pagination (/api/history)
5. Search & Filter Parameters (Search, Status, Risk Category)
6. CSV History Export (/api/history/export/csv)
7. Single Scan Details & Deletion (/api/history/{scan_id})
8. Real Aggregated Dashboard Analytics (/api/stats)
9. Model Metadata & Features Transparency (/api/model-info)
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.db.database import init_db

init_db()
client = TestClient(app)


# =====================================================================
# 1. Root & Health Check
# =====================================================================

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "active"
    assert "documentation" in data


def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("ok", "degraded")
    assert data["database_connected"] is True
    assert data["model_ready"] is True
    assert data["model_name"] != "Unavailable"


# =====================================================================
# 2. URL Scanning Endpoint (/api/scan)
# =====================================================================

def test_scan_legitimate_url_persists_record():
    payload = {"url": "https://developer.mozilla.org/en-US/docs/Web"}
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "No Phishing Indicators Detected"
    assert data["is_phishing"] is False
    assert data["risk"]["final_risk_score"] < 35
    assert data["scan_id"] is not None
    assert len(data["scan_id"]) > 10


def test_scan_phishing_url_persists_record():
    payload = {"url": "http://192.168.1.100/webscr/login.php?cmd=_login"}
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "Potentially Phishing"
    assert data["is_phishing"] is True
    assert data["risk"]["final_risk_score"] >= 60
    assert len(data["explanations"]) >= 1


def test_scan_unsupported_scheme_returns_422():
    payload = {"url": "javascript:alert(document.cookie)"}
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "Unsupported URI scheme" in str(data)


def test_scan_empty_url_returns_422():
    payload = {"url": "   "}
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 422


# =====================================================================
# 3. Scan History, Pagination, and Search (/api/history)
# =====================================================================

def test_get_history_pagination():
    response = client.get("/api/history?page=1&size=10")
    assert response.status_code == 200
    data = response.json()

    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert data["page"] == 1
    assert data["size"] == 10
    assert isinstance(data["items"], list)
    assert data["total"] >= 2  # from earlier tests


def test_get_history_search_filter():
    response = client.get("/api/history?search=mozilla")
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        assert "mozilla" in item["url"].lower() or "mozilla" in item["domain"].lower()


def test_export_history_csv():
    response = client.get("/api/history/export/csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    content = response.text
    assert "Scan ID,Timestamp (UTC),URL,Domain,Status,Risk Score" in content


# =====================================================================
# 4. Individual Scan Details and Deletion (/api/history/{scan_id})
# =====================================================================

def test_get_and_delete_scan_detail():
    # 1. Create a scan to test detail and deletion
    scan_resp = client.post("/api/scan", json={"url": "https://wikipedia.org/wiki/Main_Page"})
    scan_id = scan_resp.json()["scan_id"]

    # 2. Get scan details
    detail_resp = client.get(f"/api/history/{scan_id}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    assert detail_data["scan_id"] == scan_id
    assert "components" in detail_data
    assert "explanations" in detail_data
    assert "features" in detail_data

    # 3. Delete scan
    del_resp = client.delete(f"/api/history/{scan_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True

    # 4. Verify scan is deleted (returns 404)
    verify_resp = client.get(f"/api/history/{scan_id}")
    assert verify_resp.status_code == 404


def test_get_nonexistent_scan_returns_404():
    response = client.get("/api/history/non-existent-uuid-12345")
    assert response.status_code == 404


def test_delete_nonexistent_scan_returns_404():
    response = client.delete("/api/history/non-existent-uuid-12345")
    assert response.status_code == 404


# =====================================================================
# 5. Dashboard Aggregate Statistics (/api/stats)
# =====================================================================

def test_get_dashboard_stats():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()

    assert "total_scans" in data
    assert "phishing_detected_count" in data
    assert "legitimate_count" in data
    assert "average_risk_score" in data
    assert "status_distribution" in data
    assert "risk_category_distribution" in data
    assert "recent_scans_timeline" in data
    assert data["total_scans"] >= 1


# =====================================================================
# 6. Model Information Endpoint (/api/model-info)
# =====================================================================

def test_get_model_info():
    response = client.get("/api/model-info")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "active"
    assert "model_name" in data
    assert "optimal_threshold" in data
    assert 0.0 < data["optimal_threshold"] < 1.0
    assert data["feature_count"] == 29
    assert len(data["feature_names"]) == 29
    assert "features_metadata" in data
