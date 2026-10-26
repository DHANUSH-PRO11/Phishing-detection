"""
Locust Load Testing Scenarios for Phishing Detection Platform.

Simulates concurrent user behavior across URL scanning, dashboard metrics,
scan history pagination, and invalid input resilience.
"""

from __future__ import annotations
import json
import random
from pathlib import Path
from locust import HttpUser, task, between, events

SEEDED_FILE = Path(__file__).parent / "seeded_urls.json"
with open(SEEDED_FILE, "r", encoding="utf-8") as f:
    SEEDED_DATA = json.load(f)

VALID_URLS = SEEDED_DATA["normal_urls"] + SEEDED_DATA["phishing_lures"] + SEEDED_DATA["large_valid_urls"]
INVALID_URLS = SEEDED_DATA["invalid_urls"]


class PhishShieldUser(HttpUser):
    """Simulated security analyst or end user."""
    wait_time = between(0.1, 0.3)

    @task(7)
    def scan_valid_url(self) -> None:
        """Submits valid URLs for lexical extraction and inference."""
        url = random.choice(VALID_URLS)
        with self.client.post(
            "/api/scan",
            json={"url": url},
            name="/api/scan [valid]",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if "risk" in data and "score" in str(data["risk"]):
                    response.success()
                else:
                    response.failure("Malformed response payload")
            elif response.status_code == 429:
                response.success()  # Rate limiting functioning properly under load
            else:
                response.failure(f"Unexpected status: {response.status_code}")

    @task(1)
    def scan_invalid_url(self) -> None:
        """Tests negative resilience with malformed schemes or empty inputs."""
        bad_url = random.choice(INVALID_URLS)
        with self.client.post(
            "/api/scan",
            json={"url": bad_url},
            name="/api/scan [malformed]",
            catch_response=True,
        ) as response:
            if response.status_code == 422:
                response.success()
            elif response.status_code == 429:
                response.success()
            else:
                response.failure(f"Expected 422, got {response.status_code}")

    @task(2)
    def view_dashboard_stats(self) -> None:
        """Queries real-time aggregate statistics."""
        with self.client.get("/api/stats", name="/api/stats", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 429:
                response.success()
            else:
                response.failure(f"Unexpected stats status: {response.status_code}")

    @task(2)
    def view_scan_history(self) -> None:
        """Navigates paginated historical scans."""
        page = random.randint(1, 3)
        with self.client.get(
            f"/api/history?page={page}&size=10&sort_by=created_at&sort_order=desc",
            name="/api/history",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 429:
                response.success()
            else:
                response.failure(f"Unexpected history status: {response.status_code}")
