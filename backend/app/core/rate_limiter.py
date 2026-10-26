"""
In-Memory Rate Limiting and Security Middleware.

Tracks requests per client IP within a configurable sliding window
and returns HTTP 429 Too Many Requests when limits are exceeded.
Zero external dependency required.
"""

from __future__ import annotations
import ipaddress
import time
from collections import defaultdict
from typing import Dict, List, Tuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi import status


def get_client_ip(request: Request) -> str:
    """
    Safely resolves the client IP address, respecting reverse proxy headers
    (X-Real-IP, X-Forwarded-For) if valid, falling back to connection peer host.
    """
    forwarded = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
    if forwarded:
        candidate = forwarded.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Thread-safe in-memory sliding window rate limiter with periodic cleanup
    to prevent memory exhaustion from unbounded unique client IPs.
    """

    MAX_TRACKED_IPS = 10000

    def __init__(self, app, max_requests: int = 120, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Mapping: ip_address -> list of timestamps
        self.client_requests: Dict[str, List[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def _cleanup_expired_ips(self, now: float) -> None:
        """Prunes stale IP entries whose sliding windows have fully lapsed."""
        window_start = now - self.window_seconds
        stale_keys = [
            ip for ip, ts_list in self.client_requests.items()
            if not ts_list or ts_list[-1] <= window_start
        ]
        for ip in stale_keys:
            self.client_requests.pop(ip, None)
        self._last_cleanup = now

    async def dispatch(self, request: Request, call_next):
        # Allow health checks and static docs without rate limiting
        path = request.url.path
        if path in ("/api/health", "/docs", "/redoc", "/openapi.json", "/"):
            return await call_next(request)

        client_ip = get_client_ip(request)
        now = time.time()

        # Periodically prune stale keys to eliminate memory leak
        if now - self._last_cleanup > 60 or len(self.client_requests) > self.MAX_TRACKED_IPS:
            self._cleanup_expired_ips(now)

        # Clean old timestamps outside the sliding window
        window_start = now - self.window_seconds
        timestamps = [ts for ts in self.client_requests[client_ip] if ts > window_start]

        if not timestamps:
            # If empty after filtering, remove key to save memory
            self.client_requests.pop(client_ip, None)
        else:
            self.client_requests[client_ip] = timestamps

        if len(timestamps) >= self.max_requests:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Too Many Requests",
                    "detail": f"Rate limit of {self.max_requests} requests per minute exceeded. Please slow down.",
                },
                headers={"Retry-After": str(self.window_seconds)},
            )

        self.client_requests[client_ip].append(now)

        # Call next handler
        response = await call_next(request)

        # Attach comprehensive defensive security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"

        return response
