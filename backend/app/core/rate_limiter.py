"""
In-Memory Rate Limiting and Security Middleware.

Tracks requests per client IP within a configurable sliding window
and returns HTTP 429 Too Many Requests when limits are exceeded.
Zero external dependency required.
"""

from __future__ import annotations
import time
from collections import defaultdict
from typing import Dict, List, Tuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi import status


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Thread-safe in-memory sliding window rate limiter.
    """

    def __init__(self, app, max_requests: int = 120, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Mapping: ip_address -> list of timestamps
        self.client_requests: Dict[str, List[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Allow health checks and static docs without rate limiting
        path = request.url.path
        if path in ("/api/health", "/docs", "/redoc", "/openapi.json", "/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Clean old timestamps outside the sliding window
        window_start = now - self.window_seconds
        timestamps = [ts for ts in self.client_requests[client_ip] if ts > window_start]
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

        # Attach security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response
