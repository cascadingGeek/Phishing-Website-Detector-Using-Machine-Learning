"""Simple in-memory rate limiter middleware.

Uses a sliding-window counter per client IP.  No external dependencies — this
is intentionally lightweight.  Replace with a Redis-backed solution when
horizontal scaling is required.
"""
from __future__ import annotations

import time
from collections import defaultdict

from fastapi import HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests that exceed *requests_per_minute* from the same IP."""

    def __init__(self, app, requests_per_minute: int = 60) -> None:
        super().__init__(app)
        self._limit = requests_per_minute
        self._window = 60.0  # seconds
        # Maps client IP → list of request timestamps within the current window
        self._log: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window_start = now - self._window

        # Drop timestamps outside the sliding window
        self._log[client_ip] = [
            t for t in self._log[client_ip] if t > window_start
        ]

        if len(self._log[client_ip]) >= self._limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded — please slow down",
            )

        self._log[client_ip].append(now)
        return await call_next(request)
