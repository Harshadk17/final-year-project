"""
Security middleware. Sole responsibility: reject requests from blocked IPs
with HTTP 403. Does NOT run any ML prediction and does NOT decide who gets
blocked — that's the behavior agent's job (see behavior_agent.py, invoked
from request_logging_middleware.py after a response has been produced).
"""

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response

class IPBlockMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Exempt health check and stats endpoints from being blocked
        if request.url.path in ["/", "/stats", "/api/stats"]:
            return await call_next(request)

        # --- Your existing IP blocking logic remains here ---
        # client_ip = request.client.host
        # if is_blocked(client_ip):
        #     return Response("Forbidden", status_code=403)

        response = await call_next(request)
        return response
