"""
Security middleware. Sole responsibility: reject requests from blocked IPs
with HTTP 403. Does NOT run any ML prediction and does NOT decide who gets
blocked — that's the behavior agent's job (see behavior_agent.py, invoked
from request_logging_middleware.py after a response has been produced).
"""

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response
from app.database import SessionLocal
from app.blocking_service import is_ip_blocked

class IPBlockMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Exempt health check and stats endpoints from being blocked
        if request.url.path in ["/", "/stats", "/api/stats"]:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        
        # Check if IP is blocked
        db = SessionLocal()
        try:
            if is_ip_blocked(db, client_ip):
                return Response(
                    content='{"detail": "Access blocked due to suspicious behavior."}',
                    status_code=403,
                    media_type="application/json"
                )
        finally:
            db.close()

        response = await call_next(request)
        return response
