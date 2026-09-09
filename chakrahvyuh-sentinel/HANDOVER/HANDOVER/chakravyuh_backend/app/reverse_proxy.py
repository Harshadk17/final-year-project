"""
Reverse proxy module for forwarding requests to X Beauty origin.

This module handles forwarding requests to the X Beauty Vercel origin after
the security pipeline has processed them. The security middleware runs first
(IPBlockMiddleware, RequestLoggingMiddleware), then allowed requests are
forwarded to the origin.
"""

import httpx
from fastapi import Request, Response
from app.config import ORIGIN_URL


async def forward_to_origin(request: Request) -> Response:
    """
    Forward the request to the X Beauty origin server.
    
    This function is called after the security pipeline has processed the request
and determined it should be allowed. It forwards the request to the origin
and returns the response.
    
    Args:
        request: The incoming FastAPI request
        
    Returns:
        Response: The response from the origin server
    """
    # Build the origin URL with the path and query string
    path = request.url.path
    query_string = request.url.query
    origin_url = f"{ORIGIN_URL}{path}"
    if query_string:
        origin_url += f"?{query_string}"
    
    # Get request body if present
    body = await request.body()
    
    # Forward headers, excluding hop-by-hop headers
    headers = dict(request.headers)
    headers_to_remove = [
        "host", "content-length", "transfer-encoding", 
        "connection", "keep-alive", "te", "trailer", 
        "upgrade", "proxy-authorization", "proxy-authenticate"
    ]
    for header in headers_to_remove:
        headers.pop(header, None)
    
    # Add X-Forwarded headers
    headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"
    headers["X-Forwarded-Proto"] = request.url.scheme
    headers["X-Forwarded-Host"] = request.url.netloc
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=request.method,
                url=origin_url,
                headers=headers,
                content=body if body else None,
                timeout=30.0
            )
            
            # Return the response from origin
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )
        except httpx.TimeoutException:
            return Response(
                content='{"error": "Origin server timeout"}',
                status_code=504,
                media_type="application/json"
            )
        except httpx.RequestError as e:
            return Response(
                content=f'{{"error": "Failed to reach origin server: {str(e)}"}}',
                status_code=502,
                media_type="application/json"
            )
