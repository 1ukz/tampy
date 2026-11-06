"""Fast HTTP-level replay for payload sweeps.

Driving the whole headed browser twice per payload is slow. Once a browser run
has established session state and captured the real in-flow requests (with their
cookies), we can resend the *targeted* request directly over HTTP many times --
cheaply and deterministically -- to sweep a set of payloads.

Trade-off vs browser replay: a single HTTP request will not reproduce
downstream pages or the payment-gateway hand-off, so this path is best for
confirming a *direct* effect (the response to the tampered request itself).
Browser replay remains the default for full-flow / gateway proof.

``send`` is injectable so the request-building can be unit-tested without
network access.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from core.tamper import apply_tamper

# Headers that must not be copied verbatim onto a fresh client request.
_DROP_HEADERS = {"content-length", "host", "connection", "accept-encoding"}


def _requests_send(request: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    import requests

    headers = {
        k: v for k, v in (request.get("headers") or {}).items() if k.lower() not in _DROP_HEADERS
    }
    method = (request.get("method") or "GET").upper()
    url = request.get("url", "")
    body = request.get("body")

    resp = requests.request(
        method,
        url,
        headers=headers,
        data=body.encode("utf-8") if isinstance(body, str) else body,
        timeout=timeout,
        verify=False,
        allow_redirects=True,
    )
    try:
        text = resp.text
    except Exception:
        text = ""
    return {
        "url": resp.url,
        "method": method,
        "request_body": body,
        "status": resp.status_code,
        "headers": dict(resp.headers),
        "body": text[:200_000],
    }


def replay(
    request: Dict[str, Any],
    tamper: Optional[Dict[str, Any]] = None,
    timeout: float = 15.0,
    sender: Optional[Callable[[Dict[str, Any], float], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Send ``request`` (optionally tampered) over HTTP and return a captured
    response dict compatible with the verifier/oracle."""
    req = apply_tamper(request, tamper) if tamper else request
    send = sender or _requests_send
    return send(req, timeout)
