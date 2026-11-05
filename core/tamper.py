"""Pure request-mutation shared by the browser and HTTP replay engines.

Keeping the "apply one tamper to a request" logic in one tested place means the
headed browser replay and the fast HTTP replay mutate requests identically, so
a payload confirmed by one behaves the same in the other.

A request is represented as a plain dict::

    {"method": "POST", "url": "...", "headers": {...}, "body": "..."}

``apply_tamper`` returns a new dict with exactly one parameter changed; it never
mutates the input.
"""

from __future__ import annotations

import copy
import json
import urllib.parse
from typing import Any, Dict, Optional

Request = Dict[str, Any]


def _set_query(url: str, name: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if name not in q:
        return url
    q[name] = [value]
    new_query = urllib.parse.urlencode(q, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _set_path_segment(url: str, index: int, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    segments = parsed.path.rstrip("/").split("/")
    if not 0 <= index < len(segments):
        return url
    segments[index] = value
    new_path = "/".join(segments)
    if parsed.path.endswith("/"):
        new_path += "/"
    return urllib.parse.urlunparse(parsed._replace(path=new_path))


def _set_body(body: Optional[str], content_type: str, name: str, value: str) -> Optional[str]:
    body = body or ""
    ctype = (content_type or "").lower()
    if "application/json" in ctype or (body.strip().startswith(("{", "[")) and "=" not in body[:1]):
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return body
        if isinstance(data, dict) and name in data:
            data[name] = value
            return json.dumps(data)
        return body
    # default: urlencoded form
    parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
    if name not in parsed:
        return body
    parsed[name] = [value]
    return urllib.parse.urlencode(parsed, doseq=True)


def apply_tamper(request: Request, tamper: Dict[str, Any]) -> Request:
    """Return a copy of ``request`` with the single tampered parameter applied.

    ``tamper`` keys: ``param_location`` (url_path|query|headers|body),
    ``param_name``, ``param_value``.
    """
    req = copy.deepcopy(request)
    loc = tamper.get("param_location")
    raw_name = tamper.get("param_name")
    if raw_name is None:
        return req
    name = str(raw_name)
    value = str(tamper.get("param_value"))
    headers = req.get("headers") or {}

    if loc == "query":
        req["url"] = _set_query(req.get("url", ""), name, value)
    elif loc == "url_path":
        try:
            req["url"] = _set_path_segment(req.get("url", ""), int(name), value)
        except (TypeError, ValueError):
            pass
    elif loc == "headers":
        # case-insensitive header match; add the header if absent.
        for k in list(headers.keys()):
            if k.lower() == str(name).lower():
                headers[k] = value
                break
        else:
            headers[name] = value
        req["headers"] = headers
    elif loc == "body":
        content_type = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                content_type = v
                break
        req["body"] = _set_body(req.get("body"), content_type, name, value)

    return req
