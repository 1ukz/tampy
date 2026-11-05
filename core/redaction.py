"""Reversible secret redaction (P0).

The legacy ``anonymize_har`` only replaced the target domain string, so live
cookies, Authorization headers, bearer tokens, JWTs, emails and card-shaped
numbers were shipped verbatim to a third-party LLM. That is unacceptable for a
tool whose whole job is auditing someone's checkout.

This module replaces sensitive values with stable, reversible placeholders of
the form ``__TAMPY_<CATEGORY>_<n>__`` before egress. The placeholder<->value
map is kept on disk locally and used to re-inject the real values at replay
time (phase 4), so tampering still hits the server with valid credentials while
the LLM never sees them.

The placeholder alphabet (A-Z, 0-9, underscore) is safe inside URLs, JSON and
form-urlencoded bodies, so it survives a round-trip through the model.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any, Dict, List, Tuple

# Header names whose entire value is a secret.
SENSITIVE_HEADERS = {
    "cookie",
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "auth-token",
    "x-session-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-access-token",
    "x-refresh-token",
}

# Value patterns to redact anywhere they appear inside a string.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_BEARER = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._\-]+)")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Candidate card numbers: 13-19 digits optionally split by spaces/dashes.
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")

PLACEHOLDER_RE = re.compile(r"__TAMPY_[A-Z]+_\d+__")

# Cookie names that are session/auth secrets regardless of entropy.
_SESSIONISH = re.compile(
    r"(?i)(sess|token|auth|jwt|sid|csrf|xsrf|secret|api[_-]?key|pass(wd|word)?|"
    r"remember|refresh|access|bearer)"
)
# Set-Cookie attribute keywords that must be preserved (Control 1.2 needs them).
_COOKIE_ATTRS = {
    "path",
    "domain",
    "expires",
    "max-age",
    "samesite",
    "secure",
    "httponly",
    "version",
    "comment",
    "priority",
    "partitioned",
}


def _is_secret_value(v: str) -> bool:
    """Heuristic: is this cookie value a high-entropy secret?

    Kept deliberately conservative so low-entropy identifiers (numeric IDs,
    short flags) survive for IDOR analysis, while long random/base64/hex session
    blobs get redacted.
    """
    v = v.strip()
    if not v or v.isdigit() or len(v) < 8:
        return False
    if len(v) >= 20:
        return True
    has_alpha = any(c.isalpha() for c in v)
    has_digit = any(c.isdigit() for c in v)
    return has_alpha and has_digit and len(v) >= 12


def _luhn_ok(digits: str) -> bool:
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class Redactor:
    """Builds a reversible redaction map over arbitrary JSON structures."""

    def __init__(self) -> None:
        # original value -> placeholder (dedupes identical secrets)
        self._to_placeholder: Dict[str, str] = {}
        # placeholder -> original value (for re-injection)
        self._to_original: Dict[str, str] = {}
        self._counts: Counter = Counter()

    # -- map bookkeeping ---------------------------------------------------
    def _placeholder_for(self, value: str, category: str) -> str:
        if value in self._to_placeholder:
            return self._to_placeholder[value]
        n = self._counts[category]
        self._counts[category] += 1
        placeholder = f"__TAMPY_{category.upper()}_{n}__"
        self._to_placeholder[value] = placeholder
        self._to_original[placeholder] = value
        return placeholder

    # -- redaction ---------------------------------------------------------
    def _maybe_redact_cookie_pair(self, name: str, val: str) -> str:
        """Redact a single cookie value only if it looks secret.

        Low-entropy identifiers (e.g. ``cart_id=42``) are preserved so IDOR
        analysis still works; session/auth blobs are redacted.
        """
        if _SESSIONISH.search(name) or _is_secret_value(val):
            return f"{name}={self._placeholder_for(val, 'COOKIE')}"
        return f"{name}={val}"

    def _redact_cookie_header(self, value: str) -> str:
        # Request "Cookie" header: every "; " segment is a name=value pair.
        parts: List[str] = []
        for pair in value.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, _, val = pair.partition("=")
                parts.append(self._maybe_redact_cookie_pair(name.strip(), val.strip()))
            elif pair:
                parts.append(pair)
        return "; ".join(parts)

    def _redact_set_cookie_header(self, value: str) -> str:
        # "Set-Cookie": first segment is the cookie value; the rest are
        # attributes (Path, HttpOnly, Secure, SameSite...) that must be kept
        # intact so the model can evaluate cookie-flag controls.
        segments = [s.strip() for s in value.split(";")]
        if not segments:
            return value
        first = segments[0]
        if "=" in first:
            name, _, val = first.partition("=")
            segments[0] = self._maybe_redact_cookie_pair(name.strip(), val.strip())
        return "; ".join(segments)

    def _redact_string(self, value: str) -> str:
        value = _JWT.sub(lambda m: self._placeholder_for(m.group(0), "JWT"), value)
        value = _BEARER.sub(
            lambda m: "Bearer " + self._placeholder_for(m.group(1), "BEARER"), value
        )
        value = _EMAIL.sub(lambda m: self._placeholder_for(m.group(0), "EMAIL"), value)

        def _card_sub(m: re.Match) -> str:
            digits = re.sub(r"[ -]", "", m.group(0))
            if _luhn_ok(digits):
                return self._placeholder_for(m.group(0), "CARD")
            return m.group(0)

        value = _CARD.sub(_card_sub, value)
        return value

    def _redact_headers(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for name, val in headers.items():
            if not isinstance(val, str):
                out[name] = val
                continue
            lname = name.lower()
            if lname == "cookie":
                out[name] = self._redact_cookie_header(val)
            elif lname == "set-cookie":
                out[name] = self._redact_set_cookie_header(val)
            elif lname in SENSITIVE_HEADERS:
                out[name] = self._placeholder_for(val, "AUTH")
            else:
                out[name] = self._redact_string(val)
        return out

    def redact_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Return a redacted copy of a single filtered packet dict."""
        p = json.loads(json.dumps(packet))  # deep copy
        if isinstance(p.get("headers"), dict):
            p["headers"] = self._redact_headers(p["headers"])
        if isinstance(p.get("body"), str):
            p["body"] = self._redact_string(p["body"])
        resp = p.get("response")
        if isinstance(resp, dict) and isinstance(resp.get("headers"), dict):
            resp["headers"] = self._redact_headers(resp["headers"])
        return p

    def redact_packets(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.redact_packet(pkt) for pkt in packets]

    def redact_text(self, value: str) -> str:
        """Redact secrets from an arbitrary string (e.g. a response-body excerpt
        before it is sent to the LLM judge). Applies the value-pattern rules
        (JWT, bearer, email, card); does not attempt cookie-header parsing."""
        if not isinstance(value, str) or not value:
            return value
        return self._redact_string(value)

    # -- re-injection ------------------------------------------------------
    def reinject(self, obj: Any) -> Any:
        """Recursively replace placeholders with their original values."""
        if isinstance(obj, str):
            if "__TAMPY_" not in obj:
                return obj
            return PLACEHOLDER_RE.sub(lambda m: self._to_original.get(m.group(0), m.group(0)), obj)
        if isinstance(obj, dict):
            return {k: self.reinject(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.reinject(v) for v in obj]
        return obj

    # -- persistence & reporting ------------------------------------------
    def report(self) -> Dict[str, int]:
        """Counts per category, for a pre-egress sanity check."""
        return {cat: cnt for cat, cnt in sorted(self._counts.items())}

    def save_map(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._to_original, f, indent=2)

    @classmethod
    def load_map(cls, path: str) -> Redactor:
        inst = cls()
        with open(path, encoding="utf-8") as f:
            inst._to_original = json.load(f)
        inst._to_placeholder = {v: k for k, v in inst._to_original.items()}
        return inst


def redact_packets_file(in_path: str, out_path: str, map_path: str) -> Tuple[str, Dict[str, int]]:
    """Redact a filtered-packets JSON file to a new file, saving the map.

    Returns the output path and the redaction report (counts per category).
    """
    with open(in_path, encoding="utf-8") as f:
        packets = json.load(f)
    redactor = Redactor()
    redacted = redactor.redact_packets(packets)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(redacted, f, indent=2)
    redactor.save_map(map_path)
    return out_path, redactor.report()
