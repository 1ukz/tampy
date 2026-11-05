"""Signature / integrity-field awareness (Control 1.5).

Robust checkout flows protect critical parameters with an integrity value --
an HMAC, a signed token, a checksum. Redsys, for instance, sends
``Ds_Signature`` alongside the signed ``Ds_MerchantParameters``.

Knowing whether such a field is present next to a tampered parameter lets the
oracle give a *precise* reading instead of a vague one:

* Tamper **rejected** while a signature field is present  -> the value is
  **integrity-protected** (expected, good defence). Report it as such.
* Tamper **confirmed** while a signature field is present -> the signature does
  **not actually cover** the tampered field: a high-value finding (the merchant
  signs something, but not the thing that matters).

This module only *detects* signature fields and phrases the implication; it does
not attempt to forge or validate signatures.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Optional

_SIGNATURE_NAMES = (
    "signature",
    "sign",
    "ds_signature",
    "hmac",
    "hash",
    "mac",
    "checksum",
    "integrity",
    "digest",
    "sig",
    "token_hash",
    "firma",
)


def _looks_like_sig(name: str) -> bool:
    low = name.lower()
    # exact-ish match against known names or a clear suffix/substring
    return any(s == low or s in low for s in _SIGNATURE_NAMES)


def _params_from(url: str, body: Optional[str]) -> List[str]:
    names: List[str] = []
    q = urllib.parse.urlparse(url).query
    names += [k for k, _ in urllib.parse.parse_qsl(q, keep_blank_values=True)]
    if body:
        if "=" in body and not body.strip().startswith(("{", "[")):
            names += [k for k, _ in urllib.parse.parse_qsl(body, keep_blank_values=True)]
        else:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    names += [str(k) for k in data.keys()]
            except (json.JSONDecodeError, TypeError):
                pass
    return names


def signature_fields(
    url: str, body: Optional[str], headers: Optional[Dict[str, str]] = None
) -> List[str]:
    """Return the names of signature/integrity fields present on a request."""
    found: List[str] = []
    for n in _params_from(url, body):
        if _looks_like_sig(n) and n not in found:
            found.append(n)
    for hname in headers or {}:
        if _looks_like_sig(hname) and hname not in found:
            found.append(hname)
    return found


def annotate(reason: str, verdict_confirmed: bool, sig_fields: List[str]) -> str:
    """Append an integrity-implication clause to an oracle reason."""
    if not sig_fields:
        return reason
    fields = ", ".join(sig_fields)
    if verdict_confirmed:
        return (
            f"{reason} Note: a signature/integrity field ({fields}) is present on "
            f"the request, yet the tamper took effect -- the signature does not "
            f"cover the manipulated parameter."
        )
    return (
        f"{reason} A signature/integrity field ({fields}) protects this request, "
        f"which is consistent with the value being integrity-checked server-side."
    )


def find_on_request(captured: Any) -> List[str]:
    """Convenience: extract signature fields from a captured response/snapshot
    that carries ``url`` and ``request_body``."""
    url = getattr(captured, "url", "") or ""
    rb = getattr(captured, "request_body", None)
    return signature_fields(url, rb)
