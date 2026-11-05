"""Payment-gateway awareness (Redsys, Stripe, PayPal, ...).

E-commerce purchase flows almost always hand off to an external payment
gateway ("pasarela de pago"). The amount sent to that gateway is the money the
customer is actually charged, so if a tampered price propagates all the way to
the gateway request, that is the single strongest confirmation of a live price
manipulation -- stronger than anything on the merchant's own pages.

Two problems this module solves:

1. **Capture.** Gateways live on a *different* origin, so a same-origin-only
   capture would miss them. ``gateway_for_url`` lets the replay keep these
   cross-origin requests.
2. **Amount extraction.** The charge amount is encoded differently per gateway.
   Most importantly for Spain/EU, **Redsys** packs it into a base64 JSON blob
   (``Ds_MerchantParameters`` -> ``DS_MERCHANT_AMOUNT`` in minor units). This
   module decodes that and a set of generic ``amount``-style fields so the
   oracle can compare the charge between the baseline and tampered runs.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional

# Known payment-gateway host patterns (regex, matched against the netloc).
_GATEWAYS: Dict[str, List[re.Pattern]] = {
    "redsys": [re.compile(r"(^|\.)sis(-[ti])?\.redsys\.es$", re.I)],
    "stripe": [re.compile(r"(^|\.)(checkout|js|api|pay)\.stripe\.com$", re.I)],
    "paypal": [
        re.compile(r"(^|\.)paypal\.com$", re.I),
        re.compile(r"(^|\.)paypalobjects\.com$", re.I),
    ],
    "adyen": [
        re.compile(r"(^|\.)adyen\.com$", re.I),
        re.compile(r"(^|\.)adyenpayments\.com$", re.I),
    ],
    "braintree": [
        re.compile(r"(^|\.)braintreegateway\.com$", re.I),
        re.compile(r"(^|\.)braintree-api\.com$", re.I),
    ],
    "worldpay": [re.compile(r"(^|\.)worldpay\.com$", re.I)],
    "mollie": [re.compile(r"(^|\.)mollie\.com$", re.I)],
    "klarna": [re.compile(r"(^|\.)klarna\.com$", re.I)],
    "checkoutcom": [re.compile(r"(^|\.)checkout\.com$", re.I)],
    "sumup": [re.compile(r"(^|\.)sumup\.com$", re.I)],
    "sabadell": [re.compile(r"(^|\.)sabadell\.es$", re.I)],
    "ceca": [re.compile(r"(^|\.)cecabank\.es$", re.I), re.compile(r"(^|\.)ceca\.es$", re.I)],
    "paycomet": [re.compile(r"(^|\.)paycomet\.com$", re.I)],
    "square": [re.compile(r"(^|\.)squareup\.com$", re.I)],
    "razorpay": [re.compile(r"(^|\.)razorpay\.com$", re.I)],
}

# Field names (case-insensitive) that commonly carry a charge amount.
_AMOUNT_FIELDS = re.compile(
    r"(?i)^(ds_merchant_amount|amount|importe|total|monto|value|price|"
    r"transactionamount|paymentamount|order_?amount)$"
)


def gateway_for_url(url: str) -> Optional[str]:
    """Return the gateway name if ``url``'s host is a known gateway, else None."""
    if not url:
        return None
    host = urllib.parse.urlparse(url).netloc.split("@")[-1].split(":")[0]
    for name, patterns in _GATEWAYS.items():
        if any(p.search(host) for p in patterns):
            return name.strip()
    return None


def _b64_json(value: str) -> Optional[Any]:
    """Decode a (possibly url-safe) base64 JSON blob, tolerating padding."""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = value + "=" * (-len(value) % 4)
            return json.loads(decoder(padded).decode("utf-8", "replace"))
        except Exception:
            continue
    return None


def _to_amount(value: Any) -> Optional[float]:
    try:
        return float(str(value).replace(",", ".").strip())
    except (ValueError, AttributeError, TypeError):
        return None


def _params_from(url: str, body: Optional[str]) -> Dict[str, str]:
    """Collect scalar params from a URL query and a request body."""
    params: Dict[str, str] = {}
    q = urllib.parse.urlparse(url).query
    for k, v in urllib.parse.parse_qsl(q, keep_blank_values=True):
        params[k] = v
    if body:
        # Try urlencoded form first, then JSON.
        if "=" in body and "{" not in body[:1]:
            for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True):
                params.setdefault(k, v)
        else:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    for k, v in data.items():
                        if not isinstance(v, (dict, list)):
                            params.setdefault(str(k), str(v))
            except (json.JSONDecodeError, TypeError):
                pass
    return params


def extract_charge_amounts(url: str, request_body: Optional[str]) -> List[Dict[str, Any]]:
    """Extract charge amounts from a gateway request.

    Returns a list of ``{gateway, field, amount, currency?}`` dicts (empty if
    the URL is not a gateway or no amount is found).
    """
    gateway = gateway_for_url(url)
    if not gateway:
        return []

    params = _params_from(url, request_body)
    # Case-insensitive lookup.
    lower = {k.lower(): v for k, v in params.items()}
    out: List[Dict[str, Any]] = []

    # Redsys: amount is inside the base64 JSON Ds_MerchantParameters blob.
    if "ds_merchantparameters" in lower:
        decoded = _b64_json(lower["ds_merchantparameters"])
        if isinstance(decoded, dict):
            dlow = {str(k).lower(): v for k, v in decoded.items()}
            amt = _to_amount(dlow.get("ds_merchant_amount"))
            if amt is not None:
                out.append(
                    {
                        "gateway": gateway,
                        "field": "DS_MERCHANT_AMOUNT",
                        # Redsys amounts are in minor units (cents).
                        "amount": amt / 100.0,
                        "raw": amt,
                        "currency": dlow.get("ds_merchant_currency"),
                    }
                )

    # Generic amount-bearing fields.
    for key, val in params.items():
        if key.lower() == "ds_merchantparameters":
            continue
        if _AMOUNT_FIELDS.search(key):
            amt = _to_amount(val)
            if amt is not None:
                out.append({"gateway": gateway, "field": key, "amount": amt})

    return out
