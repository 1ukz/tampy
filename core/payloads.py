"""Deterministic payload sweeps per control.

The LLM proposes one ``test_payload`` per finding. In practice several related
payloads are worth trying -- a price of ``0.01`` may be clamped while ``-1``
isn't, a quantity of ``0`` may behave differently from ``-1``. Sweeping a small,
fixed set per parameter kind catches more live issues at **zero extra LLM
cost** (the payloads are generated locally, not by the model).

The model's own payload is always tried first and the sweep short-circuits on
the first confirmed hit, so the common case stays cheap.
"""

from __future__ import annotations

import re
from typing import List

from core.models import Finding

_PRICE = re.compile(r"(?i)(price|amount|total|subtotal|cost|charge|importe|monto|payable|due)")
_QTY = re.compile(r"(?i)(qty|quantity|units|count|stock|cantidad)")
_DISCOUNT = re.compile(r"(?i)(discount|percent|rate|descuento|rebate|off)")
_CURRENCY = re.compile(r"(?i)(currency|moneda|divisa)")

# Candidate sets, ordered most-impactful first.
_PRICE_SET = ["0.01", "0", "1", "-1", "0.00"]
_QTY_SET = ["-1", "0", "9999", "1.5"]
_DISCOUNT_SET = ["100", "99", "90"]
_CURRENCY_SET = ["USD", "EUR", "INR"]


def _dedupe(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def payloads_for(finding: Finding, limit: int = 5) -> List[str]:
    """Return an ordered list of payloads to try for a finding.

    The model's proposed payload is always first; a parameter-kind-specific set
    follows. For identifiers and unknown kinds only the model's payload is used
    (blind fuzzing of IDs is noise, not signal).
    """
    original = str(finding.test_payload)
    name = finding.parameter_name or ""

    extra: List[str] = []
    if _PRICE.search(name):
        extra = _PRICE_SET
    elif _QTY.search(name):
        extra = _QTY_SET
    elif _DISCOUNT.search(name):
        extra = _DISCOUNT_SET
    elif _CURRENCY.search(name):
        extra = _CURRENCY_SET

    return _dedupe([original, *extra])[:limit]
