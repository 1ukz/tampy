"""Deterministic verification oracle (P1).

The agentic value of TAMPY comes from *verifying* a hypothesis, not just
suggesting it. But doing that with an LLM in the loop is expensive. So the
oracle is pure Python: it compares a baseline response (flow replayed
untampered) with the tampered response and decides, with no tokens spent,
whether the tamper took effect.

Only genuinely ambiguous cases (``INCONCLUSIVE``) need to be escalated to an
LLM judge by the caller, which keeps cost close to a one-shot run.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from pydantic import BaseModel

from core.models import Finding, OracleResult, Verdict

# Status codes that signal the server rejected the tampered input outright.
_REJECT_STATUSES = {400, 401, 403, 409, 422}

# Parameter names whose manipulation we can price-check numerically.
_VALUE_PARAMS = re.compile(
    r"(?i)(price|amount|total|cost|qty|quantity|discount|balance|credit|points)"
)


class ResponseSnapshot(BaseModel):
    """A captured HTTP response for the tampered request."""

    model_config = {"extra": "ignore"}

    url: str
    status: Optional[int] = None
    headers: Dict[str, str] = {}
    body: str = ""

    def json_body(self) -> Optional[Any]:
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, TypeError):
            return None


def _contains(body: str, value: str) -> bool:
    if not body or value is None:
        return False
    return str(value) in body


def _numeric(value: Any) -> Optional[float]:
    try:
        return float(str(value).replace(",", "").strip())
    except (ValueError, AttributeError):
        return None


def evaluate(
    finding: Finding,
    tamper_value: str,
    baseline: Optional[ResponseSnapshot],
    tampered: Optional[ResponseSnapshot],
) -> OracleResult:
    """Decide whether the tamper took effect, deterministically."""

    if tampered is None:
        return OracleResult(
            verdict=Verdict.ERROR,
            reason="No tampered response was captured (replay/transport failure).",
        )

    b_status = baseline.status if baseline else None
    t_status = tampered.status
    signals: Dict[str, Any] = {}

    # 1) Hard rejection by status code.
    if t_status in _REJECT_STATUSES:
        return OracleResult(
            verdict=Verdict.REJECTED,
            reason=f"Server rejected the tampered value with HTTP {t_status}.",
            baseline_status=b_status,
            tampered_status=t_status,
        )

    # 2) Server error from unexpected input: notable but not a confirmed bypass.
    if t_status is not None and t_status >= 500:
        return OracleResult(
            verdict=Verdict.LIKELY,
            reason=(
                f"Tampered value triggered HTTP {t_status}; the input was not "
                "validated cleanly, which often indicates weak server-side checks."
            ),
            baseline_status=b_status,
            tampered_status=t_status,
        )

    # 3) Accepted (2xx/3xx). Look for evidence the value actually took effect.
    reflected = _contains(tampered.body, tamper_value)
    baseline_reflected = _contains(baseline.body, tamper_value) if baseline else False
    signals["value_reflected"] = reflected
    signals["reflected_in_baseline"] = baseline_reflected

    # 3a) Numeric value-bearing parameter: did a total/price drop in the response?
    if _VALUE_PARAMS.search(finding.parameter_name):
        drop = _detect_value_drop(baseline, tampered, tamper_value)
        if drop is not None:
            signals.update(drop)
            if drop.get("decreased"):
                return OracleResult(
                    verdict=Verdict.CONFIRMED,
                    reason=(
                        "A monetary/quantity figure in the response decreased after "
                        f"tampering ({drop.get('from')} -> {drop.get('to')}), "
                        "indicating the manipulated value was honoured server-side."
                    ),
                    baseline_status=b_status,
                    tampered_status=t_status,
                    signals=signals,
                )

    # 3b) Our injected value is reflected in the accepted response and was NOT
    #     already present in the baseline -> the server took it.
    if reflected and not baseline_reflected and t_status and t_status < 400:
        return OracleResult(
            verdict=Verdict.CONFIRMED,
            reason=(
                "The tampered value is reflected in an accepted (2xx) response and "
                "was absent from the baseline, indicating it was accepted server-side."
            ),
            baseline_status=b_status,
            tampered_status=t_status,
            signals=signals,
        )

    # 3c) Response changed meaningfully vs baseline but no direct value proof.
    if baseline is not None:
        delta = _body_delta(baseline, tampered)
        signals["body_delta"] = delta
        if delta is not None and delta >= 0.15:
            return OracleResult(
                verdict=Verdict.LIKELY,
                reason=(
                    "The tampered response differs substantially from the baseline "
                    f"(~{int(delta * 100)}% change) with a 2xx status; manual "
                    "confirmation recommended."
                ),
                baseline_status=b_status,
                tampered_status=t_status,
                signals=signals,
            )

    # 4) Accepted but no distinguishing signal -> escalate to an LLM judge.
    return OracleResult(
        verdict=Verdict.INCONCLUSIVE,
        reason=(
            "The tampered request was accepted but no deterministic signal "
            "confirms impact; an LLM judge or manual review is warranted."
        ),
        baseline_status=b_status,
        tampered_status=t_status,
        signals=signals,
    )


def _detect_value_drop(
    baseline: Optional[ResponseSnapshot],
    tampered: ResponseSnapshot,
    tamper_value: str,
) -> Optional[Dict[str, Any]]:
    """Compare the max numeric figure in baseline vs tampered JSON responses.

    A decrease in the largest monetary-looking number is a strong signal that a
    price/quantity tamper was honoured.
    """
    if baseline is None:
        return None
    b_json, t_json = baseline.json_body(), tampered.json_body()
    if b_json is None or t_json is None:
        return None
    b_max = _max_number(b_json)
    t_max = _max_number(t_json)
    if b_max is None or t_max is None:
        return None
    return {
        "from": b_max,
        "to": t_max,
        "decreased": t_max < b_max,
    }


def _max_number(obj: Any) -> Optional[float]:
    """Largest numeric leaf in a JSON structure (proxy for an order total)."""
    best: Optional[float] = None
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
        else:
            n = _numeric(cur)
            if n is not None and (best is None or n > best):
                best = n
    return best


def _body_delta(baseline: ResponseSnapshot, tampered: ResponseSnapshot) -> Optional[float]:
    """Rough normalised size/character delta between two bodies (0..1)."""
    a, b = baseline.body or "", tampered.body or ""
    if not a and not b:
        return 0.0
    longest = max(len(a), len(b)) or 1
    return abs(len(a) - len(b)) / longest
