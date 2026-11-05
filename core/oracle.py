"""Deterministic verification oracle (P1).

The agentic value of TAMPY is *verifying*, with precision, whether a proposed
issue is actually live on the target -- not merely suggesting it. Doing that
with an LLM in the loop would be expensive and non-reproducible, so the oracle
is pure Python: it compares the whole flow replayed **untampered** (baseline)
against the flow replayed **tampered**, and decides with no tokens spent.

Precision design (why this beats a naive "did the response change?"):

* **Whole-flow observation.** In a purchase flow the proof of a price/qty
  tamper usually appears *downstream* (the checkout/confirmation total), not in
  the immediate response. The oracle is given every response from both runs.
* **Same-field comparison.** It pairs responses by path, flattens their JSON,
  and compares *the same monetary field* across baseline vs tampered -- instead
  of guessing the "largest number" is the total (which IDs/timestamps fool).
* **Error-context awareness.** A value echoed inside an error body, or a 2xx
  carrying ``{"success": false}``, is treated as a rejection, not a hit, which
  removes the main class of false positives.
* **Authorization semantics for IDOR.** For id-like parameters the verdict is
  driven by whether access was granted to a *different* resource vs blocked.
* **Calibrated confidence.** Signals combine into a 0..1 confidence; only a
  high score yields CONFIRMED ("live"). Mid scores are LIKELY; genuine
  ambiguity is INCONCLUSIVE and is what the LLM judge is reserved for.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel

from core.gateways import extract_charge_amounts
from core.models import Finding, OracleResult, Verdict

# Status codes that signal the server rejected the tampered input outright.
_REJECT_STATUSES = {400, 401, 403, 404, 409, 422}

# Final-segment field names that denote money/quantity totals in a response.
_MONETARY = re.compile(
    r"(?i)(price|amount|total|subtotal|grand|cost|balance|due|payable|charge|"
    r"sum|discount|credit|points|qty|quantity)"
)

# Parameter names / kinds that identify a resource (IDOR surface).
_ID_PARAM = re.compile(
    r"(?i)(^id$|_id$|^id|user|order|account|profile|address|cart|invoice|"
    r"customer|uuid|guid|email|token|ref)"
)

# Error signals inside an otherwise-2xx response body.
_ERROR_TOKENS = re.compile(
    r"(?i)\b(error|invalid|denied|forbidden|unauthori[sz]ed|not\s+allowed|"
    r"declined|failed|cannot|could\s+not|out\s+of\s+stock|not\s+found)\b"
)

# Confidence thresholds -> verdict.
_CONFIRM_AT = 0.70
_LIKELY_AT = 0.40

ResponseLike = Union["ResponseSnapshot", None]


class ResponseSnapshot(BaseModel):
    """A single captured HTTP response from a replay."""

    model_config = {"extra": "ignore"}

    url: str
    method: Optional[str] = None
    status: Optional[int] = None
    headers: Dict[str, str] = {}
    body: str = ""
    request_body: Optional[str] = None  # request payload, kept for gateway amounts

    def path(self) -> str:
        return urllib.parse.urlparse(self.url).path.rstrip("/")

    def json_body(self) -> Optional[Any]:
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, TypeError):
            return None


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #
def _numeric(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        return float(str(value).replace(",", "").strip())
    except (ValueError, AttributeError):
        return None


def _as_list(x: Union[ResponseLike, List[ResponseSnapshot]]) -> List[ResponseSnapshot]:
    if x is None:
        return []
    if isinstance(x, list):
        return [r for r in x if r is not None]
    return [x]


def _flatten(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten a JSON structure to ``dotted.path -> scalar`` leaves."""
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.update(_flatten(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        if prefix:
            out[prefix] = obj
    return out


def _leaf_name(path: str) -> str:
    return path.split(".")[-1].split("[")[0]


def _looks_like_error(resp: Optional[ResponseSnapshot]) -> bool:
    """Detect an error context even behind a 2xx status."""
    if resp is None:
        return False
    if resp.status is not None and resp.status >= 400:
        return True
    j = resp.json_body()
    if isinstance(j, dict):
        if j.get("error") or j.get("errors"):
            return True
        if j.get("success") is False or j.get("ok") is False:
            return True
        status_field = str(j.get("status", "")).lower()
        if status_field in {"error", "failed", "failure", "denied"}:
            return True
    # Token check only on JSON or small bodies, to avoid flagging large HTML
    # pages that merely contain the word "error" somewhere.
    if j is not None or len(resp.body) < 800:
        if _ERROR_TOKENS.search(resp.body or ""):
            return True
    return False


def _find_target(
    responses: List[ResponseSnapshot], want_path: str, want_method: str
) -> Optional[ResponseSnapshot]:
    want_path = want_path.rstrip("/")
    matches = [
        r
        for r in responses
        if r.path() == want_path and (r.method or want_method).upper() == want_method.upper()
    ]
    # Prefer the last matching occurrence (closest to the tamper's effect).
    return matches[-1] if matches else None


def _monetary_changes(
    baseline: List[ResponseSnapshot], tampered: List[ResponseSnapshot]
) -> List[Dict[str, Any]]:
    """Compare the *same* monetary field across the two flows, paired by path.

    Between two otherwise-identical runs, a monetary total only changes because
    the injected value was honoured server-side -- so any such change is strong,
    precise evidence (far better than comparing the largest number).
    """

    def index(lst: List[ResponseSnapshot]) -> Dict[str, Dict[str, Any]]:
        d: Dict[str, Dict[str, Any]] = {}
        for r in lst:
            j = r.json_body()
            if j is None:
                continue
            d.setdefault(r.path(), {}).update(_flatten(j))
        return d

    b_idx, t_idx = index(baseline), index(tampered)
    changes: List[Dict[str, Any]] = []
    for path, t_flat in t_idx.items():
        b_flat = b_idx.get(path, {})
        for key, t_val in t_flat.items():
            if not _MONETARY.search(_leaf_name(key)):
                continue
            if key not in b_flat:
                continue
            t_num, b_num = _numeric(t_val), _numeric(b_flat[key])
            if t_num is None or b_num is None:
                continue
            if abs(t_num - b_num) > 1e-9:
                changes.append(
                    {
                        "field": f"{path}:{key}" if path else key,
                        "from": b_num,
                        "to": t_num,
                        "decreased": t_num < b_num,
                        "increased": t_num > b_num,
                    }
                )
    return changes


def _gateway_amounts(responses: List[ResponseSnapshot]) -> Dict[str, Dict[str, Any]]:
    """Map (gateway, field) -> amount info across a flow's gateway requests."""
    found: Dict[str, Dict[str, Any]] = {}
    for r in responses:
        for amt in extract_charge_amounts(r.url, r.request_body):
            key = f"{amt['gateway']}:{amt['field']}"
            # Keep the last occurrence (closest to the final charge).
            found[key] = amt
    return found


def _gateway_amount_change(
    baseline: List[ResponseSnapshot], tampered: List[ResponseSnapshot]
) -> Optional[Dict[str, Any]]:
    """Detect a changed charge amount at a payment gateway between the runs."""
    b_amts = _gateway_amounts(baseline)
    t_amts = _gateway_amounts(tampered)
    for key, t in t_amts.items():
        b = b_amts.get(key)
        if b is None:
            continue
        if abs(float(t["amount"]) - float(b["amount"])) > 1e-9:
            return {
                "gateway": t["gateway"],
                "field": t["field"],
                "from": b["amount"],
                "to": t["amount"],
                "currency": t.get("currency"),
            }
    return None


def _body_differs(a: Optional[ResponseSnapshot], b: Optional[ResponseSnapshot]) -> float:
    """Normalised difference (0..1) between two response bodies."""
    sa = a.body if a else ""
    sb = b.body if b else ""
    if not sa and not sb:
        return 0.0
    longest = max(len(sa), len(sb)) or 1
    return abs(len(sa) - len(sb)) / longest


def _reflected_in_success(
    tampered: List[ResponseSnapshot], baseline: List[ResponseSnapshot], value: str
) -> bool:
    """Injected value appears in an accepted, non-error tampered response and was
    not already present anywhere in the baseline."""
    if not value:
        return False
    in_baseline = any(value in (r.body or "") for r in baseline)
    if in_baseline:
        return False
    for r in tampered:
        if r.status is not None and r.status < 400 and not _looks_like_error(r):
            if value in (r.body or ""):
                return True
    return False


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def evaluate(
    finding: Finding,
    tamper_value: str,
    baseline: Union[ResponseLike, List[ResponseSnapshot]],
    tampered: Union[ResponseLike, List[ResponseSnapshot]],
) -> OracleResult:
    """Decide, with precision, whether the tamper is live on the target.

    ``baseline`` / ``tampered`` may be a single response or the full list of
    responses captured during each replay; a list enables downstream proof.
    """
    base_list = _as_list(baseline)
    tamp_list = _as_list(tampered)

    if not tamp_list:
        return OracleResult(
            verdict=Verdict.ERROR,
            confidence=0.0,
            reason="No tampered response was captured (replay/transport failure).",
        )

    want_path = urllib.parse.urlparse(finding.modified_request_example.url).path
    want_method = finding.modified_request_example.method or "GET"
    target = _find_target(tamp_list, want_path, want_method) or tamp_list[-1]
    base_target = _find_target(base_list, want_path, want_method) or (
        base_list[-1] if base_list else None
    )

    t_status = target.status
    b_status = base_target.status if base_target else None
    signals: Dict[str, Any] = {
        "target_status": t_status,
        "baseline_status": b_status,
    }

    # 1) Hard rejection: the targeted request itself was refused.
    if t_status in _REJECT_STATUSES:
        return OracleResult(
            verdict=Verdict.REJECTED,
            confidence=0.0,
            reason=f"Server rejected the tampered request with HTTP {t_status}.",
            baseline_status=b_status,
            tampered_status=t_status,
            signals=signals,
        )

    target_error = _looks_like_error(target)
    signals["target_error_context"] = target_error

    # 1b) Payment-gateway charge amount changed between the two runs. This is
    # the money the customer is actually charged, so it is the most decisive
    # proof of a live price manipulation -- checked ahead of everything else.
    gw_change = _gateway_amount_change(base_list, tamp_list)
    if gw_change:
        signals["gateway_amount_change"] = gw_change
        return OracleResult(
            verdict=Verdict.CONFIRMED,
            confidence=0.97,
            reason=(
                f"Live price manipulation confirmed at the payment gateway "
                f"({gw_change['gateway']}): charge amount changed "
                f"{gw_change['from']} -> {gw_change['to']} "
                f"(field {gw_change['field']}) between baseline and tampered runs. "
                f"The tampered price propagated to what the customer is charged."
            ),
            baseline_status=b_status,
            tampered_status=t_status,
            signals=signals,
        )

    # 2) IDOR / authorization surface (id-like parameter or a path segment).
    is_id_surface = finding.parameter_location.value == "url_path" or bool(
        _ID_PARAM.search(finding.parameter_name)
    )
    if is_id_surface:
        return _evaluate_idor(target, base_target, target_error, b_status, t_status, signals)

    # 3) Value / business-logic surface.
    return _evaluate_value(
        finding,
        tamper_value,
        base_list,
        tamp_list,
        target,
        target_error,
        b_status,
        t_status,
        signals,
    )


def _evaluate_idor(target, base_target, target_error, b_status, t_status, signals):
    # Access actively blocked at the application layer (2xx error envelope).
    if target_error:
        return OracleResult(
            verdict=Verdict.REJECTED,
            confidence=0.0,
            reason=(
                "The alternate identifier was not served: the response carries an "
                "error/denied context, so access control held."
            ),
            baseline_status=b_status,
            tampered_status=t_status,
            signals=signals,
        )

    if t_status is not None and 200 <= t_status < 400:
        diff = _body_differs(base_target, target)
        signals["body_diff_ratio"] = round(diff, 3)
        # A different, non-trivial resource was returned for someone else's id.
        if diff >= 0.10 and target and len((target.body or "").strip()) > 40:
            return OracleResult(
                verdict=Verdict.CONFIRMED,
                confidence=0.78,
                reason=(
                    "Requesting a different object identifier returned a distinct, "
                    "non-error resource (IDOR): access control did not scope the "
                    "object to the current user."
                ),
                baseline_status=b_status,
                tampered_status=t_status,
                signals=signals,
            )
        # Accepted but response ~identical: value may have been ignored/normalised.
        return OracleResult(
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.30,
            reason=(
                "The alternate identifier was accepted (2xx) but the response is "
                "nearly identical to the baseline; impact is unclear and warrants "
                "an LLM judge or manual review."
            ),
            baseline_status=b_status,
            tampered_status=t_status,
            signals=signals,
        )

    return OracleResult(
        verdict=Verdict.INCONCLUSIVE,
        confidence=0.2,
        reason=f"Inconclusive authorization outcome (HTTP {t_status}).",
        baseline_status=b_status,
        tampered_status=t_status,
        signals=signals,
    )


def _evaluate_value(
    finding,
    tamper_value,
    base_list,
    tamp_list,
    target,
    target_error,
    b_status,
    t_status,
    signals,
):
    accepted = t_status is not None and 200 <= t_status < 400 and not target_error

    changes = _monetary_changes(base_list, tamp_list)
    signals["monetary_changes"] = changes
    reflected = _reflected_in_success(tamp_list, base_list, tamper_value)
    signals["value_reflected_in_success"] = reflected

    confidence = 0.0
    reasons: List[str] = []

    # Strongest signal: a monetary total actually changed between the two runs.
    if changes:
        c = changes[0]
        if accepted:
            confidence = max(confidence, 0.85)
        else:
            confidence = max(confidence, 0.55)
        direction = "decreased" if c["decreased"] else "increased"
        reasons.append(
            f"monetary field '{c['field']}' {direction} {c['from']} -> {c['to']} "
            f"between baseline and tampered runs"
        )

    # Injected value accepted and reflected in a non-error response.
    if reflected and accepted:
        confidence = max(confidence, 0.72)
        reasons.append("the injected value is reflected in an accepted, non-error response")

    # Server error from the tampered input: weak validation, notable but not proof.
    if t_status is not None and t_status >= 500:
        confidence = max(confidence, 0.45)
        reasons.append(f"the tampered value triggered HTTP {t_status} (weak input validation)")

    # A clear body change with a clean 2xx but no direct field proof.
    if accepted and not changes and not reflected:
        diff = _body_differs(_target_in(base_list, finding), target)
        signals["body_diff_ratio"] = round(diff, 3)
        if diff >= 0.15:
            confidence = max(confidence, 0.45)
            reasons.append(f"the tampered response differs ~{int(diff * 100)}% from baseline")

    # A 2xx carrying an error/denied envelope is an application-level rejection
    # (distinct from a 5xx, which is weak-validation evidence handled above).
    is_server_error = t_status is not None and t_status >= 500
    if target_error and not changes and not reflected and not is_server_error:
        return OracleResult(
            verdict=Verdict.REJECTED,
            confidence=0.0,
            reason=(
                "The tampered value was accepted transport-wise but the response "
                "carries an error/denied context, so it was not honoured."
            ),
            baseline_status=b_status,
            tampered_status=t_status,
            signals=signals,
        )

    verdict = _verdict_for(confidence)
    reason = _compose_reason(verdict, reasons)
    return OracleResult(
        verdict=verdict,
        confidence=round(confidence, 2),
        reason=reason,
        baseline_status=b_status,
        tampered_status=t_status,
        signals=signals,
    )


def _target_in(base_list, finding):
    want_path = urllib.parse.urlparse(finding.modified_request_example.url).path
    want_method = finding.modified_request_example.method or "GET"
    return _find_target(base_list, want_path, want_method) or (base_list[-1] if base_list else None)


def _verdict_for(confidence: float) -> Verdict:
    if confidence >= _CONFIRM_AT:
        return Verdict.CONFIRMED
    if confidence >= _LIKELY_AT:
        return Verdict.LIKELY
    return Verdict.INCONCLUSIVE


def _compose_reason(verdict: Verdict, reasons: List[str]) -> str:
    if not reasons:
        return (
            "The tampered request was accepted but no deterministic signal confirms "
            "impact; escalate to an LLM judge or review manually."
        )
    joined = "; ".join(reasons)
    if verdict == Verdict.CONFIRMED:
        return f"Live issue confirmed: {joined}."
    if verdict == Verdict.LIKELY:
        return f"Likely exploitable: {joined}; confirmation recommended."
    return f"Weak signal only: {joined}; inconclusive."
