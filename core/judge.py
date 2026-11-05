"""LLM judge for INCONCLUSIVE verdicts (P1 follow-up).

The deterministic oracle resolves most cases for free. The handful it marks
``INCONCLUSIVE`` -- accepted requests with no clear signal -- are the only ones
worth spending tokens on. This module sends a *small, redacted* evidence bundle
(status codes + short body excerpts of the few relevant responses) to the LLM
and asks for a conservative CONFIRMED / REJECTED / INCONCLUSIVE ruling.

Cost control: one call, only for inconclusive findings, with trimmed evidence.
Privacy: every excerpt is run through the redactor before egress, so the judge
never sees raw cookies/tokens/PII, consistent with the Phase 3 guarantee.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from core.models import Finding, OracleResult, Verdict

_MAX_BODY = 600  # chars of each response body sent to the judge
_MAX_RESPONSES = 6  # cap on responses included in the evidence bundle

JUDGE_SYSTEM = (
    "You are a precise web-application penetration-testing judge. You are given "
    "a proposed e-commerce business-logic / price / IDOR issue and the evidence "
    "from replaying the purchase flow twice: once UNTAMPERED (baseline) and once "
    "TAMPERED. Decide whether the tampering is actually live.\n"
    "Be conservative and evidence-driven:\n"
    "- 'confirmed': the evidence shows the tampered value took effect (e.g. a "
    "total/charge changed, a different resource was returned, a restricted "
    "action succeeded).\n"
    "- 'rejected': the server ignored or blocked the tampered value (unchanged "
    "result, error/denied response, validation).\n"
    "- 'inconclusive': the evidence genuinely does not allow a decision.\n"
    "Do not assume exploitability without evidence. Output ONLY a JSON object: "
    '{"verdict": "confirmed|rejected|inconclusive", "confidence": 0.0-1.0, '
    '"rationale": "one concise sentence"}.'
)

_VERDICT_MAP = {
    "confirmed": Verdict.CONFIRMED,
    "rejected": Verdict.REJECTED,
    "inconclusive": Verdict.INCONCLUSIVE,
}


def _excerpt(body: str, redactor) -> str:
    body = (body or "")[:_MAX_BODY]
    if redactor is not None:
        try:
            body = redactor.redact_text(body)
        except Exception:
            pass
    return body


def _evidence(responses, redactor) -> List[Dict[str, Any]]:
    """Trim a captured flow into a small, redacted evidence list."""
    out: List[Dict[str, Any]] = []
    # Keep the last N responses (closest to the outcome / confirmation).
    for r in list(responses)[-_MAX_RESPONSES:]:
        out.append(
            {
                "url": r.url,
                "method": r.method,
                "status": r.status,
                "body": _excerpt(r.body, redactor),
            }
        )
    return out


def build_judge_messages(
    finding: Finding,
    oracle: OracleResult,
    baseline,
    tampered,
    redactor=None,
) -> List[Dict[str, str]]:
    """Build the (cache-friendly) judge message list. Pure / testable."""
    user = {
        "finding": {
            "control_id": finding.control_id,
            "parameter": finding.parameter_name,
            "location": finding.parameter_location.value,
            "payload": finding.test_payload,
            "hypothesis": finding.exploitation_hypothesis,
        },
        "oracle": {
            "verdict": oracle.verdict.value,
            "reason": oracle.reason,
            "signals": oracle.signals,
        },
        "baseline_responses": _evidence(baseline, redactor),
        "tampered_responses": _evidence(tampered, redactor),
    }
    return [
        {"role": "system", "content": JUDGE_SYSTEM},
        {"role": "user", "content": json.dumps(user, separators=(",", ":"))},
    ]


def parse_judge(text: str) -> Optional[Dict[str, Any]]:
    """Parse the judge's JSON ruling into {verdict, confidence, rationale}."""
    from core.llm import extract_json_object

    obj = extract_json_object(text)
    if not isinstance(obj, dict):
        return None
    verdict = str(obj.get("verdict", "")).strip().lower()
    if verdict not in _VERDICT_MAP:
        return None
    try:
        confidence = float(obj.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))
    return {
        "verdict": _VERDICT_MAP[verdict],
        "confidence": confidence,
        "rationale": str(obj.get("rationale", "")).strip(),
    }


def _llm_config(mode: str):
    if mode == "remote":
        return (
            os.getenv("REMOTE_API_KEY"),
            os.getenv("REMOTE_BASE_URL"),
            os.getenv("REMOTE_MODEL_NAME"),
        )
    return ("not-needed", os.getenv("LOCAL_BASE_URL"), os.getenv("LOCAL_MODEL_NAME"))


def judge_finding(
    finding: Finding,
    oracle: OracleResult,
    baseline,
    tampered,
    mode: str = "remote",
    redactor=None,
) -> Optional[OracleResult]:
    """Ask the LLM to rule on an inconclusive finding.

    Returns an updated OracleResult, or None if the judge is unavailable or
    fails (caller keeps the original inconclusive verdict).
    """
    api_key, base_url, model = _llm_config(mode)
    if not base_url or not model:
        return None

    try:
        from core.llm import build_client

        client = build_client(api_key or "not-needed", base_url)
        messages = build_judge_messages(finding, oracle, baseline, tampered, redactor)
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.0,
        )
        ruling = parse_judge(resp.choices[0].message.content or "")
    except Exception:
        return None

    if ruling is None:
        return None

    signals = dict(oracle.signals)
    signals["llm_judge"] = {
        "verdict": ruling["verdict"].value,
        "confidence": ruling["confidence"],
    }
    return OracleResult(
        verdict=ruling["verdict"],
        confidence=ruling["confidence"],
        reason=f"LLM judge: {ruling['rationale']}",
        baseline_status=oracle.baseline_status,
        tampered_status=oracle.tampered_status,
        signals=signals,
    )
