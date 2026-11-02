"""Agentic verification orchestrator (P1).

Ties the (cheap) deterministic oracle to the replay engine. For a given
finding it:

1. replays the recorded flow **untampered** and captures the target response
   (baseline),
2. replays it **tampered** and captures the target response,
3. asks the oracle to compare them.

The LLM is not in this loop at all -- the whole verification is tokens-free.
Only an ``INCONCLUSIVE`` verdict should be escalated to an LLM judge by the
caller, which keeps autonomous runs close to one-shot cost.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Dict, Optional

from core.models import Finding, FindingResult, OracleResult, Verdict
from core.oracle import ResponseSnapshot, evaluate


def finding_to_tamper(finding: Finding, redactor=None) -> Dict[str, Any]:
    """Build a replay tamper-config from a finding.

    If a redactor is supplied, the example URL has any secret placeholders
    restored so the matched request targets the real endpoint.
    """
    url = finding.modified_request_example.url
    if redactor is not None:
        url = redactor.reinject(url)
    return {
        "url_pattern": url,
        "method": finding.modified_request_example.method,
        "param_location": finding.parameter_location.value,
        "param_name": finding.parameter_name,
        "param_value": finding.test_payload,
    }


def _snapshot(resp: Optional[Dict[str, Any]]) -> Optional[ResponseSnapshot]:
    if not resp:
        return None
    return ResponseSnapshot(
        url=resp.get("url", ""),
        status=resp.get("status"),
        headers={str(k): str(v) for k, v in (resp.get("headers") or {}).items()},
        body=resp.get("body", "") or "",
    )


def verify_finding(
    finding: Finding,
    actions_file: str,
    redactor=None,
    debug: bool = False,
    headless: bool = True,
) -> FindingResult:
    """Run baseline + tampered replays and evaluate the outcome."""
    # Lazy import so core.verifier is importable without Playwright present
    # (e.g. for unit tests of the oracle wiring).
    from phases.phase4_replay_flow import run_replay_capture

    tamper = finding_to_tamper(finding, redactor)

    try:
        baseline = run_replay_capture(
            actions_file, [], tamper, debug=debug, headless=headless
        )
        tampered = run_replay_capture(
            actions_file, [tamper], tamper, debug=debug, headless=headless
        )
    except Exception as e:
        return FindingResult(
            finding=finding,
            oracle=OracleResult(
                verdict=Verdict.ERROR,
                reason=f"Replay/transport failure during verification: {e}",
            ),
        )

    oracle = evaluate(
        finding,
        str(finding.test_payload),
        _snapshot(baseline),
        _snapshot(tampered),
    )
    return FindingResult(finding=finding, oracle=oracle)
