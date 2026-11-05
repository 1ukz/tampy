"""Agentic verification orchestrator (P1).

Ties the (cheap) deterministic oracle to the replay engine. For a given
finding it:

1. replays the recorded flow **untampered** and captures every response
   (baseline),
2. replays it **tampered** and captures every response,
3. asks the oracle to compare the two whole flows.

Capturing the whole flow (not just the targeted request) is what lets the
oracle see downstream proof -- e.g. a checkout total that only reflects a
tampered price on the confirmation step.

The LLM is not in this loop at all -- the whole verification is tokens-free.
Only an ``INCONCLUSIVE`` verdict should be escalated to an LLM judge by the
caller, which keeps autonomous runs close to one-shot cost.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

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
        method=resp.get("method"),
        status=resp.get("status"),
        headers={str(k): str(v) for k, v in (resp.get("headers") or {}).items()},
        body=resp.get("body", "") or "",
        request_body=resp.get("request_body"),
    )


def _snapshots(responses: Optional[List[Dict[str, Any]]]) -> List[ResponseSnapshot]:
    out: List[ResponseSnapshot] = []
    for r in responses or []:
        snap = _snapshot(r)
        if snap is not None:
            out.append(snap)
    return out


def capture_baseline(
    finding: Finding,
    actions_file: str,
    redactor=None,
    debug: bool = False,
    headless: bool = True,
) -> List[Dict[str, Any]]:
    """Replay the flow once, untampered, and return the captured responses.

    The baseline is identical for every finding on the same recording, so it is
    captured once and reused across findings (N+1 replays instead of 2N).
    """
    from phases.phase4_replay_flow import run_replay_capture

    tamper = finding_to_tamper(finding, redactor)
    return run_replay_capture(actions_file, [], tamper, debug=debug, headless=headless)


def verify_finding(
    finding: Finding,
    actions_file: str,
    redactor=None,
    debug: bool = False,
    headless: bool = True,
    baseline: Optional[List[Dict[str, Any]]] = None,
    judge_mode: Optional[str] = None,
) -> FindingResult:
    """Run a tampered replay and evaluate it against a baseline.

    If ``baseline`` (captured responses from an untampered run) is provided it
    is reused; otherwise a fresh baseline is captured for this finding.

    If ``judge_mode`` ("local"/"remote") is set and the deterministic oracle is
    INCONCLUSIVE, a single LLM-judge call is made to resolve it (the only
    token-spending step in verification).
    """
    # Lazy import so core.verifier is importable without Playwright present
    # (e.g. for unit tests of the oracle wiring).
    from phases.phase4_replay_flow import run_replay_capture

    tamper = finding_to_tamper(finding, redactor)

    try:
        if baseline is None:
            baseline = run_replay_capture(actions_file, [], tamper, debug=debug, headless=headless)
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

    base_snaps = _snapshots(baseline)
    tamp_snaps = _snapshots(tampered)
    oracle = evaluate(finding, str(finding.test_payload), base_snaps, tamp_snaps)

    # Escalate only genuinely ambiguous cases to the (paid) LLM judge.
    if judge_mode and oracle.verdict == Verdict.INCONCLUSIVE:
        from core.judge import judge_finding

        ruled = judge_finding(
            finding, oracle, base_snaps, tamp_snaps, mode=judge_mode, redactor=redactor
        )
        if ruled is not None:
            oracle = ruled

    return FindingResult(finding=finding, oracle=oracle)
