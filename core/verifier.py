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
    oracle = _maybe_judge(finding, oracle, base_snaps, tamp_snaps, judge_mode, redactor)
    return FindingResult(finding=finding, oracle=oracle)


def _maybe_judge(finding, oracle, base_snaps, tamp_snaps, judge_mode, redactor):
    """Escalate only genuinely ambiguous cases to the (paid) LLM judge."""
    if judge_mode and oracle.verdict == Verdict.INCONCLUSIVE:
        from core.judge import judge_finding

        ruled = judge_finding(
            finding, oracle, base_snaps, tamp_snaps, mode=judge_mode, redactor=redactor
        )
        if ruled is not None:
            return ruled
    return oracle


def _locate_request(capture: List[Dict[str, Any]], finding: Finding) -> Optional[Dict[str, Any]]:
    """Find the captured in-flow request matching the finding's target."""
    import urllib.parse

    want_path = urllib.parse.urlparse(finding.modified_request_example.url).path.rstrip("/")
    want_method = (finding.modified_request_example.method or "GET").upper()
    match = None
    for item in capture or []:
        if (item.get("method") or "").upper() != want_method:
            continue
        if urllib.parse.urlparse(item.get("url", "")).path.rstrip("/") != want_path:
            continue
        match = item  # keep the last occurrence
    return match


def verify_finding_http(
    finding: Finding,
    baseline_capture: List[Dict[str, Any]],
    redactor=None,
    sweep: bool = True,
    timeout: float = 15.0,
    judge_mode: Optional[str] = None,
) -> FindingResult:
    """Fast verification: resend the targeted request directly over HTTP and
    sweep a set of payloads, stopping at the first confirmed hit.

    Requires a browser ``baseline_capture`` (to obtain the real in-flow request
    with its cookies). Best for direct-effect confirmation; it does not observe
    downstream/gateway responses, so a non-confirmed result here does not rule
    the issue out -- the browser path may still confirm it.
    """
    from core.http_replay import replay
    from core.payloads import payloads_for

    located = _locate_request(baseline_capture, finding)
    if not located:
        return FindingResult(
            finding=finding,
            oracle=OracleResult(
                verdict=Verdict.ERROR,
                reason="Could not locate the targeted request in the captured flow "
                "for HTTP replay; use browser replay instead.",
            ),
        )

    request = {
        "method": located.get("method"),
        "url": located.get("url"),
        "headers": located.get("request_headers") or {},
        "body": located.get("request_body"),
    }

    try:
        http_baseline = replay(request, None, timeout=timeout)
    except Exception as e:
        return FindingResult(
            finding=finding,
            oracle=OracleResult(verdict=Verdict.ERROR, reason=f"HTTP baseline replay failed: {e}"),
        )

    base_snaps = _snapshots([http_baseline])
    payloads = payloads_for(finding) if sweep else [str(finding.test_payload)]

    best: Optional[OracleResult] = None
    best_tamp: List = []
    best_rank = -1
    rank = {
        Verdict.CONFIRMED: 4,
        Verdict.LIKELY: 3,
        Verdict.INCONCLUSIVE: 2,
        Verdict.REJECTED: 1,
        Verdict.ERROR: 0,
    }
    for pv in payloads:
        tamper = finding_to_tamper(finding, redactor)
        tamper["param_value"] = pv
        try:
            http_tampered = replay(request, tamper, timeout=timeout)
        except Exception:
            continue
        tamp_snaps = _snapshots([http_tampered])
        oracle = evaluate(finding, str(pv), base_snaps, tamp_snaps)
        oracle.signals["payload_tried"] = pv
        if rank.get(oracle.verdict, 0) > best_rank:
            best, best_tamp, best_rank = oracle, tamp_snaps, rank.get(oracle.verdict, 0)
        if oracle.verdict == Verdict.CONFIRMED:
            break  # short-circuit: a live payload is proof enough

    if best is None:
        best = OracleResult(verdict=Verdict.ERROR, reason="No HTTP payload could be sent.")
    else:
        best = _maybe_judge(finding, best, base_snaps, best_tamp, judge_mode, redactor)
    return FindingResult(finding=finding, oracle=best)
