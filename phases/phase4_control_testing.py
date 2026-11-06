import json
import re
import sys
import time
import urllib.parse

from core.models import Finding
from phases.phase4_replay_flow import replay_actions_with_tamper
from resources import ui
from resources.bcolors import bcolors
from resources.yes_no_menu import yes_no_menu


def replace_domain(data, actual_domain):
    """Recursively replace PRIVATE_DOMAIN.com in all string values.

    Kept for backward compatibility with analysis logs produced by older
    versions that anonymised the domain; harmless no-op otherwise.
    """
    if isinstance(data, str):
        # replace both with and without www.
        data = re.sub(r"\b(?:www\.)?PRIVATE_DOMAIN\.com\b", actual_domain, data)
        return data
    elif isinstance(data, dict):
        return {k: replace_domain(v, actual_domain) for k, v in data.items()}
    elif isinstance(data, list):
        return [replace_domain(item, actual_domain) for item in data]
    return data


def _loc_value(finding):
    loc = finding.parameter_location
    return loc.value if hasattr(loc, "value") else loc


def _mod_req_dict(finding, redactor, actual_domain):
    """Build a display/tamper-ready modified request dict from a Finding."""
    mod_req = finding.modified_request_example.model_dump(mode="json")
    if redactor is not None:
        # Restore real secret values for the live replay / accurate display.
        mod_req = redactor.reinject(mod_req)
    mod_req = replace_domain(mod_req, actual_domain)
    return mod_req


def run_automated_verification(
    json_result, actions_file, redactor, debug, judge_mode=None, http_mode=False
):
    """Agentic pass: replay each finding tampered and judge it against a shared
    baseline with the deterministic oracle (no LLM tokens spent).

    The untampered baseline is captured once and reused across findings, so the
    cost is N+1 replays rather than 2N. If ``judge_mode`` is set, inconclusive
    findings are escalated to a single LLM-judge call each. If ``http_mode`` is
    set, findings are confirmed via fast HTTP replay with payload sweeps (using
    the browser baseline only to obtain the real in-flow requests)."""
    from core.models import Verdict
    from core.verifier import capture_baseline, verify_finding, verify_finding_http

    if not json_result:
        ui.warn("No findings to verify.")
        return []

    mode_label = "fast HTTP replay + payload sweeps" if http_mode else "full browser replay"
    ui.info(f"Verifying {len(json_result)} finding(s) via {mode_label}.")
    if judge_mode:
        ui.info(f"Inconclusive findings will be escalated to the LLM judge ({judge_mode}).")

    # Capture the untampered baseline once and reuse it for every finding.
    baseline = None
    try:
        sp = ui.Spinner("Capturing baseline flow...").start()
        baseline = capture_baseline(json_result[0], actions_file, redactor=redactor, debug=debug)
        sp.stop("Baseline captured.")
    except Exception as e:
        ui.warn(f"Baseline capture failed ({e}); each finding will capture its own.")

    results = []
    for i, finding in enumerate(json_result):
        ui.status(
            "run",
            f"[{i + 1}/{len(json_result)}] Testing control {finding.control_id} "
            f"· param '{finding.parameter_name}' (packet {finding.packet_index})",
        )
        if http_mode and baseline:
            fr = verify_finding_http(
                finding, baseline, redactor=redactor, sweep=True, judge_mode=judge_mode
            )
        else:
            fr = verify_finding(
                finding,
                actions_file,
                redactor=redactor,
                debug=debug,
                baseline=baseline,
                judge_mode=judge_mode,
            )
        results.append(fr)
        if fr.oracle:
            conf = fr.oracle.confidence
            v = fr.oracle.verdict
            line = f"({conf:.0%}) {fr.oracle.reason}"
            if v == Verdict.CONFIRMED:
                ui.hit(f"LIVE {line}")
            elif v == Verdict.LIKELY:
                ui.warn(f"LIKELY {line}")
            elif v == Verdict.REJECTED:
                ui.ok(f"DEFENDED {line}")
            elif v == Verdict.ERROR:
                ui.err(line)
            else:
                ui.info(f"INCONCLUSIVE {line}")

    _print_verification_summary(results, Verdict)
    return results


def _print_verification_summary(results, Verdict):
    """Print a precise live/not-live summary, confirmed issues first."""
    order = {
        Verdict.CONFIRMED: 0,
        Verdict.LIKELY: 1,
        Verdict.INCONCLUSIVE: 2,
        Verdict.REJECTED: 3,
        Verdict.ERROR: 4,
    }
    ranked = sorted(
        enumerate(results),
        key=lambda t: order.get(t[1].oracle.verdict if t[1].oracle else None, 5),
    )

    live = sum(1 for _, fr in ranked if fr.oracle and fr.oracle.verdict == Verdict.CONFIRMED)
    likely = sum(1 for _, fr in ranked if fr.oracle and fr.oracle.verdict == Verdict.LIKELY)

    ui.section("Verification Summary", "Confirmed issues first")
    headline = (
        f"{ui.paint(str(live) + ' LIVE', ui.C_ERR, bold=True)}  ·  "
        f"{ui.paint(str(likely) + ' likely', ui.C_WARN, bold=True)}  ·  "
        f"{ui.paint(str(len(results)) + ' total', ui.C_MUTE)}"
    )
    print(f"  {headline}\n")
    for idx, fr in ranked:
        v = fr.oracle.verdict if fr.oracle else None
        conf = f"{fr.oracle.confidence:.0%}" if fr.oracle else "n/a"
        label = "LIVE" if v == Verdict.CONFIRMED else (v.value.upper() if v else "N/A")
        color = {
            Verdict.CONFIRMED: ui.C_ERR,
            Verdict.LIKELY: ui.C_WARN,
            Verdict.REJECTED: ui.C_OK,
            Verdict.INCONCLUSIVE: ui.C_ACCENT,
            Verdict.ERROR: ui.C_WARN,
        }.get(v, ui.C_MUTE)
        tag = ui.paint(f"{label:<12}", color, bold=(v == Verdict.CONFIRMED))
        print(
            f"  [{idx}] {tag} {ui.paint(conf.rjust(4), ui.C_ACCENT)}  "
            f"{ui.paint('control=' + fr.finding.control_id, ui.C_MUTE)} "
            f"param={fr.finding.parameter_name} ({fr.finding.parameter_location.value})"
        )


def edit_packet(url_input, json_result, actions_file, map_file, mode, debug):
    actual_domain = urllib.parse.urlparse(url_input).netloc

    # Load the secret map so live replays use real cookies/tokens and the
    # displayed request shows real values rather than placeholders.
    redactor = None
    if map_file:
        try:
            from core.redaction import Redactor

            redactor = Redactor.load_map(map_file)
        except Exception as e:
            ui.warn(f"Could not load secret map ({e}); replays will use placeholders.")

    # Normalise to Finding models (cached logs may arrive as dicts).
    findings = [f if isinstance(f, Finding) else Finding.model_validate(f) for f in json_result]

    # Optional agentic pass first.
    if yes_no_menu(
        f"{bcolors.BOLD}Run automated verification on all findings first? (y/n): {bcolors.ENDC}"
    ):
        http_mode = yes_no_menu(
            f"{bcolors.BOLD}Use fast HTTP replay with payload sweeps? "
            f"(faster, tries several payloads; browser replay is more thorough "
            f"for gateway/downstream proof) (y/n): {bcolors.ENDC}"
        )
        judge_mode = None
        if yes_no_menu(
            f"{bcolors.BOLD}Escalate inconclusive findings to the LLM judge? "
            f"(costs a few tokens each) (y/n): {bcolors.ENDC}"
        ):
            judge_mode = mode
        try:
            run_automated_verification(
                findings,
                actions_file,
                redactor,
                debug,
                judge_mode=judge_mode,
                http_mode=http_mode,
            )
        except KeyboardInterrupt:
            ui.warn("Automated verification interrupted.")
        except Exception as e:
            ui.err(f"Automated verification failed: {e}")

    ui.section("Manual Tamper & Replay", "Pick a finding to craft and replay by hand")

    while True:
        for i, finding in enumerate(findings):
            print(
                f"  {ui.paint(f'[{i}]', ui.C_ACCENT, bold=True)} "
                f"control={finding.control_id}  "
                f"{ui.paint('param=' + finding.parameter_name, ui.C_MUTE)}  "
                f"packet #{finding.packet_index}"
            )

        while True:
            choice = input(f"\n{bcolors.BOLD}Select entry by list index: {bcolors.ENDC}").strip()

            if not choice.isdigit():
                ui.warn("Please enter a valid number.")
                continue

            idx = int(choice)
            if 0 <= idx < len(findings):
                break

            ui.err(f"Invalid selection — valid indices are 0-{len(findings) - 1}.")

        finding = findings[idx]
        mod_req = _mod_req_dict(finding, redactor, actual_domain)
        mod_req_url = mod_req["url"]

        tamper_config = {
            "url_pattern": mod_req_url,
            "method": mod_req["method"],
            "param_location": _loc_value(finding),
            "param_name": finding.parameter_name,
            "param_value": finding.test_payload,
        }

        if debug:
            print(f"{bcolors.OKBLUE}[DEBUG]: Tamper config includes:")
            print(f"  URL: {tamper_config['url_pattern']}")
            print(f"  Method: {tamper_config['method']}")
            print(f"  Parameter: {tamper_config['param_name']} ({tamper_config['param_location']})")
            print(f"  New value: {tamper_config['param_value']}")
            print(bcolors.ENDC)
            sys.stdout.flush()

        ui.info("Selected request:")
        for line in json.dumps(mod_req, indent=2).splitlines():
            print(f"     {ui.paint(line, ui.C_MUTE)}")
        time.sleep(0.4)

        if not yes_no_menu(
            f"{bcolors.BOLD}Send this modified request packet as it is? (y/n): {bcolors.ENDC}"
        ):
            while True:
                ui.status("run", f"Current param_value: {tamper_config['param_value']}")
                newval = input(
                    f"{bcolors.BOLD}Enter new value for param_value (or leave blank to keep current): {bcolors.ENDC}"
                ).strip()
                if newval:
                    tamper_config["param_value"] = newval
                if yes_no_menu(
                    f"{bcolors.BOLD}Do you confirm the new value for param_value? (y/n): {bcolors.ENDC}"
                ):
                    break

        ui.info("Replaying flow with packet tampering...")
        try:
            replay_actions_with_tamper(actions_file, [tamper_config], debug)
        except KeyboardInterrupt:
            ui.warn("Replay interrupted by user.")
        except Exception as e:
            ui.err(f"Replay failed: {e}")

        if not yes_no_menu(f"{bcolors.BOLD}Test another control? (y/n): {bcolors.ENDC}"):
            break
