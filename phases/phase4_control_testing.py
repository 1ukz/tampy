import re
import sys
import time
import json
import urllib.parse
from phases.phase4_replay_flow import replay_actions_with_tamper
from resources.bcolors import bcolors
from resources.yes_no_menu import yes_no_menu
from core.models import Finding


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


def _verdict_colour(verdict):
    from core.models import Verdict

    return {
        Verdict.CONFIRMED: bcolors.FAIL,     # confirmed issue == red (bad for target)
        Verdict.LIKELY: bcolors.WARNING,
        Verdict.INCONCLUSIVE: bcolors.OKBLUE,
        Verdict.REJECTED: bcolors.OKGREEN,   # server defended == green
        Verdict.ERROR: bcolors.WARNING,
    }.get(verdict, bcolors.ENDC)


def run_automated_verification(json_result, actions_file, redactor, debug):
    """Agentic pass: baseline+tampered replay per finding, judged by the
    deterministic oracle (no LLM tokens spent)."""
    from core.verifier import verify_finding

    print(
        f"{bcolors.OKBLUE}[INFO]: Running automated verification on "
        f"{len(json_result)} finding(s). This replays the flow twice per "
        f"finding (baseline + tampered).{bcolors.ENDC}"
    )
    results = []
    for i, finding in enumerate(json_result):
        print(
            f"{bcolors.BOLD}[{i + 1}/{len(json_result)}] Verifying control "
            f"{finding.control_id} (packet {finding.packet_index})...{bcolors.ENDC}"
        )
        fr = verify_finding(finding, actions_file, redactor=redactor, debug=debug)
        results.append(fr)
        if fr.oracle:
            col = _verdict_colour(fr.oracle.verdict)
            print(
                f"  {col}-> {fr.oracle.verdict.value.upper()}{bcolors.ENDC}: "
                f"{fr.oracle.reason}"
            )

    print(f"\n{bcolors.BOLD}{bcolors.HEADER}VERIFICATION SUMMARY{bcolors.ENDC}")
    for i, fr in enumerate(results):
        v = fr.oracle.verdict if fr.oracle else None
        col = _verdict_colour(v)
        label = v.value.upper() if v else "N/A"
        print(
            f"  [{i}] {col}{label:<12}{bcolors.ENDC} "
            f"control={fr.finding.control_id} packet={fr.finding.packet_index} "
            f"param={fr.finding.parameter_name}"
        )
    return results


def edit_packet(url_input, json_result, actions_file, map_file, debug):
    actual_domain = urllib.parse.urlparse(url_input).netloc

    # Load the secret map so live replays use real cookies/tokens and the
    # displayed request shows real values rather than placeholders.
    redactor = None
    if map_file:
        try:
            from core.redaction import Redactor

            redactor = Redactor.load_map(map_file)
        except Exception as e:
            print(
                f"{bcolors.WARNING}[WARNING]: Could not load secret map "
                f"({e}); replays will use redacted placeholders.{bcolors.ENDC}"
            )

    # Normalise to Finding models (cached logs may arrive as dicts).
    findings = [
        f if isinstance(f, Finding) else Finding.model_validate(f) for f in json_result
    ]

    # Optional agentic pass first.
    if yes_no_menu(
        f"{bcolors.BOLD}Run automated verification on all findings first? (y/n): {bcolors.ENDC}"
    ):
        try:
            run_automated_verification(findings, actions_file, redactor, debug)
        except KeyboardInterrupt:
            print(
                f"{bcolors.WARNING}[WARNING]: Automated verification interrupted.{bcolors.ENDC}"
            )
        except Exception as e:
            print(
                f"{bcolors.FAIL}[ERROR]: Automated verification failed: {e}{bcolors.ENDC}"
            )

    print(f"{bcolors.OKBLUE}[INFO]: Available entries:{bcolors.ENDC}")

    while True:
        for i, finding in enumerate(findings):
            print(
                f"  [{i}] Control={finding.control_id}  Packet Index={finding.packet_index}"
            )

        while True:
            choice = input(
                f"\n{bcolors.BOLD}Select entry by list index: {bcolors.ENDC}"
            ).strip()

            if not choice.isdigit():
                print(
                    f"{bcolors.WARNING}[WARNING]: Please enter a valid number.{bcolors.ENDC}"
                )
                continue

            idx = int(choice)
            if 0 <= idx < len(findings):
                break

            print(f"{bcolors.FAIL}[ERROR]: Invalid selection!{bcolors.ENDC}")
            print(
                f"{bcolors.WARNING} Valid list indices: 0-{len(findings) - 1}{bcolors.ENDC}"
            )

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
            print(
                f"  Parameter: {tamper_config['param_name']} ({tamper_config['param_location']})"
            )
            print(f"  New value: {tamper_config['param_value']}")
            print(bcolors.ENDC)
            sys.stdout.flush()

        print(
            f"{bcolors.OKBLUE}[INFO]: Selected request:\n {bcolors.ENDC}",
            json.dumps(mod_req, indent=2),
        )
        time.sleep(0.5)

        if not yes_no_menu(
            f"{bcolors.BOLD}Send this modified request packet as it is? (y/n): {bcolors.ENDC}"
        ):
            while True:
                print(
                    f"{bcolors.BOLD}{bcolors.WARNING}Current param_value: {tamper_config['param_value']}{bcolors.ENDC}"
                )
                newval = input(
                    f"{bcolors.BOLD}Enter new value for param_value (or leave blank to keep current): {bcolors.ENDC}"
                ).strip()
                if newval:
                    tamper_config["param_value"] = newval
                if yes_no_menu(
                    f"{bcolors.BOLD}Do you confirm the new value for param_value? (y/n): {bcolors.ENDC}"
                ):
                    break

        print(
            f"{bcolors.OKBLUE}[INFO]: Replaying flow with packet tampering...{bcolors.ENDC}"
        )
        try:
            replay_actions_with_tamper(actions_file, [tamper_config], debug)
        except KeyboardInterrupt:
            print(
                f"{bcolors.BOLD}{bcolors.WARNING}[WARNING]: Replay interrupted by user.{bcolors.ENDC}"
            )
        except Exception as e:
            print(
                f"{bcolors.BOLD}{bcolors.FAIL}[ERROR]: Replay failed: {str(e)}{bcolors.ENDC}"
            )

        if not yes_no_menu(
            f"{bcolors.BOLD}Test another control? (y/n): {bcolors.ENDC}"
        ):
            break
