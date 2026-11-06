import json
import warnings

from phases.phase2_har_parser import parse_har, redact_filtered
from resources.animate_title import animate_title
from resources.control_refs import control_references

warnings.filterwarnings(
    "ignore", category=UserWarning, message="pkg_resources is deprecated as an API.*"
)

# noqa: E402
import argparse  # noqa: E402
import os  # noqa: E402
import time  # noqa: E402
import urllib.parse  # noqa: E402

from dotenv import load_dotenv  # noqa: E402

from phases.phase1_webtech_rec import (  # noqa: E402
    ScanError,
    check_ecommerce_platforms,
    get_pretty_output,
    parse_existing_file_for_ecommerce,
    save_results_to_file,
    scan_url,
    url_menu,
    verify_website_exists,
)
from phases.phase2_session_recorder_pw import (
    record_user_session as record_user_session_pw,
)  # noqa: E402
from phases.phase3_ai_analyzer import analyze_packets_with_ai, print_ai_answer  # noqa: E402
from phases.phase4_control_testing import edit_packet  # noqa: E402
from resources import ui  # noqa: E402
from resources.bcolors import bcolors  # noqa: E402
from resources.yes_no_menu import yes_no_menu  # noqa: E402


def phase_1(url_input, webtechs_dir):
    parsed_url = urllib.parse.urlparse(url_input)
    domain = parsed_url.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    prefix = domain.split(".")[0]

    filename = os.path.join(webtechs_dir, f"{prefix}_webtechs_found.log")

    if os.path.exists(filename):
        ui.info("A web-techs enumeration log already exists for this URL.")
        if yes_no_menu(
            f"{bcolors.BOLD}Use the existing log and skip enumeration? (y/n): {bcolors.ENDC}"
        ):
            ui.info(f"Using existing enumeration log: {filename}")
            time.sleep(0.5)
            ecommerce_found = parse_existing_file_for_ecommerce(filename)
            return ecommerce_found, prefix

    spinner = ui.Spinner("Scanning web technologies...").start()
    try:
        results = scan_url(url_input, spinner)
    except ScanError:
        # Enumeration failed (network/library issue), which is NOT the same as
        # detecting an e-commerce platform. Warn and continue the assessment.
        ui.warn("Skipping platform detection and continuing with the assessment.")
        return False, prefix

    if not results:
        ui.warn("Enumeration returned no technologies; continuing with the assessment.")
        return False, prefix

    platforms_found, ecommerce_found = check_ecommerce_platforms(results, spinner)
    pretty = get_pretty_output(results, platforms_found, items_per_row=3)
    save_results_to_file(url_input, pretty, webtechs_dir)
    ui.ok(f"Web-techs log saved to: {filename}")
    return ecommerce_found, prefix


def phase_2(url_input, packets_dir, actions_path, debug):
    ui.section("Phase 2 · User Session Recording", "Record the purchase flow you want to test")

    # Compute prefix for filenames
    parsed = urllib.parse.urlparse(url_input)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    prefix = domain.split(".")[0]

    har_file = os.path.join(packets_dir, f"{prefix}_packets.json")
    har_raw = os.path.join(packets_dir, f"{prefix}_raw_packets.har")
    redacted_file = os.path.join(packets_dir, f"{prefix}_packets_redacted.json")
    map_file = os.path.join(packets_dir, f"{prefix}_packets_secretmap.json")
    actions_filename = os.path.join(actions_path, f"{prefix}_actions.py")
    # Check if HAR and actions files already exist
    if os.path.exists(har_file) and os.path.exists(har_raw) and os.path.exists(actions_filename):
        ui.info("Existing session files found for this URL.")
        if yes_no_menu(
            f"{bcolors.BOLD}Use the existing recording and skip this step? (y/n): {bcolors.ENDC}"
        ):
            ui.info(f"Using existing files: {har_file}, {actions_filename}")
            actions_file = actions_filename
            # Re-run redaction if the redacted file/map are missing (e.g. logs
            # produced by an older TAMPY version).
            if not (os.path.exists(redacted_file) and os.path.exists(map_file)):
                redacted_file, map_file = redact_filtered(har_file, domain)

            if not redacted_file or not actions_file or not map_file:
                ui.err("Existing files could not be prepared. Unable to proceed.")
                return None, None, None

            return redacted_file, actions_file, map_file

    # 1) Record user session with Playwright
    har_filename_raw, actions_file = record_user_session_pw(url_input, har_raw, actions_filename)

    # Check if we got valid paths
    if not har_filename_raw or not actions_file:
        ui.err("Session recording failed.")
        return None, None, None

    if debug:
        print(f"{bcolors.OKCYAN}")
        print(f"[DEBUG] cwd is:        {os.getcwd()}")
        print(f"[DEBUG] looking for:    {har_filename_raw}")
        print(f"[DEBUG] dir listing of packets_dir: {os.listdir(packets_dir)}")
        print(f"{bcolors.ENDC}")

    # 2) Parse, filter and redact HAR into JSON
    har_filename_filtered = redacted = secret_map = None
    if har_filename_raw and actions_file:
        har_filename_filtered, redacted, secret_map = parse_har(har_filename_raw, har_file, domain)

    if not har_filename_filtered or not redacted or not secret_map:
        ui.err("Packets could not be filtered/redacted. Unable to proceed.")
        return None, None, None

    return redacted, actions_file, secret_map


def phase_3(har_filename, mode, streaming, show_think, analysis_dir, prefix):
    stream_mode = "streaming" if streaming else "non-streaming"
    ui.section(
        "Phase 3 · AI-Powered Packet Analysis",
        f"{mode} · {stream_mode}",
    )
    time.sleep(0.3)
    ui.info("Evaluating the following business-logic controls:")
    print("\n" + control_references() + "\n")
    time.sleep(0.6)

    analysis_filename = os.path.join(analysis_dir, f"{prefix}_analysis.json")

    if os.path.exists(analysis_filename):
        ui.info(f"An analysis file already exists: {analysis_filename}")
        if yes_no_menu(
            f"{bcolors.BOLD}Use the existing analysis and skip the AI step? (y/n): {bcolors.ENDC}"
        ):
            ui.info("Using existing analysis file.")
            time.sleep(0.3)
            with open(analysis_filename, encoding="utf-8") as f:
                cached = json.load(f)
            from core.models import parse_findings

            result = parse_findings(cached)
            print_ai_answer(result)
            return result

    spinner2 = ui.Spinner("Analyzing packets with the LLM (this may take a while)...").start()

    # Pass spinner to analyzer
    raw_result, result = analyze_packets_with_ai(
        har_filename, mode, streaming, show_think, spinner2
    )
    if result == []:
        ui.err(
            "After a thorough review, no potential vulnerabilities were identified in "
            "the provided requests. The captured packets may not contain parameters "
            "relevant to the purchase flow. Review the HAR and try again if needed."
        )
        print(raw_result or f"{bcolors.FAIL}(no raw text captured){bcolors.ENDC}")
        return None
    if not result:
        ui.err(
            "No results to display (could not parse the JSON answer). Try again, or "
            f"insert the raw response manually into {har_filename}. Raw response:"
        )
        print(raw_result or f"{bcolors.FAIL}(no raw text captured){bcolors.ENDC}")
        return None

    ui.ok(f"Analysis complete — {len(result)} potential finding(s).")
    print()
    print_ai_answer(result)

    with open(analysis_filename, "w", encoding="utf-8") as f:
        serialisable = [
            item.model_dump(mode="json") if hasattr(item, "model_dump") else item for item in result
        ]
        json.dump(serialisable, f, indent=2)
    ui.info(f"Analysis results saved to: {analysis_filename}")

    return result


def phase_4(url_input, json_result, actions_file, map_file, mode, debug):
    ui.section("Phase 4 · Control Testing & Verification", "Tamper, replay and confirm live issues")
    edit_packet(url_input, json_result, actions_file, map_file, mode, debug)


def startup():
    load_dotenv()

    logs_dir = ".logs"
    os.makedirs(logs_dir, exist_ok=True)

    webtechs_dir = os.path.join(logs_dir, "webtechs")
    packets_dir = os.path.join(logs_dir, "packets")
    actions_dir = os.path.join(logs_dir, "actions")
    analysis_dir = os.path.join(logs_dir, "analysis")

    for d in (webtechs_dir, packets_dir, actions_dir, analysis_dir):
        os.makedirs(d, exist_ok=True)

    return logs_dir, webtechs_dir, packets_dir, actions_dir, analysis_dir


def load_args():
    parser = argparse.ArgumentParser(
        description="TAMPY 1.0 - An E-Commerce Web Security Assessment Tool"
    )
    lr_group = parser.add_mutually_exclusive_group(required=True)
    lr_group.add_argument("-L", "--local", action="store_true", help="Use local LLM server")
    lr_group.add_argument("-R", "--remote", action="store_true", help="Use a remote LLM API")
    parser.add_argument(
        "-U",
        "--url",
        type=str,
        help="Provide a URL to analyze and skip prompt (default: none)",
        default=None,
    )
    parser.add_argument(
        "-S",
        "--stream",
        action="store_true",
        help="Enable streaming mode for LLM output (default: false)",
    )
    parser.add_argument(
        "-T",
        "--think",
        action="store_true",
        help="Display chain-of-reasoning thinking of the LLM output (default: false)",
    )
    parser.add_argument(
        "-D",
        "--debug",
        action="store_true",
        help="Debug mode to print extra information (default: false)",
    )
    parser.add_argument(
        "--no-anim",
        action="store_true",
        help="Disable startup animations (colour is kept)",
    )
    args = parser.parse_args()

    if args.no_anim:
        os.environ["TAMPY_NO_ANIM"] = "1"

    mode = "local" if args.local else "remote"
    streaming = bool(args.stream)
    show_think = bool(args.think)
    url_input = args.url if args.url else None
    debug = bool(args.debug)

    return mode, streaming, show_think, url_input, debug


def main():
    mode, streaming, show_think, url_skip_prompt, debug = load_args()
    animate_title()
    logs_dir, webtechs_dir, packets_dir, actions_path, analysis_dir = startup()
    another_url = False
    while True:
        url_input = url_menu(url_skip_prompt, another_url)
        if url_input:
            if verify_website_exists(url_input) or url_input == "https://127.0.0.1:5000/":
                ecommerce_found, prefix = phase_1(url_input, webtechs_dir)
                if not ecommerce_found:
                    phase_2_success = False
                    har_filename = None
                    actions_file = None
                    map_file = None
                    try:
                        har_filename, actions_file, map_file = phase_2(
                            url_input, packets_dir, actions_path, debug
                        )
                        if har_filename and actions_file and map_file:
                            phase_2_success = True

                    except KeyboardInterrupt:
                        print(f"{bcolors.OKBLUE}[INFO]: Recording stopped by user.{bcolors.ENDC}")
                        if not har_filename or not actions_file:
                            print(
                                f"{bcolors.FAIL}[ERROR]: Recording was interrupted, no files saved.{bcolors.ENDC}"
                            )
                        else:
                            # Check if files were created
                            har_file = os.path.join(packets_dir, f"{prefix}_packets.json")
                            har_raw = os.path.join(packets_dir, f"{prefix}_raw_packets.har")
                            actions_filename = os.path.join(actions_path, f"{prefix}_actions.py")
                            if (
                                os.path.exists(har_file)
                                and os.path.exists(har_raw)
                                and os.path.exists(actions_filename)
                            ):
                                # Must redact before anything reaches the LLM,
                                # even on the interrupt-recovery path.
                                parsed = urllib.parse.urlparse(url_input)
                                dom = parsed.netloc.lower()
                                if dom.startswith("www."):
                                    dom = dom[4:]
                                redacted_file, map_file = redact_filtered(har_file, dom)
                                actions_file = actions_filename
                                if redacted_file and map_file:
                                    har_filename = redacted_file
                                    phase_2_success = True

                    if phase_2_success:
                        json_result = phase_3(
                            har_filename,
                            mode,
                            streaming,
                            show_think,
                            analysis_dir,
                            prefix,
                        )
                        if json_result:
                            phase_4(
                                url_input,
                                json_result,
                                actions_file,
                                map_file,
                                mode,
                                debug,
                            )
                    else:
                        ui.err("Phase 2 did not produce the required files.")
                else:
                    ui.err("Assessment cannot continue: an e-commerce platform was detected.")
            else:
                ui.err("The website does not exist or could not be accessed. Try another URL.")
        else:
            ui.err("Invalid URL entered. Please try again.")

        if not yes_no_menu(
            f"{bcolors.BOLD}\nDo you want to try a new website? (y/n): {bcolors.ENDC}"
        ):
            break
        another_url = True

    print()
    print(ui.rule())
    ui.ok("Thank you for using TAMPY. Stay sharp, hack ethically.")
    print()


if __name__ == "__main__":
    main()
