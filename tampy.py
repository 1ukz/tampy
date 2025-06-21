import json
import warnings
from phases.har_parser import parse_har
from resources.animate_title import animate_title
from resources.control_refs import control_references

warnings.filterwarnings(
    "ignore", category=UserWarning, message="pkg_resources is deprecated as an API.*"
)

# noqa: E402
import os  # noqa: E402
import time  # noqa: E402
import urllib.parse  # noqa: E402
import argparse  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from halo import Halo  # noqa: E402
from phases.webtech_rec import (  # noqa: E402
    scan_url,
    check_ecommerce_platforms,
    get_pretty_output,
    save_results_to_file,
    url_menu,
    verify_website_exists,
    parse_existing_file_for_ecommerce,
)
from phases.session_recorder_pw import record_user_session as record_user_session_pw  # noqa: E402
from phases.ai_analyzer import analyze_packets_with_ai, print_ai_answer  # noqa: E402
from phases.control_testing import edit_packet  # noqa: E402
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
        print(
            f"{bcolors.OKBLUE}[INFO]: A web techs enumeration log file has been found for this URL. {bcolors.ENDC}"
        )
        if yes_no_menu(
            f"{bcolors.BOLD}Do you want to use the existing log file and skip enumeration? (y/n): {bcolors.ENDC}"
        ):
            print(
                f"{bcolors.OKBLUE}[INFO]: Using existing web techs enumeration log: {filename}{bcolors.ENDC}"
            )
            time.sleep(1)
            ecommerce_found = parse_existing_file_for_ecommerce(filename)
            return ecommerce_found, prefix

    spinner = Halo(
        text="Scanning web technologies... Please wait patiently.", spinner="dots"
    )
    spinner.start()
    results = scan_url(url_input, spinner)
    if not results:
        return True, prefix

    platforms_found, ecommerce_found = check_ecommerce_platforms(results, spinner)
    pretty = get_pretty_output(results, platforms_found, items_per_row=3)
    save_results_to_file(url_input, pretty, webtechs_dir)
    print(
        f"{bcolors.OKGREEN}[SUCCESS]: Webtechs log saved to: {filename}{bcolors.ENDC}"
    )
    return ecommerce_found, prefix


def phase_2(url_input, packets_dir, actions_path, debug):
    print(
        f"{bcolors.BOLD}{bcolors.HEADER}\n[PHASE 2]: USER SESSION RECORDING{bcolors.ENDC}"
    )

    # Compute prefix for filenames
    parsed = urllib.parse.urlparse(url_input)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    prefix = domain.split(".")[0]

    har_file = os.path.join(packets_dir, f"{prefix}_packets.json")
    har_raw = os.path.join(packets_dir, f"{prefix}_raw_packets.har")
    actions_filename = os.path.join(actions_path, f"{prefix}_actions.py")
    # Check if HAR and actions files already exist
    if (
        os.path.exists(har_file)
        and os.path.exists(har_raw)
        and os.path.exists(actions_filename)
    ):
        print(
            f"{bcolors.OKBLUE}[INFO]: Existing session files found for this URL.{bcolors.ENDC}"
        )
        if yes_no_menu(
            f"{bcolors.BOLD}Do you want to use the existing HAR and actions files and skip recording? (y/n): {bcolors.ENDC}"
        ):
            print(
                f"{bcolors.OKBLUE}[INFO]: Using existing files: {har_file}, {har_raw}, {actions_filename}{bcolors.ENDC}"
            )
            har_filename_filtered = har_file
            har_filename_raw = har_raw
            actions_file = actions_filename

            if not har_filename_filtered or not har_filename_raw or not actions_file:
                print(
                    f"{bcolors.FAIL}[ERROR]: Existing files could not be saved correctly. Unable to proceed with the analysis.{bcolors.ENDC}"
                )
                return None
            return har_filename_filtered, har_filename_raw, actions_file

    # 1) Record user session with Playwright
    har_filename_raw, actions_file = record_user_session_pw(
        url_input, har_raw, actions_filename
    )

    # Check if we got valid paths
    if not har_filename_raw or not actions_file:
        print(f"{bcolors.FAIL}[ERROR]: Session recording failed{bcolors.ENDC}")
        return None, None, None

    if debug:
        print(f"{bcolors.OKCYAN}")
        print(f"{bcolors.OKCYAN}[DEBUG] cwd is:        {os.getcwd()}")
        print(f"[DEBUG] looking for:    {har_filename_raw}")
        print(f"[DEBUG] dir listing of packets_dir: {os.listdir(packets_dir)}")
        print(f"{bcolors.ENDC}")

    # 2) Parse and filter HAR into JSON
    if har_filename_raw and actions_file:
        har_filename_filtered, har_filename_filtered_anon = parse_har(
            har_filename_raw, har_file, domain
        )

    if not har_filename_filtered or not har_filename_filtered_anon:
        print(
            f"{bcolors.FAIL}[ERROR]: Packets could not be filtered. Unable to proceed with the analysis.{bcolors.ENDC}"
        )
        return None, None, None

    return har_filename_filtered_anon, har_filename_raw, actions_file


def phase_3(har_filename, mode, streaming, show_think, analysis_dir, prefix):
    stream_mode = "streaming" if streaming else "non-streaming"
    print(
        f"{bcolors.BOLD}{bcolors.HEADER}\n[PHASE 3]: ANALYZING HTTP PACKETS ({mode} {stream_mode} mode){bcolors.ENDC}"
    )
    time.sleep(0.5)
    print(
        f"{bcolors.OKBLUE}[INFO]: Evaluating the following controls: {bcolors.ENDC}\n\n"
        + control_references()
        + "\n"
    )
    time.sleep(1)

    analysis_filename = os.path.join(analysis_dir, f"{prefix}_analysis.json")

    if os.path.exists(analysis_filename):
        print(
            f"{bcolors.OKBLUE}[INFO]: An analysis file already exists for this URL: {analysis_filename}{bcolors.ENDC}"
        )
        if yes_no_menu(
            f"{bcolors.BOLD}Do you want to use the existing analysis file and skip AI analysis? (y/n): {bcolors.ENDC}"
        ):
            print(
                f"{bcolors.OKBLUE}[INFO]: Using existing analysis file.{bcolors.ENDC}"
            )
            time.sleep(0.5)
            with open(analysis_filename, "r", encoding="utf-8") as f:
                result = json.load(f)
            print_ai_answer(result)
            return result
    spinner2 = Halo(
        text="Analyzing packets... Please wait patiently, this may take a little while.",
        spinner="dots",
    )
    spinner2.start()

    # Pass spinner to analyzer
    raw_result, result = analyze_packets_with_ai(
        har_filename, mode, streaming, show_think, spinner2
    )

    if not result:
        print(
            f"{bcolors.FAIL}[ERROR]: No AI results to display. Raw response:{bcolors.ENDC}\n"
        )
        print(raw_result or f"{bcolors.FAIL}(no raw text captured){bcolors.ENDC}")
        return None

    print(
        f"\n{bcolors.BOLD}{bcolors.OKGREEN}[SUCCESS]: ANALYSIS RESULTS: {bcolors.ENDC}\n"
    )
    print_ai_answer(result)

    with open(analysis_filename, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(
        f"{bcolors.OKBLUE}[INFO]: Analysis results saved to: {har_filename}{bcolors.ENDC}"
    )

    return result


def phase_4(har_filtered, url_input, json_result, actions_file):
    print(f"{bcolors.BOLD}{bcolors.HEADER}\n[PHASE 4]: CONTROL TESTING{bcolors.ENDC}")
    edit_packet(har_filtered, url_input, json_result, actions_file)


def startup():
    print(
        f"{bcolors.BOLD}{bcolors.OKBLUE}[INFO]: Welcome to TAMPY v1.0!{bcolors.ENDC}\n"
    )

    load_dotenv()

    logs_dir = ".logs"
    os.makedirs(logs_dir, exist_ok=True)
    webtechs_dir = r".logs\webtechs"
    os.makedirs(webtechs_dir, exist_ok=True)
    packets_dir = r".logs\packets"
    os.makedirs(packets_dir, exist_ok=True)
    actions_dir = r".logs\actions"
    os.makedirs(actions_dir, exist_ok=True)
    analysis_dir = r".logs\analysis"
    os.makedirs(analysis_dir, exist_ok=True)
    return logs_dir, webtechs_dir, packets_dir, actions_dir, analysis_dir


def load_args():
    parser = argparse.ArgumentParser(
        description="TAMPY 1.0 - An E-Commerce Web Security Assessment Tool"
    )
    lr_group = parser.add_mutually_exclusive_group(required=True)
    lr_group.add_argument(
        "-L", "--local", action="store_true", help="Use local LLM server"
    )
    lr_group.add_argument(
        "-R", "--remote", action="store_true", help="Use a remote LLM API"
    )
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
    args = parser.parse_args()

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
            if verify_website_exists(url_input):
                ecommerce_found, prefix = phase_1(url_input, webtechs_dir)
                if not ecommerce_found:
                    phase_2_success = False
                    har_filename = None
                    har_filename_raw = None
                    actions_file = None
                    try:
                        har_filename, har_filename_raw, actions_file = phase_2(
                            url_input, packets_dir, actions_path, debug
                        )
                        phase_2_success = True
                    except KeyboardInterrupt:
                        print(
                            f"{bcolors.OKBLUE}[INFO]: Recording stopped by user.{bcolors.ENDC}"
                        )
                        # Check if files were created
                        har_file = os.path.join(packets_dir, f"{prefix}_packets.json")
                        har_raw = os.path.join(packets_dir, f"{prefix}_raw_packets.har")
                        actions_filename = os.path.join(
                            actions_path, f"{prefix}_actions.py"
                        )
                        if (
                            os.path.exists(har_file)
                            and os.path.exists(har_raw)
                            and os.path.exists(actions_filename)
                        ):
                            har_filename = har_file
                            har_filename_raw = har_raw
                            actions_file = actions_filename
                            phase_2_success = True
                        else:
                            print(
                                f"{bcolors.FAIL}[ERROR]: Recording incomplete, files not saved.{bcolors.ENDC}"
                            )

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
                            phase_4(har_filename, url_input, json_result, actions_file)
                    else:
                        print(
                            f"{bcolors.FAIL}[ERROR]: Phase 2 did not produce required files.{bcolors.ENDC}"
                        )
                else:
                    print(
                        f"{bcolors.BOLD}{bcolors.FAIL}[ERROR]: The assessment cannot continue as an E-Commerce platform was found :({bcolors.ENDC}"
                    )
            else:
                print(
                    f"{bcolors.FAIL}[ERROR]: The website does not exist or could not be accessed. Please try another URL.{bcolors.ENDC}"
                )
        else:
            print(
                f"{bcolors.FAIL}[ERROR]: Invalid URL entered. Please try again.{bcolors.ENDC}"
            )

        if not yes_no_menu(
            f"{bcolors.BOLD}\nDo you want to try a new website? (y/n): {bcolors.ENDC}"
        ):
            break
        another_url = True

    print(
        f"{bcolors.BOLD}{bcolors.OKCYAN}\nGoodbye! Thank you for using TAMPY :){bcolors.ENDC}"
    )
    print(f"{bcolors.OKBLUE}[INFO]: Exiting now...{bcolors.ENDC}")


if __name__ == "__main__":
    main()
