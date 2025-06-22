import re
import sys
import time
import json
import urllib.parse
from phases.replay_flow import replay_actions_with_tamper
from resources.bcolors import bcolors
from resources.yes_no_menu import yes_no_menu


def replace_domain(data, actual_domain):
    """Recursively replace PRIVATE_DOMAIN.com in all string values."""
    if isinstance(data, str):
        # replace both with and without www.
        data = re.sub(r"\bPRIVATE_DOMAIN\.com\b", actual_domain, data)
        data = re.sub(r"\bwww\.PRIVATE_DOMAIN\.com\b", actual_domain, data)
        return data
    elif isinstance(data, dict):
        return {k: replace_domain(v, actual_domain) for k, v in data.items()}
    elif isinstance(data, list):
        return [replace_domain(item, actual_domain) for item in data]
    return data


def edit_packet(har_filtered, url_input, json_result, actions_file):
    print(f"{bcolors.OKBLUE}[INFO]: Available entries:{bcolors.ENDC}")
    actual_domain = urllib.parse.urlparse(url_input).netloc

    while True:
        for i, item in enumerate(json_result):
            print(
                f"  [{i}] Control={item['control_id']}  Packet Index={item['packet_index']}"
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

            if 0 <= idx < len(json_result):
                entry = json_result[idx]
                break

            print(f"{bcolors.FAIL}[ERROR]: Invalid selection!{bcolors.ENDC}")
            print(
                f"{bcolors.BOLD} Valid list indices: 0-{len(json_result) - 1}{bcolors.ENDC}"
            )

        # Get selected entry
        entry = json_result[idx]
        mod_req = entry["modified_request_example"]

        # Replace domain in all parts of the request
        mod_req = replace_domain(mod_req, actual_domain)
        mod_req_url = mod_req["url"]

        # Create minimal tamper config
        tamper_config = {
            "url_pattern": mod_req_url,
            "method": mod_req["method"],
            "param_location": entry["parameter_location"],
            "param_name": entry["parameter_name"],
            "param_value": entry["test_payload"],
        }

        # Debug output
        print(f"{bcolors.OKBLUE}[DEBUG] Tamper config includes:")
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
                # Simple one-field edit
                field = input(
                    f"{bcolors.BOLD}Enter field to change (e.g., headers.User-Agent or body): {bcolors.ENDC}"
                ).strip()
                newval = input(
                    f"{bcolors.BOLD}Enter new value for {field}: {bcolors.ENDC}"
                ).strip()

                # Update tamper config
                parts = field.split(".")
                current = tamper_config["tampered_data"]
                for p in parts[:-1]:
                    if p not in current:
                        current[p] = {}
                    current = current[p]
                current[parts[-1]] = newval

                print(f"{bcolors.OKBLUE}[INFO]: Modified tamper config: {bcolors.ENDC}")
                print(json.dumps(tamper_config, indent=2))

                if not yes_no_menu(
                    f"{bcolors.BOLD}Edit another field? (y/n): {bcolors.ENDC}"
                ):
                    break

        print(
            f"{bcolors.OKBLUE}[INFO]: Replaying flow with packet tampering...{bcolors.ENDC}"
        )
        try:
            replay_actions_with_tamper(actions_file, [tamper_config])
        except Exception as e:
            print(
                f"{bcolors.BOLD}{bcolors.FAIL}[ERROR]: Replay failed: {str(e)}{bcolors.ENDC}"
            )

        if not yes_no_menu(
            f"{bcolors.BOLD}Test another control? (y/n): {bcolors.ENDC}"
        ):
            break
