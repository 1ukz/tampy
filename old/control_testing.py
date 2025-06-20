import re
import shutil
import subprocess
import sys
import traceback
from phases.replay_flow import replay_flow
from resources.bcolors import bcolors
from resources.yes_no_menu import yes_no_menu
import json
import os
import asyncio


def edit_packet(har_filtered, url_input, json_result, actions_file):
    print(f"{bcolors.OKBLUE}[INFO]: Available entries:{bcolors.ENDC}")

    # Create replay directory if not exists
    replay_dir = os.path.join(os.path.dirname(actions_file), "replay")
    os.makedirs(replay_dir, exist_ok=True)

    for i, item in enumerate(json_result):
        print(
            f"  [{i}] Control={item['control_id']}  Packet Index={item['packet_index']}"
        )

    while True:
        choice = input(
            f"{bcolors.BOLD}Select entry by list index: {bcolors.ENDC}"
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
            f"{bcolors.BOLD}  ↳ Valid list indices: 0-{len(json_result) - 1}{bcolors.ENDC}"
        )

    # Get selected entry
    index = entry["packet_index"]
    mod_req = entry["modified_request_example"]

    # Extract original request details from modified request example
    original_method = mod_req["method"]
    original_url = mod_req["url"]

    print(
        f"{bcolors.OKBLUE}[INFO]: Selected request:\n {bcolors.ENDC}",
        json.dumps(mod_req, indent=2),
    )

    if not yes_no_menu(
        f"{bcolors.BOLD}Send this packet as it is? (y/n): {bcolors.ENDC}"
    ):
        while True:
            # Simple one-field edit
            field = input(
                f"{bcolors.BOLD}Enter field to change (e.g., headers.User-Agent or body): {bcolors.ENDC}"
            ).strip()
            newval = input(
                f"{bcolors.BOLD}Enter new value for {field}: {bcolors.ENDC}"
            ).strip()

            # Drill down to modify specific field
            parts = field.split(".")
            obj = mod_req
            for p in parts[:-1]:
                if p not in obj:
                    obj[p] = {}
                obj = obj[p]
            obj[parts[-1]] = newval

            print(f"{bcolors.OKBLUE}[INFO]: Modified request: {bcolors.ENDC}")
            print(json.dumps(mod_req, indent=2))

            if not yes_no_menu(
                f"{bcolors.BOLD}Edit another field? (y/n): {bcolors.ENDC}"
            ):
                break

    print(
        f"{bcolors.OKBLUE}[INFO]: Replaying packets with your modification...{bcolors.ENDC}"
    )

    # Create modified actions file
    modified_actions = os.path.join(
        replay_dir, f"modified_{os.path.basename(actions_file)}"
    )
    shutil.copy(actions_file, modified_actions)

    # Inject modification code into actions script
    with open(modified_actions, "r+", encoding="utf-8") as f:
        content = f.read()

        # Find page creation line
        page_creation = re.search(r"page\s*=\s*await context\.new_page\(\)", content)
        if not page_creation:
            print(
                f"{bcolors.FAIL}[ERROR]: Couldn't find page creation in actions script{bcolors.ENDC}"
            )
            return

        # Insert route handler after page creation
        start_pos = page_creation.end()
        new_content = (
            content[:start_pos]
            + "\n\n"
            + ROUTE_HANDLER_TEMPLATE.format(
                orig_method=json.dumps(original_method),
                orig_url=json.dumps(original_url),
                new_method=json.dumps(mod_req["method"]),
                new_headers=json.dumps(mod_req.get("headers", {})),
                new_body=json.dumps(mod_req.get("body", "")),
            )
            + content[start_pos:]
        )

        f.seek(0)
        f.write(new_content)
        f.truncate()

    # Replay with modified script
    replay_flow(modified_actions, url_input)

    print(
        f"{bcolors.BOLD}{bcolors.OKGREEN}[SUCCESS]: All packets replayed! Evaluate results.{bcolors.ENDC}"
    )


# Template for request interception
ROUTE_HANDLER_TEMPLATE = """
    # ------ TAMPY Request Interceptor ------
    async def handle_route(route, request):
        if request.method == {orig_method} and request.url == {orig_url}:
            print("\\n>> Intercepting request: ", request.url)
            await route.continue_(method={new_method}, headers={new_headers}, post_data={new_body})
        else:
            await route.continue_()
            
    await page.route("**/*", handle_route)
    # ---------------------------------------
"""
