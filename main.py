import warnings
warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    message="pkg_resources is deprecated as an API.*"
)
import os
import time
import re
import urllib.parse
import time
import json
import argparse
from dotenv import load_dotenv
from webtech_rec import (
    scan_url,
    check_ecommerce_platforms,
    get_pretty_output,
    save_results_to_file,
    verify_website_exists,
    parse_existing_file_for_ecommerce
)
from resources.bcolors import bcolors
from session_recorder import record_user_session
from ai_analyzer import analyze_packets_with_ai

def animate_title():
    ascii_art = [
        f"{bcolors.BOLD} /$$$$$$$$ /$$$$$$  /$$      /$$ /$$$$$$$  /$$     /$$",
        "|__  $$__//$$__  $$| $$$    /$$$| $$__  $$|  $$   /$$/",
        "   | $$  | $$  \\ $$| $$$$  /$$$$| $$  \\ $$ \\  $$ /$$/ ",
        "   | $$  | $$$$$$$$| $$ $$/$$ $$| $$$$$$$/  \\  $$$$/  ",
        "   | $$  | $$__  $$| $$  $$$| $$| $$____/    \\  $$/   ",
        "   | $$  | $$  | $$| $$\\  $ | $$| $$          | $$    ",
        "   | $$  | $$  | $$| $$ \\/  | $$| $$          | $$    ",
        "   |__/  |__/  |__/|__/     |__/|__/          |__/     ",
        f"                                                       {bcolors.ENDC}"
    ]
    max_shift = 10
    for shift in range(max_shift):
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in ascii_art:
            print(" " * shift + line)
        time.sleep(0.05)
    for shift in range(max_shift, -1, -1):
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in ascii_art:
            print(" " * shift + line)
        time.sleep(0.05)
    os.system('cls' if os.name == 'nt' else 'clear')
    for line in ascii_art:
        print(line)
    print(f"{bcolors.BOLD}created by @1ukz{bcolors.ENDC}")
    print("------------------------------------------------------------\n\n")
    time.sleep(0.5)

def url_menu():
    url_input = input(f"{bcolors.BOLD}Enter the URL to analyze: {bcolors.ENDC}").strip()
    if not (url_input.startswith("http://") or url_input.startswith("https://")):
        pattern = re.compile(r'^([a-z0-9-]+\.)+[a-z]{2,}$', re.IGNORECASE)
        if url_input.startswith("www."):
            modified_url = "https://" + url_input
        elif pattern.match(url_input):
            modified_url = "https://www." + url_input
        else:
            print(f"{bcolors.BOLD}{bcolors.FAIL}URL does not have an expected format. Please check it and try again.{bcolors.ENDC}")
            return None
        print(f"{bcolors.WARNING}URL modified to: {modified_url}{bcolors.ENDC}")
        url_input = modified_url
    return url_input

def yes_no_menu(question):
    while True:
        choice = input(question).strip().lower()
        if choice not in ['y', 'yes', 'n', 'no']:
            print(f"{bcolors.BOLD}{bcolors.FAIL}Please enter 'y' or 'n'{bcolors.ENDC}")
        else:
            return choice in ['y', 'yes']

def phase_1(url_input, webtechs_dir):
    """
    - Checks if a previous analysis file exists in 'webtechs' folder.
    - Otherwise, run a new analysis, store the .log, and parse for e-commerce.
    """
    print(f"{bcolors.BOLD}{bcolors.HEADER}[PHASE 1]: WEB TECHNOLOGIES ENUMERATION...{bcolors.ENDC}")
    parsed_url = urllib.parse.urlparse(url_input)
    domain = parsed_url.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    prefix = domain.split('.')[0]
    
    filename = os.path.join(webtechs_dir, f"{prefix}_webtechs_found.log")
    
    if os.path.exists(filename):
        print(f"{bcolors.OKBLUE}A log file has been found for this URL. {bcolors.ENDC}")      
        if yes_no_menu(f"{bcolors.BOLD}Do you want to use the existing log file and skip enumeration? (y/n): {bcolors.ENDC}"):
            print(f"{bcolors.OKBLUE}Using existing log: {filename}{bcolors.ENDC}")
            time.sleep(1)
            ecommerce_found = parse_existing_file_for_ecommerce(filename)
            return ecommerce_found
        
    results = scan_url(url_input)
    if not results:
        return True
    
    platforms_found, ecommerce_found = check_ecommerce_platforms(results)
    pretty = get_pretty_output(results, platforms_found, items_per_row=3)
    save_results_to_file(url_input, pretty, webtechs_dir)
    print(f"{bcolors.OKGREEN}Webtechs log saved to: {filename}{bcolors.ENDC}")
    return ecommerce_found

def phase_2(url_input, packets_dir):
    print(f"{bcolors.BOLD}{bcolors.HEADER}\n[PHASE 2]: USER SESSION RECORDING...{bcolors.ENDC}")
        
    # Compute prefix for filenames
    parsed = urllib.parse.urlparse(url_input)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    prefix = domain.split('.')[0]

    har_filename = os.path.join(packets_dir, f"{prefix}_packets.json")
    
    if os.path.exists(har_filename):
        print(f"{bcolors.OKBLUE}A HAR file has been found for this URL. {bcolors.ENDC}")      
        if yes_no_menu(f"{bcolors.BOLD}Do you want to use the existing HAR file and skip recording? (y/n): {bcolors.ENDC}"):
            print(f"{bcolors.OKBLUE}Using existing HAR file: {har_filename}{bcolors.ENDC}")
            return har_filename
        
    har_file = record_user_session(url_input, domain, har_filename)
    if not har_file:
        print(f"{bcolors.FAIL}ERROR: No packets were captured or could not be analyzed.{bcolors.ENDC}")
        return None
    return har_file

def phase_3(har_filename, mode, streaming):
    print(f"{bcolors.BOLD}{bcolors.HEADER}\n[PHASE 3]: ANALYZING HTTP PACKETS...{bcolors.ENDC}")

    # 2) Llama al analizador (bloqueante)
    raw_result, result = analyze_packets_with_ai(har_filename, mode, streaming)
    
    if not result:
        print(f"{bcolors.FAIL}ERROR: No AI results to display. Raw response below for debugging:{bcolors.ENDC}\n")
        print(raw_result or "(no raw text captured)")
        print(f"\n{bcolors.OKCYAN}Phase 3 completed with errors.{bcolors.ENDC}")
        return

    print(f"\n{bcolors.BOLD}=== Analysis Results ==={bcolors.ENDC}\n")
    for item in result:
        print(f"{bcolors.UNDERLINE}Control:{bcolors.ENDC} {item['control_id']}")
        print(f" Packet index: {item['packet_index']}")
        print(f" Parameter: {item['parameter']}")
        print(f" Test: {item['test']}")
        print(" Modified request example:")
        print(json.dumps(item['modified_request_example'], indent=2))
        print("-" * 60)
    print(f"{bcolors.OKGREEN}Phase 3 completed successfully!{bcolors.ENDC}")


def startup():

    print(f"{bcolors.BOLD}{bcolors.OKBLUE}Welcome to TAMPY v1.0!{bcolors.ENDC}")

    load_dotenv()

    logs_dir = ".logs"
    os.makedirs(logs_dir, exist_ok=True)
    webtechs_dir = r".logs\webtechs"
    os.makedirs(webtechs_dir, exist_ok=True)
    packets_dir = r".logs\packets"
    os.makedirs(packets_dir, exist_ok=True)

    return logs_dir, webtechs_dir, packets_dir

def load_args():
    parser = argparse.ArgumentParser(description="TAMPY 1.0 - An E-Commerce Web Security Assessment Tool")
    lr_group = parser.add_mutually_exclusive_group(required=True)
    lr_group.add_argument('-L', '--local',  action='store_true',
                   help='Use local LLM server')
    lr_group.add_argument('-R', '--remote', action='store_true',
                   help='Use a remote LLM API')
    parser.add_argument('-S', '--stream',   action='store_true',  
                   help='Enable streaming mode for LLM output (default: false)')
    args = parser.parse_args()
    
    mode = 'local' if args.local else 'remote'  
    streaming = True if args.stream else False

    return mode, streaming

def main():
    mode, streaming = load_args()
    animate_title()
    logs_dir, webtechs_dir, packets_dir = startup()
    
    while True:
        url_input = url_menu()
        if url_input:
            if verify_website_exists(url_input):
                ecommerce_found = phase_1(url_input, webtechs_dir)
                if not ecommerce_found:
                    har_filename = phase_2(url_input, packets_dir)
                    if har_filename:
                        phase_3(har_filename, mode, streaming)
                    else:
                        print(f"{bcolors.FAIL}ERROR: No packets captured in Phase 2.{bcolors.ENDC}")
                else:
                    print(f"{bcolors.BOLD}{bcolors.FAIL}ERROR: The assessment cannot continue as an E-Commerce platform was found :({bcolors.ENDC}")
            else:
                print(f"{bcolors.FAIL}ERROR: The website does not exist or could not be accessed. Please try another URL.{bcolors.ENDC}")
        else:
            print(f"{bcolors.FAIL}ERROR: Invalid URL entered. Please try again.{bcolors.ENDC}")

        if not yes_no_menu(f"{bcolors.BOLD}\nDo you want to try a new website? (y/n): {bcolors.ENDC}"):
            break

    print(f"{bcolors.BOLD}{bcolors.OKCYAN}\nGoodbye! Thank you for using TAMPY :){bcolors.ENDC}")
    print(f"{bcolors.WARNING}Exiting now...{bcolors.ENDC}")


if __name__ == '__main__':
    main()
