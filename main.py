import os
import time
import re
import urllib.parse
from webtech_rec import (
    scan_url,
    check_ecommerce_platforms,
    get_pretty_output,
    save_results_to_file,
    verify_website_exists,
    parse_existing_file_for_ecommerce
)
from bcolors import bcolors
from session_recorder import record_user_session

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
    url_input = input(f"{bcolors.BOLD}Enter the URL to analyze: {bcolors.ENDC}").strip().lower()
    if not (url_input.startswith("http://") or url_input.startswith("https://")):
        pattern = re.compile(r'^([a-z0-9-]+\.)+[a-z]{2,}$')
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


def phase_1(url_input):
    """
    - Checks if a previous analysis file exists.
      - If so, parse it to see if e-commerce was found (without printing the entire file).
    - Otherwise, run a new analysis, store the results, and parse them for e-commerce.
    """
    parsed_url = urllib.parse.urlparse(url_input)
    domain = parsed_url.netloc
    if domain.startswith("www."):
        domain = domain[4:]
    prefix = domain.split('.')[0]
    filename = f"{prefix}_webtechs_found.txt"
    
    if os.path.exists(filename):
        time.sleep(1)
        print(f"{bcolors.OKBLUE}Found existing analysis file: {filename}. Using existing results...{bcolors.ENDC}")
        # Parse the file to see if it indicates e-commerce
        ecommerce_found = parse_existing_file_for_ecommerce(filename)
        return ecommerce_found
    else:
        results = scan_url(url_input)
        if not results:
            # If scanning failed, assume no e-commerce found, but skip Phase 2
            return True  # Return True to skip Phase 2
        ecommerce_platforms_found, ecommerce_found = check_ecommerce_platforms(results)
        pretty_output = get_pretty_output(results, ecommerce_platforms_found, items_per_row=3)
        filename = save_results_to_file(url_input, pretty_output)
        
        # Display the same messages as if the scan was done live:
        # check_ecommerce_platforms already printed "No E-Commerce..." or "The following E-Commerce..."
        
        # Optionally ask to show the entire file
        if yes_no_menu(f"{bcolors.BOLD}\nDo you want to display the saved results on screen? (y/n): {bcolors.ENDC}"):
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    print(f"{bcolors.BOLD}\nDisplaying saved results:\n{bcolors.ENDC}")
                    print(f.read())
            except Exception as e:
                print(f"{bcolors.FAIL}Error reading the saved file:{bcolors.ENDC}", e)
        else:
            print(f"{bcolors.WARNING}Skipping display of saved results.{bcolors.ENDC}")
        
        return ecommerce_found

def main():
    animate_title()
    
    while True:
        url_input = url_menu()
        if url_input:
            if verify_website_exists(url_input):
                # Phase 1
                ecommerce_found = phase_1(url_input)
                if not ecommerce_found:
                    print(f"{bcolors.BOLD}{bcolors.HEADER}\nRunning PHASE 2: USER SESSION RECORDING...\n{bcolors.ENDC}")
                    time.sleep(1)
                    record_user_session(url_input)
                else:
                    print(f"{bcolors.BOLD}{bcolors.FAIL}The assessment cannot continue as an E-Commerce platform was found :({bcolors.ENDC}")
            else:
                print(f"{bcolors.FAIL}The website does not exist or could not be accessed. Please try another URL.{bcolors.ENDC}")
        else:
            print(f"{bcolors.FAIL}Invalid URL entered. Please try again.{bcolors.ENDC}")

        if not yes_no_menu(f"{bcolors.BOLD}\nDo you want to try a new website? (y/n): {bcolors.ENDC}"):
            break

    print(f"{bcolors.BOLD}{bcolors.OKCYAN}\nGoodbye! Thank you for using TAMPY :){bcolors.ENDC}")
    print(f"{bcolors.WARNING}Exiting now...{bcolors.ENDC}")

if __name__ == '__main__':
    main()
