import os
import time
from wappalyzer import analyze
from webtech_rec import check_ecommerce_platforms, get_pretty_output, save_results_to_file

def animate_title():
    # ASCII art of the title "TAMPY"
    ascii_art = [
        " /$$$$$$$$ /$$$$$$  /$$      /$$ /$$$$$$$  /$$     /$$",
        "|__  $$__//$$__  $$| $$$    /$$$| $$__  $$|  $$   /$$/",
        "   | $$  | $$  \\ $$| $$$$  /$$$$| $$  \\ $$ \\  $$ /$$/ ",
        "   | $$  | $$$$$$$$| $$ $$/$$ $$| $$$$$$$/  \\  $$$$/  ",
        "   | $$  | $$__  $$| $$  $$$| $$| $$____/    \\  $$/   ",
        "   | $$  | $$  | $$| $$\\  $ | $$| $$          | $$    ",
        "   | $$  | $$  | $$| $$ \\/  | $$| $$          | $$    ",
        "   |__/  |__/  |__/|__/     |__/|__/          |__/     ",
        "                                                       "
    ]
    max_shift = 10

    # Move right faster
    for shift in range(max_shift):
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in ascii_art:
            print(" " * shift + line)
        time.sleep(0.05)
    
    # Move left faster
    for shift in range(max_shift, -1, -1):
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in ascii_art:
            print(" " * shift + line)
        time.sleep(0.05)
    
    # Remain fixed on the left and display the signature
    os.system('cls' if os.name == 'nt' else 'clear')
    for line in ascii_art:
        print(line)
    print("created by @1ukz")
    print("------------------------------------------------------------\n\n")
    time.sleep(0.5)

def main_menu():
    
    url_input = input("Enter the URL to analyze: ").strip()
    if not (url_input.startswith("http://") or url_input.startswith("https://")):
        modified_url = "https://www." + url_input
        print(f"URL modified to: {modified_url}")
        url_input = modified_url

    # Ask for the scan type
    scan_choice = input("Choose scan type: quick(q)/balanced(b)/full(f): ").strip().lower()
    if scan_choice == 'q':
        scan_type = 'quick'
    elif scan_choice == 'b':
        scan_type = 'balanced'
    elif scan_choice == 'f':
        scan_type = 'full'
    else:
        print("Invalid option. Using 'full' by default.")
        scan_type = 'full'

    return url_input, scan_type

def yes_no_menu(question):

    choice = input(question).strip().lower()
    
    if choice in ['y', 'yes']:
        return True
    else:
        return False

def main():
    animate_title()
    
    # Ask for the URL to analyze
    url_input, scan_type = main_menu()
    
    try:
        print("\nRunning PHASE 1: WEB TECHNOLOGIES ENUMERATION...")
        print("Please be patient until the scan is completed.")
        results = analyze(url_input, scan_type=scan_type)
    except Exception as e:
        print("An error occurred during analysis:", e)
        return

    # Check for e-commerce technologies
    commerce_platforms_found = check_ecommerce_platforms(results)
    
    # Generate pretty-formatted output (grouping technologies in rows)
    pretty_output = get_pretty_output(results, commerce_platforms_found, items_per_row=3)
    
    # Save the pretty output to a file
    filename = save_results_to_file(url_input, pretty_output)
    
    # Ask the user if they want to display the saved results on screen
    choice = yes_no_menu("\nDo you want to display the saved results on screen? (y/n): ")
    

        try:
            with open(filename, "r", encoding="utf-8") as f:
                file_content = f.read()
            print("\nDisplaying saved results:\n")
            print(file_content)
        except Exception as e:
            print("Error reading the saved file:", e)
    else:
        print("Skipping display of saved results.")
    
    # Phase 2 placeholder message (further automation would go here)
    print("\nPhase 1 completed. Starting Phase 2: Examination of Purchase Process Logic...\n")
    # (Phase 2 automation/integration with ZAP would be implemented here)

if __name__ == '__main__':
    main()
