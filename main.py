import os
import time
import re
from webtech_rec import scan_url, check_ecommerce_platforms, get_pretty_output, save_results_to_file, verify_website_exists
from html_analyzer import search_html_for_keywords
from bcolors import bcolors

def animate_title():
    # ASCII art of the title "TAMPY"
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

    # Desplazar hacia la derecha
    for shift in range(max_shift):
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in ascii_art:
            print(" " * shift + line)
        time.sleep(0.05)
    
    # Desplazar hacia la izquierda
    for shift in range(max_shift, -1, -1):
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in ascii_art:
            print(" " * shift + line)
        time.sleep(0.05)
    
    # Mostrar el título fijo y la firma
    os.system('cls' if os.name == 'nt' else 'clear')
    for line in ascii_art:
        print(line)
    print(f"{bcolors.BOLD}created by @1ukz{bcolors.ENDC}")
    print("------------------------------------------------------------\n\n")
    time.sleep(0.5)

def url_menu():
    url_input = input(f"{bcolors.BOLD}Enter the URL to analyze: {bcolors.ENDC}").strip().lower()
    
    # Si la URL no comienza con http:// o https://, se intenta corregir:
    if not (url_input.startswith("http://") or url_input.startswith("https://")):
        # Expresión regular para un dominio simple (ej. ejemplo.com o sub.ejemplo.com)
        pattern = re.compile(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}$')
        if url_input.startswith("www."):
            modified_url = "https://" + url_input
        elif pattern.match(url_input):
            modified_url = "https://www." + url_input
        else:
            print(f"{bcolors.BOLD}{bcolors.FAIL}URL does not have an expected format. Please check it is correctly introduced, and try again.{bcolors.ENDC}")
            url_input = None
            return url_input, None
        
        print(f"{bcolors.WARNING}URL modified to: {modified_url}{bcolors.ENDC}")
        url_input = modified_url

    # Preguntar por el tipo de escaneo
    scan_choice = input(f"{bcolors.BOLD}Choose scan type: quick(q)/balanced(b)/full(f): {bcolors.ENDC}").strip().lower()
    if scan_choice == 'q':
        scan_type = 'quick'
    elif scan_choice == 'b':
        scan_type = 'balanced'
    elif scan_choice == 'f':
        scan_type = 'full'
    else:
        print(f"{bcolors.WARNING}Invalid option. Using 'full' by default.{bcolors.ENDC}")
        scan_type = 'full'

    return url_input, scan_type

def yes_no_menu(question):
    choice = input(question).strip().lower()
    return choice in ['y', 'yes']

def phase_2(url_input):
    # Define the list of keywords to search for (can be modified as needed)
    keywords = ['cart', 'shopping cart', 'bag']
    search_html_for_keywords(url_input, keywords)

def phase_1(url_input, scan_type):
    # Ejecuta el escaneo de tecnologías web
    results = scan_url(url_input, scan_type)
    
    # Comprueba tecnologías de e-commerce
    ecommerce_platforms_found, ecommerce_found = check_ecommerce_platforms(results)
    
    # Genera salida formateada
    pretty_output = get_pretty_output(results, ecommerce_platforms_found, items_per_row=3)
    
    # Guarda la salida en un fichero
    filename = save_results_to_file(url_input, pretty_output)
    
    # Preguntar si se quiere mostrar el fichero en pantalla
    choice = yes_no_menu(f"{bcolors.BOLD}\nDo you want to display the saved results on screen? (y/n): {bcolors.ENDC}")
    if choice:
        try:
            with open(filename, "r", encoding="utf-8") as f:
                file_content = f.read()
                print(f"{bcolors.BOLD}\nDisplaying saved results:\n{bcolors.ENDC}")
                print(file_content)
        except Exception as e:
            print(f"{bcolors.FAIL}Error reading the saved file:{bcolors.ENDC}", e)
    else:
        print(f"{bcolors.WARNING}Skipping display of saved results.{bcolors.ENDC}")
    
    return ecommerce_found

def main():
    animate_title()
    
    while True:
        url_input, scan_type = url_menu()
        
        if url_input is not None:
            if verify_website_exists(url_input):
                ecommerce_found = phase_1(url_input, scan_type)
            
                if ecommerce_found != True:
                    print(f"{bcolors.BOLD}{bcolors.HEADER}\nRunning PHASE 2: EXAMINATION OF PURCHASE LOGIC...\n{bcolors.ENDC}")
                    time.sleep(1)
                    phase_2(url_input)
                else:
                    print(f"{bcolors.BOLD}{bcolors.FAIL}The assessment cannot continue as an E-Commerce platform was found :({bcolors.ENDC}")

        if not yes_no_menu(f"{bcolors.BOLD}\nDo you want to try a new website? (y/n): {bcolors.ENDC}"):
            break

    print(f"{bcolors.BOLD}{bcolors.OKCYAN}\nGoodbye! Thank you for using TAMPY :){bcolors.ENDC}")
    print(f"{bcolors.WARNING}Exiting now...{bcolors.ENDC}")

if __name__ == '__main__':
    main()
