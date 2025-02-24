import os
import time
import json
from wappalyzer import analyze

def animate_title():
    # ASCII art del título "TAMPY"
    ascii_art = [
        " /$$$$$$$$ /$$$$$$  /$$      /$$ /$$$$$$$  /$$     /$$",
        "|__  $$__//$$__  $$| $$$    /$$$| $$__  $$|  $$   /$$/",
        "   | $$  | $$  \ $$| $$$$  /$$$$| $$  \ $$ \  $$ /$$/ ", 
        "   | $$  | $$$$$$$$| $$ $$/$$ $$| $$$$$$$/  \  $$$$/  ", 
        "   | $$  | $$__  $$| $$  $$$| $$| $$____/    \  $$/   ", 
        "   | $$  | $$  | $$| $$\  $ | $$| $$          | $$    ", 
        "   | $$  | $$  | $$| $$ \/  | $$| $$          | $$    ", 
        "   |__/  |__/  |__/|__/     |__/|__/          |__/     ", 
        "                                                       "
    ]
    max_shift = 10

    # Desplaza a la derecha
    for shift in range(max_shift):
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in ascii_art:
            print(" " * shift + line)
        time.sleep(0.1)
    
    # Desplaza a la izquierda
    for shift in range(max_shift, -1, -1):
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in ascii_art:
            print(" " * shift + line)
        time.sleep(0.1)
    
    # Queda fijo a la izquierda y muestra la firma
    os.system('cls' if os.name == 'nt' else 'clear')
    for line in ascii_art:
        print(line)
    print("created by @1ukz")
    print("------------------------------------------------------------\n\n")
    time.sleep(0.5)

def main():
    animate_title()
    
    # Preguntar por la URL a analizar
    url_input = input("Introduce la URL a analizar: ").strip()
    
    # Preguntar por el tipo de scan a realizar
    scan_choice = input("Elige el tipo de scan: quick(q)/balanced(b)/full(f): ").strip().lower()
    if scan_choice == 'q':
        scan_type = 'quick'
    elif scan_choice == 'b':
        scan_type = 'balanced'
    elif scan_choice == 'f':
        scan_type = 'full'
    else:
        print("Opción no válida. Usando 'full' por defecto.")
        scan_type = 'full'
    
    try:
        results = analyze(url_input, scan_type=scan_type)
    except Exception as e:
        print("Se ha producido un error durante el análisis:", e)
        return

    # Lista de plataformas a buscar
    platforms = [
        "Ecommerce", "Shopify", "Wix", "WooCommerce", "PrestaShop", "Joomla", 
        "Magento", "BigCommerce", "Squarespace", "OpenCart", "Zen Cart", 
        "Shopware", "Salesforce Commerce Cloud", "Ecwid", "Weebly"
    ]
    
    found = False
    # Iterar por todas las entradas del diccionario (la estructura es {url: {tecnologia: {detalles}}})
    for analyzed_url, techs in results.items():
        for tech, details in techs.items():
            for platform in platforms:
                if platform.lower() in tech.lower():
                    print(f"\nSe ha encontrado: {platform}")
                    # Imprime el JSON en el que se encontro la tecnologia
                    print(json.dumps({tech: details}, indent=4, sort_keys=True))
                    found = True
                    break
            if found:
                break
        if found:
            break

    if not found:
        print("\nNo se ha encontrado ninguna de las plataformas buscadas en el resultado.")

if __name__ == '__main__':
    main()
