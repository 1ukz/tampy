import urllib.parse
from wappalyzer import analyze
from bcolors import bcolors
import requests


def verify_website_exists(url):
    """
    Verifica que la página existe intentando descargarla.
    Retorna True si se accede correctamente (código 200), False en caso contrario.
    """
    try:
        # Se utiliza GET ya que algunos servidores no responden bien a HEAD.
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"{bcolors.BOLD}{bcolors.FAIL}Connection error: The website does not exist or could not be accessed. Please try another URL.{bcolors.ENDC}")
        print(f"{bcolors.FAIL}({e}{bcolors.ENDC}")   
        return False

def scan_url(url_input, scan_type): 
    try:
        print(f"{bcolors.BOLD}{bcolors.HEADER}\nRunning PHASE 1: WEB TECHNOLOGIES ENUMERATION...{bcolors.ENDC}")
        print(f"{bcolors.HEADER}Please be patient until the scan is completed.{bcolors.ENDC}")
        results = analyze(url_input, scan_type=scan_type)
        return results  # Devolver el resultado obtenido
    except Exception as e:
        print(f"{bcolors.FAIL}An error occurred during analysis:{bcolors.ENDC}", e)
        return None

def check_ecommerce_platforms(results):
    """
    Checks the scan results for any e-commerce technology and prints a message.ENDCCC
    Returns a dictionary of detected e-commerce technologies.
    """
    commerce_platforms = [
        "Ecommerce", "Shopify", "Wix", "WooCommerce", "PrestaShop", "Joomla", 
        "Magento", "BigCommerce", "Squarespace", "OpenCart", "Zen Cart", 
        "Shopware", "Salesforce Commerce Cloud", "Ecwid", "Weebly"
    ]
    
    commerce_platforms_found = {}
    # Iterate over results (structure: {url: {technology: {details}}})
    for analyzed_url, techs in results.items():
        for tech, details in techs.items():
            for platform in commerce_platforms:
                if platform.lower() in tech.lower():
                    commerce_platforms_found[tech] = details.get("categories", [])
    
    ecommerce_found = False

    if commerce_platforms_found:
        print(f"{bcolors.FAIL}{bcolors.BOLD}\nThe following E-Commerce technologies were detected:{bcolors.ENDC}")
        for tech, cats in commerce_platforms_found.items():
            # Print in red (ANSI escape code)
            print(f"{bcolors.FAIL}{tech} - {', '.join(cats)}{bcolors.ENDC}")
        ecommerce_found = True
    else:
        print(f"{bcolors.BOLD}{bcolors.OKGREEN}\nNo E-Commerce technologies were detected!! :){bcolors.ENDC}")
    
    return commerce_platforms_found, ecommerce_found

def get_pretty_output(results, commerce_platforms_found, items_per_row=3):
    """
    Generates a pretty-formatted string that groups technologies by category.
    Each category will be displayed with up to items_per_row per row.
    E-commerce technologies are marked with the prefix 'E-COMMERCE:'.
    """
    grouped_by_category = {}
    for analyzed_url, techs in results.items():
        for tech, details in techs.items():
            for cat in details.get("categories", []):
                grouped_by_category.setdefault(cat, []).append(tech)
    
    lines = []
    for cat, tech_list in grouped_by_category.items():
        lines.append(f"Category: {cat}")
        lines.append("-" * (10 + len(cat)))
        row = []
        for index, tech in enumerate(tech_list, start=1):
            if tech in commerce_platforms_found:
                row.append(f"E-COMMERCE: {tech} - {cat}")
            else:
                row.append(tech)
            if index % items_per_row == 0:
                lines.append(" | ".join(row))
                row = []
        if row:
            lines.append(" | ".join(row))
        lines.append("")  # Blank line for separation
    return "\n".join(lines)

def save_results_to_file(url, content):
    """
    Saves the given content to a text file whose name is derived from the URL.
    Returns the filename.
    """
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    if domain.startswith("www."):
        domain = domain[4:]
    prefix = domain.split('.')[0]
    filename = f"{prefix}_webtechs_found.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"{bcolors.OKBLUE}\nResults saved to file: {filename}{bcolors.ENDC}")
    except Exception as e:
        print(f"{bcolors.FAIL} Error saving results to file:{bcolors.ENDC}", e)
    return filename
