import os
import time
import json
import urllib.parse

def check_ecommerce_platforms(results):
    """
    Checks the scan results for any e-commerce technology and prints a message.
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
    
    if commerce_platforms_found:
        print("\nThe following E-Commerce technologies were detected:")
        for tech, cats in commerce_platforms_found.items():
            # Print in red (ANSI escape code)
            print("\033[91m" + f"{tech} - {', '.join(cats)}" + "\033[0m")
    else:
        print("\nNo E-Commerce technologies were detected.")
    
    return commerce_platforms_found

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
        print(f"\nResults saved to file: {filename}")
    except Exception as e:
        print("Error saving results to file:", e)
    return filename
