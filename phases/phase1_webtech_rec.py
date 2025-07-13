import re
import urllib.parse
import os
from wappalyzer import analyze
from resources.bcolors import bcolors
import requests
from requests.exceptions import SSLError, HTTPError


def url_menu(url_skip_prompt, another_url):
    print(
        f"{bcolors.BOLD}{bcolors.HEADER}[PHASE 1]: WEB TECHNOLOGIES ENUMERATION{bcolors.ENDC}"
    )
    url_input = ""

    if (
        url_skip_prompt is not None
        and another_url is False
        or url_skip_prompt == "https://127.0.0.1:5000/"
    ):
        url_input = url_skip_prompt.strip()
        print(
            f"{bcolors.BOLD}{bcolors.OKGREEN} Using the provided URL: {url_input} {bcolors.ENDC}"
        )
        another_url = True
    else:
        url_input = input(
            f"{bcolors.BOLD}Enter the URL to analyze: {bcolors.ENDC}"
        ).strip()

    if not (url_input.startswith("http://") or url_input.startswith("https://")):
        pattern = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)
        if url_input.startswith("www."):
            modified_url = "https://" + url_input
        elif pattern.match(url_input):
            modified_url = "https://www." + url_input
        else:
            print(
                f"{bcolors.BOLD}{bcolors.FAIL}URL does not have an expected format. Please check it and try again.{bcolors.ENDC}"
            )
            return None
        print(f"{bcolors.OKBLUE}[INFO]: URL modified to: {modified_url}{bcolors.ENDC}")
        url_input = modified_url
    return url_input


def parse_existing_file_for_ecommerce(filename):
    if not os.path.exists(filename):
        return False
    ecom_detected = False
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            if "e-commerce:" in line.lower():
                ecom_detected = True
    if ecom_detected:
        print(
            f"{bcolors.FAIL}{bcolors.BOLD}\nThe following E-Commerce technologies were detected (from existing log):{bcolors.ENDC}"
        )
    else:
        print(
            f"{bcolors.BOLD}{bcolors.OKGREEN}[SUCCESS]: No E-Commerce technologies were detected (from existing log)!! :){bcolors.ENDC}"
        )
    return ecom_detected


def verify_website_exists(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "*/*",
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return True
    except SSLError:
        pass
    except HTTPError as e:
        print(
            f"{bcolors.BOLD}{bcolors.FAIL}Connection 4XX or 5XX [ERROR]: : {e} (status {getattr(e.response, 'status_code', 'N/A')}){bcolors.ENDC}"
        )
        return False
    except Exception as e:
        print(f"{bcolors.BOLD}{bcolors.FAIL}Connection [ERROR]: : {e}{bcolors.ENDC}")
        return False


def scan_url(url_input, spinner):
    try:
        results = analyze(url_input, scan_type="full")
        return results
    except Exception as e:
        print(
            f"{bcolors.FAIL}An [ERROR]: Error occurred during analysis: {e}{bcolors.ENDC}"
        )
        return None


def check_ecommerce_platforms(results, spinner):
    commerce_platforms = [
        "Ecommerce",
        "Shopify",
        "Wix",
        "WooCommerce",
        "PrestaShop",
        "Joomla",
        "Magento",
        "BigCommerce",
        "Squarespace",
        "OpenCart",
        "Zen Cart",
        "Shopware",
        "Salesforce Commerce Cloud",
        "Ecwid",
        "Weebly",
    ]
    found = {}
    for analyzed_url, techs in results.items():
        for tech, details in techs.items():
            for platform in commerce_platforms:
                if platform.lower() in tech.lower():
                    found[tech] = details.get("categories", [])
    if found:
        spinner.stop()
        print(
            f"{bcolors.FAIL}{bcolors.BOLD}\nThe following E-Commerce technologies were detected:{bcolors.ENDC}"
        )
        for tech, cats in found.items():
            print(f"{bcolors.FAIL}{tech} - {', '.join(cats)}{bcolors.ENDC}")
        return found, True
    else:
        spinner.stop()
        print(
            f"{bcolors.BOLD}{bcolors.OKGREEN}[SUCCESS]: No E-Commerce technologies were detected!! :){bcolors.ENDC}"
        )
        return found, False


def get_pretty_output(results, found, items_per_row=3):
    grouped = {}
    for url, techs in results.items():
        for tech, details in techs.items():
            for cat in details.get("categories", []):
                grouped.setdefault(cat, []).append(tech)
    lines = []
    for cat, tech_list in grouped.items():
        lines.append(f"Category: {cat}")
        lines.append("-" * (10 + len(cat)))
        row = []
        for i, tech in enumerate(tech_list, 1):
            label = f"E-COMMERCE: {tech} - {cat}" if tech in found else tech
            row.append(label)
            if i % items_per_row == 0:
                lines.append(" | ".join(row))
                row = []
        if row:
            lines.append(" | ".join(row))
        lines.append("")
    return "\n".join(lines)


def save_results_to_file(url, content, logs_dir):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    prefix = domain.split(".")[0]
    filename = os.path.join(logs_dir, f"{prefix}_webtechs_found.log")
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        print(f"{bcolors.FAIL} [ERROR]: Error saving log:{bcolors.ENDC} {e}")
    return filename
