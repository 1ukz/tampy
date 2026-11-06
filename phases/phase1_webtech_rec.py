import os
import re
import urllib.parse

import requests
from requests.exceptions import HTTPError, SSLError
from wappalyzer import analyze

from resources import ui
from resources.bcolors import bcolors

try:
    # verify=False in verify_website_exists would otherwise spam warnings.
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


def url_menu(url_skip_prompt, another_url):
    ui.section("Phase 1 · Web Technologies Enumeration", "Fingerprint the target stack")
    url_input = ""

    if (
        url_skip_prompt is not None
        and another_url is False
        or url_skip_prompt == "https://127.0.0.1:5000/"
    ):
        url_input = url_skip_prompt.strip()
        ui.ok(f"Using the provided URL: {url_input}")
        another_url = True
    else:
        url_input = input(f"{bcolors.BOLD}Enter the URL to analyze: {bcolors.ENDC}").strip()

    if not (url_input.startswith("http://") or url_input.startswith("https://")):
        pattern = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)
        if url_input.startswith("www."):
            modified_url = "https://" + url_input
        elif pattern.match(url_input):
            modified_url = "https://www." + url_input
        else:
            ui.err("URL does not have an expected format. Please check it and try again.")
            return None
        ui.info(f"URL normalised to: {modified_url}")
        url_input = modified_url
    return url_input


def parse_existing_file_for_ecommerce(filename):
    if not os.path.exists(filename):
        return False
    ecom_detected = False
    with open(filename, encoding="utf-8") as f:
        for line in f:
            if "e-commerce:" in line.lower():
                ecom_detected = True
    if ecom_detected:
        ui.hit("E-commerce technologies were detected (from existing log):")
    else:
        ui.ok("No e-commerce platform detected (from existing log).")
    return ecom_detected


def verify_website_exists(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "*/*",
    }
    try:
        # verify=False: a self-signed/invalid cert is common on test targets and
        # must not read as "site down". We only need to know the host answers.
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
        return True
    except SSLError:
        # Reached the server; only the TLS chain was unhappy. Treat as reachable.
        ui.warn(f"TLS certificate could not be verified for {url}; continuing.")
        return True
    except HTTPError as e:
        ui.err(f"Connection error {getattr(e.response, 'status_code', 'N/A')}: {e}")
        return False
    except Exception as e:
        ui.err(f"Connection error: {e}")
        return False


class ScanError(Exception):
    """Raised when technology enumeration fails (distinct from 'no e-commerce')."""


def scan_url(url_input, spinner):
    try:
        results = analyze(url_input, scan_type="full")
        return results
    except Exception as e:
        spinner.stop()
        ui.err(f"Technology enumeration failed: {e}")
        # Signal failure distinctly so the caller does NOT treat it as
        # "an e-commerce platform was found" and silently abort the run.
        raise ScanError(str(e)) from e


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
    for techs in results.values():
        for tech, details in techs.items():
            for platform in commerce_platforms:
                if platform.lower() in tech.lower():
                    found[tech] = details.get("categories", [])
    if found:
        spinner.stop()
        ui.hit("E-commerce platform technologies were detected:")
        for tech, cats in found.items():
            print(
                f"      {ui.paint('•', ui.C_ERR)} {tech} {ui.paint('— ' + ', '.join(cats), ui.C_MUTE)}"
            )
        return found, True
    else:
        spinner.stop()
        ui.ok("No e-commerce platform detected — target uses custom logic.")
        return found, False


def get_pretty_output(results, found, items_per_row=3):
    grouped = {}
    for techs in results.values():
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
        ui.err(f"Error saving log: {e}")
    return filename
