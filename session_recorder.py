import os
import json
import urllib.parse
from seleniumwire import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager
from bcolors import bcolors

def record_user_session(url, packets_dir):
    """
    Opens Firefox (via Selenium Wire) to capture all HTTP(S) traffic,
    allows the user to interact, then saves captured requests to JSON.
    """
    # Compute prefix for filenames
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    prefix = domain.split('.')[0]


    # Configure Selenium Wire (no extra options needed)
    options = Options()
    options.headless = False

    print(f"{bcolors.OKBLUE}Opening Firefox with Selenium Wire to capture traffic...{bcolors.ENDC}")
    driver = webdriver.Firefox(
        service=FirefoxService(GeckoDriverManager().install()),
        options=options
    )
    driver.get(url)

    input(f"{bcolors.BOLD}Press Enter when you have finished the interaction...{bcolors.ENDC}")

    # Collect and save captured requests
    print(f"{bcolors.OKBLUE}Saving captured requests to JSON...{bcolors.ENDC}")
    # tras calcular `prefix` y crear packets_dir…
    # Dominio objetivo (sin subdominio ni www)
    target = domain  

    # Lista de extensiones a ignorar
    ignored_exts = (
        ".png", ".jpg", ".jpeg", ".gif", ".css", ".js",
        ".ico", ".svg", ".woff", ".woff2", ".ttf", ".map"
    )

    ignored_analytics = (
        "google", "gtag", "analytics.js", "ga.js",
        "collect", "analytics", "track", "beacon", "facebook",
        "fbq", "mixpanel", "hotjar", "matomo", "piwik"
    )

    har_data = []
    
    for request in driver.requests:
        url = request.url.lower()

        # 1. filtrar sólo tu dominio
        if target not in url:
            continue

        # 2. ignorar estáticos por extensión
        if any(url.endswith(ext) for ext in ignored_exts):
            continue
        if any(term in url for term in ignored_analytics):
            continue

        # 3. ignorar métodos que no interesen
        if request.method not in ("GET", "POST", "PUT"):
            continue

        # 4. filtrar por content-type de la respuesta
        content_type = ""
        if request.response and "Content-Type" in request.response.headers:
            content_type = request.response.headers["Content-Type"]
        if content_type.startswith(("image/", "font/", "video/")):
            continue

        # Si pasa todos los filtros, lo metemos en el JSON
        entry = {
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
            "response": {
                "status_code": request.response.status_code if request.response else None,
                "headers": dict(request.response.headers) if request.response else None,
            },
            "body": request.body.decode('utf-8', errors='ignore') if request.body else None,
        }
        har_data.append(entry)

    har_filename = os.path.join(packets_dir, f"{prefix}_packets.json")
    with open(har_filename, "w", encoding="utf-8") as f:
        json.dump(har_data, f, indent=2)
    print(f"{bcolors.OKGREEN}Captured traffic saved to: {har_filename}{bcolors.ENDC}")

    driver.quit()
    print(f"{bcolors.OKCYAN}Session recording complete.{bcolors.ENDC}")
    return har_filename

