import json
from seleniumwire import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager
from resources.bcolors import bcolors
import gzip
import zlib

def decode_response_body(response):

    if not response.body:
        return None

    content_encoding = response.headers.get('Content-Encoding', '').lower()
    
    if content_encoding == 'gzip':
        return gzip.decompress(response.body).decode('utf-8', errors='ignore')
    elif content_encoding == 'deflate':
        return zlib.decompress(response.body).decode('utf-8', errors='ignore')
    
    return response.body.decode('utf-8', errors='ignore')

def record_user_session(url, domain, har_filename):
    """
    Opens Firefox (via Selenium Wire) to capture all HTTP(S) traffic,
    allows the user to interact, then saves captured requests to JSON.
    """

    # Configure Selenium Wire (no extra options needed)
    options = Options()
    options.headless = False

    print(f"{bcolors.OKBLUE}[INFO]: Opening Firefox with Selenium Wire to capture traffic...{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}[INFO]: If the Firefox browser does not open automatically, please exit and rerun Tampy.{bcolors.ENDC}")
    driver = webdriver.Firefox(
        service=FirefoxService(GeckoDriverManager().install()),
        options=options
    )
    driver.get(url)

    input(f"{bcolors.BOLD}Press Enter when you have finished the interaction...{bcolors.ENDC}")

    # Collect and save captured requests
    print(f"{bcolors.OKBLUE}[INFO]: Saving captured requests to JSON...{bcolors.ENDC}")
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
        if domain not in url:
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
            "body": request.body.decode('utf-8', errors='ignore') if request.body else None,
            "response": {
                "status_code": request.response.status_code if request.response else None,
                "headers": dict(request.response.headers) if request.response else None,
                # "body": decode_response_body(request.response) if request.response and request.response.body else None,
            },
            
        }
        har_data.append(entry)

    with open(har_filename, "w", encoding="utf-8") as f:
        json.dump(har_data, f, indent=2)
    print(f"{bcolors.OKGREEN}[SUCCESS]: Captured traffic saved to: {har_filename}{bcolors.ENDC}")

    print(f"{bcolors.OKBLUE}[INFO]: Session recording complete. Keeping browser open for replay tests…{bcolors.ENDC}")
    return har_filename, driver

