import json
import gzip
import zlib
import os
from resources.bcolors import bcolors


def decode_response_body(content, encoding):
    if encoding == "gzip":
        return gzip.decompress(content).decode("utf-8", errors="ignore")
    if encoding == "deflate":
        return zlib.decompress(content).decode("utf-8", errors="ignore")
    return content.decode("utf-8", errors="ignore")


def parse_har(har_path, filtered_path, domain):
    """
    Reads a Playwright-generated HAR, filters out:
      - resources not on `domain`
      - static file extensions (images, fonts, etc.)
      - analytics/tracking hosts
      - non-GET/POST/PUT methods
      - binary content-types (image/, font/, video/)
    Then writes the remaining requests as a JSON list to `filtered_path`.
    """
    with open(har_path, "r", encoding="utf-8") as f:
        har = json.load(f)
    entries = har.get("log", {}).get("entries", [])

    ignored_exts = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".css",
        ".js",
        ".ico",
        ".svg",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
    )
    ignored_analytics = (
        "google",
        "gtag",
        "analytics.js",
        "ga.js",
        "collect",
        "analytics",
        "track",
        "beacon",
        "facebook",
        "fbq",
        "mixpanel",
        "hotjar",
        "matomo",
        "piwik",
    )

    filtered = []
    for idx, entry in enumerate(entries):
        req = entry["request"]
        res = entry["response"]
        url = req["url"].lower()

        if domain not in url:
            continue
        if any(url.endswith(ext) for ext in ignored_exts):
            continue
        if any(term in url for term in ignored_analytics):
            continue
        if req["method"] not in ("GET", "POST", "PUT"):
            continue

        # find content-type
        content_type = ""
        for h in res.get("headers", []):
            if h["name"].lower() == "content-type":
                content_type = h["value"]
                break
        if content_type.startswith(("image/", "font/", "video/")):
            continue

        body = None
        if "text" in req.get("postData", {}):
            body = req["postData"]["text"]

        packet = {
            "packet_index": idx,
            "method": req["method"],
            "url": req["url"],
            "headers": {h["name"]: h["value"] for h in req.get("headers", [])},
            "body": body,
            "response": {
                "status_code": res.get("status"),
                "headers": {h["name"]: h["value"] for h in res.get("headers", [])},
            },
        }
        filtered.append(packet)

    with open(filtered_path, "w", encoding="utf-8") as f:
        json.dump(filtered, f, indent=2)

    print(
        f"{bcolors.OKGREEN}[SUCCESS]: Filtered packets saved to: {filtered_path}{bcolors.ENDC}"
    )
    return filtered_path
