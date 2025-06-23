import json
import re
from resources.bcolors import bcolors

# ==== AI USE to generate an initial anonymization function and improve some sections in parser ====


def anonymize_har(har_path: str, domain: str):
    try:
        replacement = "PRIVATE_DOMAIN.com"
        output_path = har_path.replace(".har", f"_{replacement}.har")

        """
        Load a HAR at har_path, replace all occurrences of `domain`
        in any string value with `replacement`, and write it back
        to output_path.
        """
        # compile once, for case‐insensitive replacement
        pat = re.compile(re.escape(domain), re.IGNORECASE)

        def recurse(obj):
            # walk the JSON tree
            if isinstance(obj, dict):
                return {k: recurse(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [recurse(item) for item in obj]
            elif isinstance(obj, str):
                # replace anywhere in the string
                return pat.sub(replacement, obj)
            else:
                return obj

        # load, transform, write
        with open(har_path, "r", encoding="utf-8") as f:
            har = json.load(f)

        har_anon = recurse(har)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(har_anon, f, indent=2)

        print(
            f"{bcolors.OKBLUE}[INFO]: Anonymized HAR written to {output_path}.{bcolors.ENDC}"
        )
    except Exception as e:
        print(f"{bcolors.FAIL}[ERROR]: Failed to anonymize HAR: {e}{bcolors.ENDC}")
        return None

    return output_path


def parse_har(har_path, filtered_path, domain):
    try:
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
            "twitter",
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
        anon_path = anonymize_har(filtered_path, domain)

        return filtered_path, anon_path

    except Exception as e:
        print(f"{bcolors.FAIL}[ERROR]: Failed to parse HAR: {e}{bcolors.ENDC}")
        return None, None
