import json

from core.redaction import Redactor
from resources import ui


def redact_filtered(filtered_path, domain):
    """Produce a redacted copy of the filtered packets plus a local secret map.

    Replaces the old ``anonymize_har`` (which only swapped the domain string and
    left live cookies, tokens, emails and card numbers intact). Secrets are now
    replaced with reversible placeholders before anything is sent to the LLM;
    the placeholder->value map is written next to the redacted file and never
    leaves the machine.

    Returns (redacted_path, map_path) or (None, None) on failure.
    """
    try:
        redacted_path = filtered_path.replace(".json", "_redacted.json")
        map_path = filtered_path.replace(".json", "_secretmap.json")

        with open(filtered_path, encoding="utf-8") as f:
            packets = json.load(f)

        redactor = Redactor()
        redacted = redactor.redact_packets(packets)

        with open(redacted_path, "w", encoding="utf-8") as f:
            json.dump(redacted, f, indent=2)
        redactor.save_map(map_path)

        report = redactor.report()
        total = sum(report.values())
        if total:
            summary = ", ".join(f"{k.lower()}={v}" for k, v in report.items())
            ui.ok(f"Redacted {total} secret value(s) before LLM egress ({summary}).")
        else:
            ui.info("No secrets detected to redact.")
        ui.info(f"Redacted packets written to {redacted_path}")
        return redacted_path, map_path
    except Exception as e:
        ui.err(f"Failed to redact packets: {e}")
        return None, None


def parse_har(har_path, filtered_path, domain):
    try:
        with open(har_path, encoding="utf-8") as f:
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

        ui.ok(f"Filtered {len(filtered)} relevant packet(s) → {filtered_path}")
        redacted_path, map_path = redact_filtered(filtered_path, domain)

        return filtered_path, redacted_path, map_path

    except Exception as e:
        ui.err(f"Failed to parse HAR: {e}")
        return None, None, None
