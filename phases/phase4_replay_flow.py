import importlib
import json
from pathlib import Path
import urllib.parse
import base64
import zlib
import gzip
from io import BytesIO
from playwright.sync_api import sync_playwright
from resources.bcolors import bcolors


PAUSE_SNIPPET = [
    "    # ---------------------\n",
    "    from resources.bcolors import bcolors \n",
    "    print(f'{bcolors.BOLD}{bcolors.OKGREEN} [SUCCESS]: All packets replayed! Evaluate the results. {bcolors.ENDC}')\n",
    "    print(f'{bcolors.BOLD}{bcolors.WARNING} Press <ENTER> to close browser. {bcolors.ENDC}')\n",
    "    input()\n",
]


def debugLog(message, debug):
    if debug:
        print(f"{bcolors.OKCYAN}{message}{bcolors.ENDC}")


def decode_value(value):
    """Decode a value using common encodings and return decoded data with encoding type."""
    try:
        base64_decoded_bytes = base64.b64decode(value)
        try:
            decompressed = zlib.decompress(base64_decoded_bytes).decode("utf-8")
            try:
                return json.loads(decompressed), "base64+deflate"
            except json.JSONDecodeError:
                return decompressed, "base64+deflate"
        except zlib.error:
            try:
                with gzip.GzipFile(fileobj=BytesIO(base64_decoded_bytes)) as f:
                    decompressed = f.read().decode("utf-8")
                try:
                    return json.loads(decompressed), "base64+gzip"
                except json.JSONDecodeError:
                    return decompressed, "base64+gzip"
            except (OSError, zlib.error):
                try:
                    decoded_str = base64_decoded_bytes.decode("utf-8")
                    try:
                        return json.loads(decoded_str), "base64"
                    except json.JSONDecodeError:
                        return decoded_str, "base64"
                except UnicodeDecodeError:
                    pass
    except (base64.binascii.Error, UnicodeDecodeError):
        pass

    try:
        decompressed = zlib.decompress(value.encode("latin1")).decode("utf-8")
        try:
            return json.loads(decompressed), "deflate"
        except json.JSONDecodeError:
            return decompressed, "deflate"
    except zlib.error:
        pass

    try:
        with gzip.GzipFile(fileobj=BytesIO(value.encode("latin1"))) as f:
            decompressed = f.read().decode("utf-8")
        try:
            return json.loads(decompressed), "gzip"
        except json.JSONDecodeError:
            return decompressed, "gzip"
    except (OSError, zlib.error):
        pass

    try:
        return json.loads(value), None
    except json.JSONDecodeError:
        return value, None


def encode_value(value, encoding):
    """Re-encode a value using the specified encoding."""
    if isinstance(value, dict):
        value = json.dumps(value)
    if encoding == "base64+deflate":
        compressed = zlib.compress(value.encode("utf-8"))
        return base64.b64encode(compressed).decode("utf-8")
    elif encoding == "base64+gzip":
        buf = BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as f:
            f.write(value.encode("utf-8"))
        return base64.b64encode(buf.getvalue()).decode("utf-8")
    elif encoding == "base64":
        return base64.b64encode(value.encode("utf-8")).decode("utf-8")
    elif encoding == "deflate":
        return zlib.compress(value.encode("utf-8")).decode("latin1")
    elif encoding == "gzip":
        buf = BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as f:
            f.write(value.encode("utf-8"))
        return buf.getvalue().decode("latin1")
    else:
        return value


def setup_tampering(context, tamper_configs, debug):
    """Setup request interception to tamper only when parameter exists and value differs"""

    def master_handler(route, request):
        matched = False
        parsed_request = urllib.parse.urlparse(request.url)

        for config in tamper_configs:
            parsed_pattern = urllib.parse.urlparse(config["url_pattern"])
            param_loc = config.get("param_location")
            param_name = config.get("param_name")
            new_value = str(config.get("param_value"))
            body_method = config.get("body_method", "")
            overrides = {}

            # Match scheme, netloc, and method
            if (
                request.method != config["method"]
                or parsed_request.scheme != parsed_pattern.scheme
                or parsed_request.netloc != parsed_pattern.netloc
            ):
                continue

            # Handle different parameter locations with appropriate matching
            if param_loc in ["body", "headers", "query"]:
                if parsed_request.path != parsed_pattern.path:
                    continue

            # Proceed with tampering based on location
            if param_loc == "body":
                body = request.post_data or ""
                parsed_body = urllib.parse.parse_qs(body) if body else {}
                request_body_method = parsed_body.get("Method", [""])[0]
                if body_method and request_body_method != body_method:
                    debugLog(
                        f"[DEBUG]: Body method {request_body_method} does not match {body_method}, skipping: {request.url}",
                        debug,
                    )
                    continue

                content_type = request.headers.get("content-type", "").lower()
                if "application/x-www-form-urlencoded" in content_type:
                    if param_name in parsed_body:
                        current_value = parsed_body[param_name][0]
                        if current_value != new_value:
                            print(
                                f"{bcolors.OKGREEN}[TAMPERING]: Matched config for: {request.url} (Method: {request_body_method}){bcolors.ENDC}"
                            )
                            print(
                                f"{bcolors.WARNING}  Original body: {body}{bcolors.ENDC}"
                            )
                            parsed_body[param_name] = [new_value]
                            body = urllib.parse.urlencode(parsed_body, doseq=True)
                            overrides["post_data"] = body
                            print(
                                f"{bcolors.WARNING}  Modified body: {body}{bcolors.ENDC}"
                            )
                            route.continue_(**overrides)
                            matched = True
                        else:
                            debugLog(
                                f"[DEBUG]: Parameter {param_name} value matches, skipping: {request.url}",
                                debug,
                            )
                    else:
                        for key, values in parsed_body.items():
                            for j, value in enumerate(values):
                                decoded_value, encoding = decode_value(value)
                                if (
                                    isinstance(decoded_value, dict)
                                    and param_name in decoded_value
                                ):
                                    current_value = str(decoded_value[param_name])
                                    if current_value != new_value:
                                        print(
                                            f"{bcolors.OKGREEN}[TAMPERING]: Matched config for: {request.url} (Method: {request_body_method}){bcolors.ENDC}"
                                        )
                                        print(
                                            f"{bcolors.WARNING}  Original body: {body}{bcolors.ENDC}"
                                        )
                                        decoded_value[param_name] = new_value
                                        modified_value = encode_value(
                                            decoded_value, encoding
                                        )
                                        parsed_body[key][j] = modified_value
                                        body = urllib.parse.urlencode(
                                            parsed_body, doseq=True
                                        )
                                        overrides["post_data"] = body
                                        print(
                                            f"{bcolors.WARNING}  Modified body: {body}{bcolors.ENDC}"
                                        )
                                        route.continue_(**overrides)
                                        matched = True
                                        break
                        if not matched:
                            debugLog(
                                f"[DEBUG]: Parameter {param_name} not found in any nested structure, skipping: {request.url}",
                                debug,
                            )
                elif "application/json" in content_type:
                    try:
                        data = json.loads(body)
                        if param_name in data:
                            current_value = str(data[param_name])
                            if current_value != new_value:
                                print(
                                    f"{bcolors.OKGREEN}[TAMPERING]: Matched config for: {request.url} (Method: {request_body_method}{bcolors.ENDC})"
                                )
                                print(
                                    f"{bcolors.WARNING}  Original body: {body}{bcolors.ENDC}"
                                )
                                data[param_name] = new_value
                                body = json.dumps(data)
                                overrides["post_data"] = body
                                print(
                                    f"{bcolors.WARNING}  Modified body: {body}{bcolors.ENDC}"
                                )
                                route.continue_(**overrides)
                                matched = True
                            else:
                                debugLog(
                                    f"[DEBUG]: Parameter {param_name} value matches, skipping: {request.url}",
                                    debug,
                                )
                        else:
                            debugLog(
                                f"[DEBUG]: Parameter {param_name} not found in JSON body, skipping: {request.url}",
                                debug,
                            )
                    except json.JSONDecodeError:
                        print(f"[ERROR]: Failed to parse JSON body for: {request.url}")
                else:
                    print(
                        f"[ERROR]: Unsupported content type '{content_type}' for body tampering, skipping: {request.url}"
                    )

            elif param_loc == "headers":
                if param_name in request.headers:
                    current_value = request.headers[param_name]
                    if current_value != new_value:
                        print(
                            f"{bcolors.OKGREEN}[TAMPERING]: Matched config for: {request.url}{bcolors.ENDC}"
                        )
                        print(
                            f"{bcolors.WARNING}  Original header {param_name}: {current_value}{bcolors.ENDC}"
                        )
                        headers = {**request.headers}
                        headers[param_name] = new_value
                        overrides["headers"] = headers
                        print(
                            f"{bcolors.WARNING}  Modified header {param_name}: {new_value}{bcolors.ENDC}"
                        )
                        route.continue_(**overrides)
                        matched = True
                    else:
                        debugLog(
                            f"[DEBUG]: Header {param_name} value matches, skipping: {request.url}",
                            debug,
                        )
                else:
                    debugLog(
                        f"[DEBUG]: Header {param_name} not found, skipping: {request.url}",
                        debug,
                    )

            elif param_loc == "query":
                query_dict = urllib.parse.parse_qs(parsed_request.query)
                if param_name in query_dict:
                    current_value = query_dict[param_name][0]
                    if current_value != new_value:
                        print(
                            f"{bcolors.OKGREEN}[TAMPERING]: Matched config for: {request.url}{bcolors.ENDC}"
                        )
                        print(
                            f"{bcolors.WARNING}  Original query: {parsed_request.query}{bcolors.ENDC}"
                        )
                        query_dict[param_name] = [new_value]
                        new_query = urllib.parse.urlencode(query_dict, doseq=True)
                        new_url = urllib.parse.urlunparse(
                            (
                                parsed_request.scheme,
                                parsed_request.netloc,
                                parsed_request.path,
                                parsed_request.params,
                                new_query,
                                parsed_request.fragment,
                            )
                        )
                        overrides["url"] = new_url
                        print(
                            f"{bcolors.WARNING}  Modified query: {new_query}{bcolors.ENDC}"
                        )
                        route.continue_(**overrides)
                        matched = True
                    else:
                        debugLog(
                            f"[DEBUG]: Query parameter {param_name} value matches, skipping: {request.url}",
                            debug,
                        )
                else:
                    debugLog(
                        f"[DEBUG]: Query parameter {param_name} not found, skipping: {request.url}",
                        debug,
                    )

            elif param_loc == "url_path":
                # Normalize paths by removing trailing slashes
                pattern_path = parsed_pattern.path.rstrip("/")
                request_path = parsed_request.path.rstrip("/")

                # Split into segments
                pattern_segments = pattern_path.split("/")
                request_segments = request_path.split("/")

                # Find the position of the parameter in the pattern
                param_position = int(param_name)
                try:
                    param_val = pattern_segments[param_position]
                except ValueError:
                    debugLog(
                        f"[DEBUG]: Parameter position {param_name} not found in pattern path",
                        debug,
                    )
                    continue

                # Verify base path matches
                if (
                    pattern_segments[:param_position]
                    != request_segments[:param_position]
                ):
                    debugLog(f"[DEBUG]: Base path mismatch for {request.url}", debug)
                    continue

                # Check if request has enough segments
                if len(request_segments) <= param_position:
                    debugLog(f"[DEBUG]: Not enough segments in {request.url}", debug)
                    continue

                current_value = request_segments[param_position]
                if current_value != new_value:
                    # Replace only the target segment
                    request_segments[param_position] = new_value
                    new_path = "/".join(request_segments)

                    # Preserve trailing slash if original had it
                    if parsed_request.path.endswith("/"):
                        new_path += "/"

                    new_url = urllib.parse.urlunparse(
                        (
                            parsed_request.scheme,
                            parsed_request.netloc,
                            new_path,
                            parsed_request.params,
                            parsed_request.query,
                            parsed_request.fragment,
                        )
                    )
                    print(
                        f"{bcolors.OKGREEN}[TAMPERING]: Changed URL from {request.url} to {new_url}{bcolors.OKGREEN}"
                    )
                    overrides["url"] = new_url
                    route.continue_(**overrides)
                    matched = True
                else:
                    debugLog(
                        f"[DEBUG]: Path parameter value matches, skipping: {request.url}",
                        debug,
                    )
            else:
                debugLog(
                    f"[DEBUG]: Path segment count mismatch for {request.url}", debug
                )

        if not matched:
            debugLog(f"[DEBUG]: Passing through: {request.method} {request.url}", debug)
            route.continue_()

    context.route("**/*", master_handler)


def post_process(path):
    """Process recorded script to make it compatible with our replay system"""
    source = path.read_text(encoding="utf-8")
    action_lines = []
    for line in source.splitlines():
        if (
            line.startswith("import ")
            or line.startswith("from ")
            or line.startswith("def ")
            or line.startswith("@")
        ):
            continue
        if (
            "playwright" in line
            or "browser" in line
            or "context" in line
            or "run(" in line
            or "close()" in line
        ):
            continue
        if "page." in line or "expect(" in line:
            if not line.startswith("    "):
                line = "    " + line
            action_lines.append(line)

    new_source = [
        "from playwright.sync_api import Page\n\n",
        "def run_actions(page: Page):\n",
    ]
    new_source.extend(action_lines)
    new_source.extend(PAUSE_SNIPPET)
    path.write_text("\n".join(new_source), encoding="utf-8")


def load_actions_module(actions_file):
    """Dynamically load a Python module from a file path"""
    path = Path(actions_file)
    module_name = path.stem
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None:
        raise ImportError(f"Could not load module from {actions_file}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replay_actions_with_tamper(actions_file, tamper_configs, debug):
    actions_file_path = Path(actions_file)
    post_process(actions_file_path)
    module = load_actions_module(actions_file_path)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=False)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        for config in tamper_configs:
            if "modified_request_example" in config:
                body_data = urllib.parse.parse_qs(
                    config["modified_request_example"].get("body_data", "")
                )
                config["body_method"] = body_data.get("Method", [""])[0]

        if tamper_configs:
            setup_tampering(context, tamper_configs, debug)

            try:
                if hasattr(module, "run_actions"):
                    module.run_actions(page)
                else:
                    raise RuntimeError(
                        "No run_actions function found in actions script"
                    )

            except Exception as e:
                print(f"{bcolors.FAIL}[ERROR] Replay failed: {e}{bcolors.ENDC}")
                print(
                    f"{bcolors.BOLD}{bcolors.WARNING}Please consider recording again the actions if the error persists.{bcolors.ENDC}"
                )

        context.close()
        browser.close()
