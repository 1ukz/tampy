import importlib
import json
from pathlib import Path
import sys
import urllib.parse
import base64
import zlib
import gzip
from io import BytesIO
from playwright.sync_api import sync_playwright, TimeoutError
from resources.bcolors import bcolors

# --- Tampering Script ---

PAUSE_SNIPPET = [
    "    # ---------------------\n",
    "    from resources.bcolors import bcolors \n",
    "    print(f'{bcolors.BOLD}{bcolors.OKGREEN} [SUCCESS]: All packets replayed! Evaluate the results. {bcolors.ENDC}')\n",
    "    print(f'{bcolors.BOLD}{bcolors.WARNING} Press <ENTER> to close browser. {bcolors.ENDC}')\n",
    "    input()\n",
]


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


def setup_tampering(context, tamper_configs):
    """Setup request interception to tamper only when parameter exists and value differs"""
    print(
        f"{bcolors.OKBLUE}[DEBUG] Setting up tampering for {len(tamper_configs)} configs{bcolors.ENDC}"
    )
    sys.stdout.flush()

    def master_handler(route, request):
        matched = False
        for _, config in enumerate(tamper_configs):
            if (
                request.url == config["url_pattern"]
                and request.method == config["method"]
            ):
                param_loc = config.get("param_location")
                param_name = config.get("param_name")
                new_value = str(config.get("param_value"))
                body_method = config.get("body_method", "")
                overrides = {}

                body = request.post_data or ""
                parsed_body = urllib.parse.parse_qs(body) if body else {}
                request_body_method = parsed_body.get("Method", [""])[0]
                if body_method and request_body_method != body_method:
                    print(
                        f"{bcolors.OKBLUE}[DEBUG] Body method {request_body_method} does not match {body_method}, skipping: {request.url}{bcolors.ENDC}"
                    )
                    continue

                if param_loc == "body":
                    content_type = request.headers.get("content-type", "").lower()
                    if "application/x-www-form-urlencoded" in content_type:
                        if param_name in parsed_body:
                            current_value = parsed_body[param_name][0]
                            if current_value != new_value:
                                print(
                                    f"{bcolors.OKGREEN}[TAMPERING] Matched config for: {request.url} (Method: {request_body_method}){bcolors.ENDC}"
                                )
                                print(f"  Original body: {body}")
                                parsed_body[param_name] = [new_value]
                                body = urllib.parse.urlencode(parsed_body, doseq=True)
                                overrides["post_data"] = body
                                print(f"  Modified body: {body}")
                                route.continue_(**overrides)
                                matched = True
                            else:
                                print(
                                    f"{bcolors.OKBLUE}[DEBUG] Parameter {param_name} value matches, skipping: {request.url}{bcolors.ENDC}"
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
                                                f"{bcolors.OKGREEN}[TAMPERING] Matched config for: {request.url} (Method: {request_body_method}){bcolors.ENDC}"
                                            )
                                            print(f"  Original body: {body}")
                                            decoded_value[param_name] = new_value
                                            modified_value = encode_value(
                                                decoded_value, encoding
                                            )
                                            parsed_body[key][j] = modified_value
                                            body = urllib.parse.urlencode(
                                                parsed_body, doseq=True
                                            )
                                            overrides["post_data"] = body
                                            print(f"  Modified body: {body}")
                                            route.continue_(**overrides)
                                            matched = True
                                            break
                            if not matched:
                                print(
                                    f"{bcolors.OKBLUE}[DEBUG] Parameter {param_name} not found in any nested structure, skipping: {request.url}{bcolors.ENDC}"
                                )
                    elif "application/json" in content_type:
                        try:
                            data = json.loads(body)
                            if param_name in data:
                                current_value = str(data[param_name])
                                if current_value != new_value:
                                    print(
                                        f"{bcolors.OKGREEN}[TAMPERING] Matched config for: {request.url} (Method: {request_body_method}){bcolors.ENDC}"
                                    )
                                    print(f"  Original body: {body}")
                                    data[param_name] = new_value
                                    body = json.dumps(data)
                                    overrides["post_data"] = body
                                    print(f"  Modified body: {body}")
                                    route.continue_(**overrides)
                                    matched = True
                                else:
                                    print(
                                        f"{bcolors.OKBLUE}[DEBUG] Parameter {param_name} value matches, skipping: {request.url}{bcolors.ENDC}"
                                    )
                            else:
                                print(
                                    f"{bcolors.OKBLUE}[DEBUG] Parameter {param_name} not found in JSON body, skipping: {request.url}{bcolors.ENDC}"
                                )
                        except json.JSONDecodeError:
                            print(
                                f"{bcolors.FAIL}[ERROR] Failed to parse JSON body for: {request.url}{bcolors.ENDC}"
                            )
                    else:
                        print(
                            f"{bcolors.WARNING}[WARNING] Unsupported content type '{content_type}' for body tampering, skipping: {request.url}{bcolors.ENDC}"
                        )

                elif param_loc == "headers":
                    if param_name in request.headers:
                        current_value = request.headers[param_name]
                        if current_value != new_value:
                            print(
                                f"{bcolors.OKGREEN}[TAMPERING] Matched config for: {request.url}{bcolors.ENDC}"
                            )
                            print(f"  Original header {param_name}: {current_value}")
                            headers = {**request.headers}
                            headers[param_name] = new_value
                            overrides["headers"] = headers
                            print(f"  Modified header {param_name}: {new_value}")
                            route.continue_(**overrides)
                            matched = True
                        else:
                            print(
                                f"{bcolors.OKBLUE}[DEBUG] Header {param_name} value matches, skipping: {request.url}{bcolors.ENDC}"
                            )
                    else:
                        print(
                            f"{bcolors.OKBLUE}[DEBUG] Header {param_name} not found, skipping: {request.url}{bcolors.ENDC}"
                        )

                elif param_loc == "query":
                    parsed_url = urllib.parse.urlparse(request.url)
                    query_dict = urllib.parse.parse_qs(parsed_url.query)
                    if param_name in query_dict:
                        current_value = query_dict[param_name][0]
                        if current_value != new_value:
                            print(
                                f"{bcolors.OKGREEN}[TAMPERING] Matched config for: {request.url}{bcolors.ENDC}"
                            )
                            print(f"  Original query: {parsed_url.query}")
                            query_dict[param_name] = [new_value]
                            new_query = urllib.parse.urlencode(query_dict, doseq=True)
                            new_url = urllib.parse.urlunparse(
                                (
                                    parsed_url.scheme,
                                    parsed_url.netloc,
                                    parsed_url.path,
                                    parsed_url.params,
                                    new_query,
                                    parsed_url.fragment,
                                )
                            )
                            overrides["url"] = new_url
                            print(f"  Modified query: {new_query}")
                            route.continue_(**overrides)
                            matched = True
                        else:
                            print(
                                f"{bcolors.OKBLUE}[DEBUG] Query parameter {param_name} value matches, skipping: {request.url}{bcolors.ENDC}"
                            )
                    else:
                        print(
                            f"{bcolors.OKBLUE}[DEBUG] Query parameter {param_name} not found, skipping: {request.url}{bcolors.ENDC}"
                        )

                elif param_loc == "url_path":
                    print(
                        f"{bcolors.WARNING}[WARNING] url_path tampering not supported yet, skipping: {request.url}{bcolors.ENDC}"
                    )

        if not matched:
            print(
                f"{bcolors.OKBLUE}[DEBUG] Passing through: {request.method} {request.url}{bcolors.ENDC}"
            )
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


def replay_actions_with_tamper(actions_file, tamper_configs):
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
            setup_tampering(context, tamper_configs)

            try:
                if hasattr(module, "run_actions"):
                    module.run_actions(page)
                else:
                    raise RuntimeError(
                        "No run_actions function found in actions script"
                    )

            except Exception as e:
                print(f"{bcolors.FAIL}[ERROR] Replay failed: {e}{bcolors.ENDC}")

        context.close()
        browser.close()
