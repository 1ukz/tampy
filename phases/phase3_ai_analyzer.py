import os
import json
from openai import OpenAI
from resources.bcolors import bcolors


def print_ai_answer(result):
    for item in result:
        print(
            f"\n{bcolors.UNDERLINE}{bcolors.BOLD}{bcolors.OKBLUE}Control:{bcolors.ENDC} {item['control_id']}"
        )
        print(f"{bcolors.WARNING} [Packet index]: {bcolors.ENDC}{item['packet_index']}")
        print(
            f"\n{bcolors.WARNING} [Vuln. description]: {bcolors.ENDC}{item['vulnerability_description']}"
        )
        print(
            f"{bcolors.WARNING} [Exploitation hypothesis]: {bcolors.ENDC}{item['exploitation_hypothesis']}"
        )
        print(f"{bcolors.WARNING} [Parameter]: {bcolors.ENDC}{item['parameter_name']}")
        print(
            f"{bcolors.WARNING} [Parameter location]: {bcolors.ENDC}{item['parameter_location']}"
        )
        print(
            f"{bcolors.WARNING} [Test payload]: {bcolors.ENDC}{item['test_payload']}\n"
        )
        print(f"{bcolors.WARNING} Modified request example:{bcolors.ENDC}")
        print(json.dumps(item["modified_request_example"], indent=2))
        print("=" * 100 + "\n")


def analyze_packets_with_ai(har_filename, mode, streaming, show_think, spinner):
    """
    Fase 3: carga el JSON de paquetes, construye un prompt que cubre los controles
    y envía a DeepSeek y muestra el análisis.
    """
    # 1. Carga los paquetes ya filtrados y guardados
    try:
        with open(har_filename, encoding="utf-8") as f:
            packets = json.load(f)
    except FileNotFoundError:
        print(
            f"{bcolors.FAIL}[ERROR]: : Packets file could not be found: {har_filename}{bcolors.ENDC}"
        )
        return

    # 2. Configura las credenciales de la API según el modo
    if mode == "remote":
        api_key = os.getenv("REMOTE_API_KEY")
        base_url = os.getenv("REMOTE_BASE_URL")
        model = os.getenv("REMOTE_MODEL_NAME")

        if not api_key or not base_url or not model:
            print(
                f"{bcolors.FAIL}[ERROR]: : Remote AI API configuration is not set correctly. Please check your environment variables.{bcolors.ENDC}"
            )
            return
    else:
        api_key = "not-needed"  # no se usa en local
        base_url = os.getenv("LOCAL_BASE_URL")
        model = os.getenv("LOCAL_MODEL_NAME")

        if not base_url or not model:
            print(
                f"{bcolors.FAIL}[ERROR]: : Local LLM configurations is not set correctly. Please check your environment variables.{bcolors.ENDC}"
            )
            return

    # 3. Prepara el prompt del sistema (contexto de auditor)
    system_prompt = (
        "You are an expert e-commerce security auditor and a professional vulnerability researcher with deep knowledge in business logic flaws. You are technical, creative, and have an outstanding eye for possible inconsistencies that could be exploited.\n"
        "Your task is to profoundly analyze the provided sequence of HTTP requests, which represents an e-commerce purchase flow. Your goal is to identify every potential security weakness, from common vulnerabilities to advanced business logic flaws.\n"
        "Your analysis will be a critical component of a professional penetration testing report. Therefore, your findings must be technical, precise, and directly actionable.\n\n"
        "Analyze the purchase flow according to the following comprehensive controls, do not miss any one of them in your analysis:\n"
        "1.  Control 1.1 — Insecure Direct Object References (IDOR): Inspect all user-supplied identifiers in URL paths, query parameters, headers, and the request body. Look for predictable or easily guessable IDs (e.g., 'cart_id', 'order_id', 'user_id', 'profile_id', 'address_id'). Propose tests that attempt to access resources that should not be allowed (e.g. belonging to other users).\n\n"
        "2.  Control 1.2 — Weak session & Cookie management: Inspect cookies and session tokens for security best practices. Check for missing 'HttpOnly', 'Secure', and 'SameSite=Strict' flags. Analyze the predictability and entropy of token values. Identify any session-related data that, if manipulated, could alter the application's state or user identity.\n\n"
        "3.  Control 1.3 — State management & Race conditions: Analyze the logical sequence of the purchase flow. Identify opportunities to bypass, repeat, or perform steps out of order (e.g., jumping from cart to payment confirmation, re-using a completed order session). Consider the potential for race conditions in operations like applying a coupon or inventory holds (e.g., parallel requests to use the same discount code).\n\n"
        "4.  Control 1.4 — Critical parameter tampering: Meticulously examine all parameters that influence the final price and order details. This includes, but is not limited to, 'price', 'quantity', 'discount', 'currency', 'shipping_cost', and product/variant IDs. Propose tests with classic manipulations (e.g., negative quantities, price set to lower values) and more subtle attacks like parameter pollution or data type fuzzing.\n\n"
        "5.  Control 1.5 — Weak obfuscation & hashing: Identify and decode any non-standard encoding or obfuscation techniques applied to parameters (e.g., Base64, URL encoding, gzip/deflate, checksums, hex, simple substitution ciphers, weak hashing algorithms like MD5 or SHA1 used for integrity checks). Your analysis should focus on what sensitive data or logic is being hidden and how it can be manipulated post-decoding.\n\n"
        "6.  Control 1.6 — Sensitive data exposure: Scan all parts of the requests for the insecure transmission of sensitive information. This includes Personally Identifiable Information (PII), financial data (full or partial credit card numbers, CVVs), authentication credentials, or API keys in cleartext.\n\n"
        "7.  Control 1.7 — Business logic flaws & abuse: Think beyond technical vulnerabilities and focus on how the e-commerce logic itself can be abused. Examples include: applying multiple exclusive discounts, manipulating loyalty point calculations, circumventing purchase limits, or exploiting shipping and tax calculation logic.\n\n"
        "Crucial Instructions:\n"
        "-   Anti-duplication: If a vulnerability could fit under multiple controls, assign it only ONCE to the MOST SPECIFIC control that best describes the root cause.\n"
        "-   No repeated vulnerabilities: Do not report the same vulnerability multiple times, even if it appears in different requests. Each unique possible vulnerability should be reported only once.\n"
        "-   Be proactive: Just because a parameter looks encrypted it does not mean it is secure. Suggest tests to validate the strength of the protection.\n\n"
        "-   No assumptions: Do not assume that every potential vulnerability found is actually vulnerable. You should articulate your words in a manner that explains the possible vulnerability, but do not assume it. Only assume it if it is clearly vulnerable from the packet provided and no more analysis or action is required.\n\n"
        "-   Parameter specificity: For parameters in nested structures (e.g., 'quantity' in a JSON object/key like 'data'), specify the exact field name (e.g., 'quantity') as 'parameter_name', not the container ('data'). The parameter_name should be exactly the one that appears, do not make it up. The 'test_payload' must be the value for that field (e.g., '-1').\n"
        "-   Modified request: In 'modified_request_example', change only the specific parameter value. For nested JSON in form data (e.g., 'application/x-www-form-urlencoded') or JSON bodies, update only the targeted field, preserving other fields. Ensure the body format matches the original content type.\n"
        "-   Content type handling: Support all common content types (e.g., 'application/json', 'application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain').\n"
        "-   Parameter locations: Handle 'url_path', 'query', 'headers', and 'body' consistently. For 'url_path', identify dynamic segments (e.g., '/resource/{id}') and return in the parameter_name the 0 index position of the segment (e.g., /user/{id}/cart, this should be parameter_name:'2', as '','user','id','cart').\n\n"
        "For each identified potential vulnerability, generate exactly ONE JSON object with the following fields. You must ensure each JSON object references one particular and specific parameter/value to test:\n"
        "   -   'control_id': (String) The corresponding control ID (e.g., \"2.1.4\").\n"
        "   -   'packet_index': (Integer) The 0-based index of the vulnerable request in the input array.\n"
        "   -   'parameter_name': (String) The specific name of the vulnerable parameter. This means that if it is a variable inside the body data, you should display that particular variable name/parameter. If it is a variable inside url_path, display the parameter index position instead (as explained before).\n"
        "   -   'parameter_location': (String) The location of the parameter: 'url_path', 'query', 'headers', or 'body'.\n"
        "   -   'vulnerability_description': (String) A concise, technical explanation of the potential weakness.\n"
        "   -   'exploitation_hypothesis': (String) A clear and direct statement about what an attacker could achieve (e.g., 'Change the price of an item to another value', 'View the order history of another user').\n"
        "   -   'test_payload': (String) The specific value to use in the test (e.g., '0.01', '-1', 'another_user_id').\n"
        "   -    'modified_request_example': (JSON Object) Full HTTP request with these fields:\n"
        "        * 'url': (String) Full URL\n"
        "        * 'method': (String) HTTP method\n"
        "        * 'headers': (Object) Key-value pairs of headers\n"
        "        * 'body_data': (String) Request body if applicable\n"
        "Crucial instructions for the modified request:\n"
        "- When providing 'modified_request_example', ONLY change the specific parameter being tested, and it should always be ONLY one.\n"
        "- Preserve ALL other headers and body content exactly as in the original request\n"
        "- If the modified data is in the body parameters, provide ONLY the changed parameter value, not the entire body\n"
        "- If the modified data is in the header parameters, provide ONLY the changed header value\n"
        "- If the modified data is an encoded value such as base64 or deflate, ensure that what you have modified and encoded is correct (no extra or added bad characters) and follows the original data stucture\n"
        "- If the identified potential vulnerability is just informational and non exploitable, such as the Control 1.6, also create a JSON object informing it and displaying the vulnerable packet (but without modifications)."
        "Your final and only output must be a single, well-formed JSON array of these objects, and nothing else. Do not include any introductory text or explanations outside of the JSON structure, nor formatting style/markdown. Only a JSON object with the array of objects as described above.\n"
        "In case of no vulnerabilities found, return an empty JSON array: []\n"
    )

    # 3. User prompt con el array JSON
    user_prompt = (
        f"I captured {len(packets)} requests:\n"
        + json.dumps(
            packets, separators=(",", ":")
        )  # compactar el JSON sin espacios despyes de comas y dos puntos
    )

    client = OpenAI(api_key=api_key, base_url=base_url)
    client._client_timeout = 1200.0  # aumentar timeout a 20 minutos para evitar timeouts en respuestas largas

    raw_output = ""
    raw_reasoning_content = ""
    result = []
    try:
        if not streaming:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
            )

            raw_reasoning_content = resp.choices[0].message.reasoning_content
            raw_output = resp.choices[0].message.content

            if show_think:
                spinner.stop()
                print(raw_reasoning_content)

        else:
            first_token = True
            stream_resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                stream=True,
            )

            for chunk in stream_resp:
                delta = chunk.choices[0].delta

                # 1) Chain-of-thought chunk?
                if hasattr(delta, "reasoning_content") and delta.reasoning_content:
                    raw_reasoning_content += delta.reasoning_content
                    if show_think:
                        if first_token:
                            spinner.stop()
                            first_token = False
                        # print reasoning as it comes
                        print(
                            delta.reasoning_content, end="", flush=True
                        )  # end="" para no hacer salto de linea y fluush para forzar salida inmediata sin almacenar en buffer

                # 2) Final answer chunk?
                if hasattr(delta, "content") and delta.content:
                    raw_output += delta.content
                    if first_token:
                        spinner.stop()
                        first_token = False
                    print(delta.content, end="", flush=True)

            print()  # newline after stream

    except Exception as e:
        spinner.stop()
        print(f"\n{bcolors.FAIL}[ERROR]: Error during LLM analysis: {e}{bcolors.ENDC}")
        return None, None

    last_raw_response = raw_output

    if not last_raw_response:
        spinner.stop()
        print(
            f"{bcolors.FAIL}[ERROR]: No response received or correctly saved from AI model.{bcolors.ENDC}"
        )
        return None, None

    try:
        result = json.loads(last_raw_response)
    except json.JSONDecodeError:
        spinner.stop()
        return last_raw_response, None

    if not streaming and not show_think:
        spinner.stop()
    return last_raw_response, result
