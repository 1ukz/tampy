import os
import json
from openai import OpenAI  # cliente OpenAI utilizado también para DeepSeek
from resources.bcolors import bcolors


def print_ai_answer(result):
    for item in result:
        print(f"{bcolors.UNDERLINE}Control:{bcolors.ENDC} {item['control_id']}")
        print(f" Packet index: {item['packet_index']}")
        print(f" Parameter: {item['parameter']}")
        print(f" Test: {item['test']}")
        print(" Modified request example:")
        print(json.dumps(item["modified_request_example"], indent=2))
        print("-" * 60)


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
        "You are a senior e-commerce security auditor and vulnerability researcher.\n"
        "Your task is to analyze the following HTTP requests and identify every possible security weakness in the purchase flow and business logic.\n"
        "Be exhaustive and technical—your findings will be inserted directly into a professional security report.\n"
        "Analyze according to these OWASP-style controls:\n"
        "1. Control 2.1.1 — IDOR: insecure direct object references in parameters, for example *_id, object_id, user_id.\n"
        "2. Control 2.1.2 — Weak session & cookie management: missing HttpOnly/Secure flags, predictable or manipulable values for session tokens/cookies.\n"
        "3. Control 2.1.3 — Race conditions & state management: parallel or out-of-order steps (e.g., skipping stages, session reuse by modifying certain values/variables/parameters).\n"
        "4. Control 2.1.4 — Critical parameter tampering: price, quantity, currency, IDs, etc. For example, changing the quantity to a negative value or modifying the price to a lower value might affect the total to pay. Keep in mind that these parameters might not be in clear-text but weakly-obfuscated (base64, deflate, etc.).\n"
        "5. Control 2.1.5 — Obfuscation & weak hashes: base64, deflate, simple hashes—decode and inspect contents.\n"
        "6. Control 2.1.6 — Sensitive data exposure: credit-card fields, PII or other secrets sent in cleartext.\n\n"
        "Do NOT repeat the same issue under multiple controls; if it fits more than one, assign it to the single most relevant control.\n\n"
        "For each vulnerable request, output exactly one entry (in English) with these fields:\n"
        '  • control_id  (e.g. "2.1.4")\n'
        "  • packet_index (0-based index in the input array)\n"
        "  • parameter (name and location: URL/query, headers, or body)\n"
        '  • test (what value to change and why—e.g. change price to "0.01", swap user_id, change quantity to -1). Only ONE change per request.\n'
        "  • modified_request_example (the full HTTP request in JSON with your test values applied)\n\n"
        "The only answer you need to finally return is a single JSON array of these objects, nothing else."
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
        print(
            f"{bcolors.FAIL}[ERROR]: Error parsing JSON from AI response{bcolors.ENDC}"
        )
        return last_raw_response, None

    if not streaming and not show_think:
        spinner.stop()
    return last_raw_response, result
