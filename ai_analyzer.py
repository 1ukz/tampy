import os
import json
from openai import OpenAI   # cliente OpenAI utilizado también para DeepSeek
from resources.bcolors import bcolors



def analyze_packets_with_ai(har_filename, mode, streaming):
    """
    Fase 3: carga el JSON de paquetes, construye un prompt que cubre los controles
    y envía a DeepSeek y muestra el análisis.
    """
    # 1. Carga los paquetes ya filtrados y guardados
    try:
        with open(har_filename, encoding="utf-8") as f:
            packets = json.load(f)
    except FileNotFoundError:
        print(f"{bcolors.FAIL}ERROR: Packets file could not be found: {har_filename}{bcolors.ENDC}")
        return
    
    # 2. Configura las credenciales de la API según el modo
    if mode == 'remote':
        api_key    = os.getenv("REMOTE_API_KEY")
        base_url   = os.getenv("REMOTE_BASE_URL")
        model = os.getenv("REMOTE_MODEL_NAME")
    else:
        api_key    = "not-needed"  # no se usa en local
        base_url   = os.getenv("LOCAL_BASE_URL")
        model = os.getenv("LOCAL_MODEL_NAME")

    if mode == 'remote' and (not api_key or not base_url or not model):
        print(f"{bcolors.FAIL}ERROR: Remote AI API configuration is not set correctly. Please check your environment variables.{bcolors.ENDC}")
        return
    if mode == 'local' and (not base_url or not model):
        print(f"{bcolors.FAIL}ERROR: Local LLM configurations is not set correctly. Please check your environment variables.{bcolors.ENDC}")
        return
    
    # 3. Prepara el prompt del sistema (contexto de auditor)
    system_prompt = (
        "Eres un auditor de ciberseguridad experto en páginas web de e-commerce y programación. Analiza estas peticiones HTTP y detecta vectores de vulnerabilidad en el proceso de compra o la lógica de compra. El ánalisis debe ser muy exhaustivo en busca de cada detalle ya que tu ánalisis formara parte de un reporte profesional de seguridad.\n"
        "No repitas la información que has dado en un control para otro. Si hay algo que puede encajar con más de un control, solo muestralo en uno. \n" 
        "Basate en estos controles:\n"
        "• 2.1.1 IDOR: parámetros como '*_id', 'object_id', 'user_id' que permiten a los atacantes cambiar el valor de un parámetro para apuntar, cambiar y/o acceder a un objeto, apartado o componente que no deberían poder. Entre otras cosas, esta vulnerabilidad hace que un atacante pueda eludir y saltar posibles reglas de autorización necesarias, o apuntar a otros objetos y cambiar valores.\n"
        "• 2.1.2 Cookies: cadenas cifradas debilmente, predecibles, modificables, ... etc. \n"
        "• 2.1.3 Race conditions y gestiones de estado: pasos de compra paralelos. Aquí es bueno buscar posibles variables de pasos de compra (stages, steps, etc), o ver si cambiar ciertos parametros afecta a la gestión de compra.  \n"
        "• 2.1.4 Parámetros/variables críticas: precios, cantidades, moneda, etc. Este tipo de vulnerabilidad hace referencia a la manipulación y modificación del contenido de parámetros y variables específicas enviados entre el cliente y el servidor y ver si afecta a la lógica o producto final de la compra como el precio a pagar. Hay que tener en cuenta no solo parametros o variables en texto en claro, sino también que estén cifrados debilmente como inflates/deflates, base64, etc. Los precios siempre deben cambiarse a menos para ver si afecta al total a pagar, y la cantidad a números negativos a ver si resta del total también (entre otras pruebas de seguridad que puedan prepararse).\n"
        "• 2.1.5 Ofuscación/Hash: base64, deflate, hashes débiles. Todo aquello que encuentres que posiblemente pueda ser descifrable (como un deflate o un base64), no solo lo destaques sino descifralo también.\n"
        "• 2.1.6 Información sensible siendo enviada como tarjetas de crédito siendo expuestas en texto claro, u otra información que no debería ser visible.\n"
        "Por cada petición que hayas encontrado posiblemente vulnerable bajo cada control, devuelve en idioma inglés siempre:\n"
        "- índice (0-based)\n"
        "- parámetro(s) sospechosos o inseguros\n"
        "- parámetro(s) a modificar y tipo de prueba explotación sugerida (e.g. cambiar precio, cambiar ID, forzar cookie)\n"
        "- la petición http pero modificada (por ejemplo, si aparece el precio, pues con un valor de precio diferente) para hacer una prueba relanzando esa petición modificada (petición http en formato JSON, tal como se te ha sido dada). \n"
        "El formato de tu respuesta debe ser siempre un array JSON con objetos que contengan los campos: 'control_id', y dentro (por cada paquete) 'packet_index', 'parameter', 'test', 'modified_request_example' (y dentro de este último la petición modificada completa).\n"
    )

    # 3. User prompt con el array JSON
    user_prompt = (
        f"He capturado {len(packets)} peticiones en '{har_filename}':\n\n"
        + json.dumps(packets, separators=(',',':')) # compactar el JSON sin espacios despyes de comas y dos puntos
    )

    client = OpenAI(
        api_key=api_key,
        base_url=base_url 
    )
    client._client_timeout = 1200.0 # aumentar timeout a 20 minutos para evitar timeouts en respuestas largas

    raw_output = ""
    result = []
    try:
        if not streaming:
            print(f"{bcolors.OKBLUE}Analyzing packets (non-streaming {mode} mode)... Please be patient.{bcolors.ENDC}")
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt}
                ],
                temperature=0.2
            )
            
            raw_output = resp.choices[0].message.content

        else:
            print(f"{bcolors.OKBLUE}Analyzing packets (streaming {mode} mode)... Please be patient.{bcolors.ENDC}")
            for chunk in client.chat.completions.create(
                model=model,
                messages=[
                    {"role":"system","content":system_prompt},
                    {"role":"user",  "content":user_prompt}
                ],
                temperature=0.2,
                stream=True,
            ):
                delta = chunk.choices[0].delta.content or ""
                raw_output += delta
                print(delta, end="", flush=True)
            
            print() # Nueva línea al finalizar el streaming
    except Exception as e:
        print(f"\n{bcolors.FAIL}ERROR during LLM analysis: {e}{bcolors.ENDC}")
        return raw_output, [] or None, []
    
    last_raw_response = raw_output
    if not last_raw_response:
        print(f"{bcolors.FAIL}ERROR: No response received or correctly saved from AI model.{bcolors.ENDC}")
        return None, []
    
    try:
        result = json.loads(last_raw_response)
    except json.JSONDecodeError:
        print(f"{bcolors.FAIL}Error parsing JSON from AI response{bcolors.ENDC}")
        return []

    return last_raw_response, result