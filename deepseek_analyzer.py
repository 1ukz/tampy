import os
import json
from openai import OpenAI   # cliente OpenAI utilizado también para DeepSeek
from bcolors import bcolors



def analyze_packets_with_deepseek(har_filename, model):
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

    # 2. Prepara el prompt del sistema (contexto de auditor)
    system_prompt = (
        "Eres un auditor de ciberseguridad experto en páginas web de e-commerce y programación. Analiza estas peticiones HTTP y detecta vectores de vulnerabilidad en el proceso de compra o la lógica de compra. El ánalisis debe ser muy exhaustivo en busca de cada detalle ya que tu ánalisis formara parte de un reporte profesional de seguridad.\n"
        "No repitas la información que has dado en un control para otro. Si hay algo que puede encajar con más de un control, solo muestralo en uno. \n" 
        "Basate en estos controles:\n"
        "• 2.1.1 IDOR: parámetros como '*_id', 'object_id', 'user_id' que permiten a los atacantes cambiar el valor de un parámetro para apuntar, cambiar y/o acceder a un objeto, apartado o componente que no deberían poder. Entre otras cosas, esta vulnerabilidad hace que un atacante pueda eludir y saltar posibles reglas de autorización necesarias, o apuntar a otros objetos y cambiar valores.\n"
        "• 2.1.2 Cookies: cadenas cifradas debilmente, predecibles, modificables, sin HttpOnly/Secure... etc. \n"
        "• 2.1.3 Race conditions y gestiones de estado: pasos de compra paralelos. Aquí es bueno buscar posibles variables de pasos de compra (stages, steps, etc), o ver si cambiar ciertos parametros afecta a la gestión de compra.  \n"
        "• 2.1.4 Parámetros/variables críticas: precios, cantidades, moneda, IDs. Este tipo de vulnerabilidad hace referencia a la manipulación y modificación del contenido de parámetros y variables específicas enviados entre el cliente y el servidor y ver si afecta a la lógica o producto final de la compra como el precio a pagar. Hay que tener en cuenta no solo texto en claro, sino también posibles cifrados débiles como inflates/deflates, base64, etc.\n"
        "• 2.1.5 Ofuscación/Hash: base64, deflate, hashes débiles. Todo aquello que encuentres que posiblemente pueda ser descifrable (como un deflate o un base64), no solo lo destaques sino descifralo también.\n"
        "• 2.1.6 Información sensible siendo enviada como tarjetas de crédito siendo expuestas en texto claro, u otra información que no debería ser visible.\n"
        "Por cada petición que hayas encontrado posiblemente vulnerable bajo cada control, devuelve en idioma inglés siempre:\n"
        "- índice (0-based)\n"
        "- parámetro(s) sospechosos o inseguros\n"
        "- parámetro(s) a modificar y tipo de prueba explotación sugerida (e.g. cambiar precio, cambiar ID, forzar cookie)\n"
        "- la petición http pero modificada (por ejemplo, si aparece el precio, pues con un valor de precio diferente) para hacer una prueba relanzando esa petición modificada (petición http en formato JSON, tal como se te ha sido dada). \n"
        "El formato de tu respuesta debe ser un array JSON con objetos que contengan los campos: 'control_id', y dentro (por cada paquete) 'packet_index', 'parameter', 'test', 'modified_request_example' (y dentro de este último la petición modificada completa).\n"
    )

    # 3. User prompt con el array JSON
    user_prompt = (
        f"He capturado {len(packets)} peticiones en '{har_filename}':\n\n"
        + json.dumps(packets, indent=2)
    )

    # 4. Inicializa cliente OpenAI apuntando a DeepSeek
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        print(f"{bcolors.FAIL}ERROR: Please define DEEPSEEK_API_KEY in the environment variables (.env) file. {bcolors.ENDC}")
        return

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com"  # sobreescribe la URL de OpenAI :contentReference[oaicite:1]{index=1}
    )

    # 5. Llamada a la API
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt}
        ],
        temperature=0.2
    )

    # 6. Mostrar resultado
    #print(f"\n{bcolors.BOLD}=== Análisis DeepSeek (Fase 3) ==={bcolors.ENDC}\n")
    raw_result = resp.choices[0].message.content
    try:
        result = json.loads(raw_result)
    except json.JSONDecodeError:
        print(f"{bcolors.FAIL}Error parsing JSON from AI response{bcolors.ENDC}")
        return []

    return raw_result, result