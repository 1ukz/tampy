import requests
from bs4 import BeautifulSoup
from bcolors import bcolors

def check_cart_section(url):
    """
    Descarga el código fuente de la URL y busca indicios de la sección de carrito
    basándose en las palabras clave definidas. 
    Guarda el volcado de líneas en las que se encontró alguna keyword en un fichero,
    informa cuántas líneas se encontraron y pregunta al usuario si desea ver el resultado.
    """
    # Verificar que la web existe antes de proceder
    if not verify_website_exists(url):
        return False

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"{bcolors.FAIL}Error al descargar la página: {e}{bcolors.ENDC}")
        return False

    # Parsear el HTML con Beautiful Soup y pasarlo a minúsculas
    soup = BeautifulSoup(response.text, 'html.parser')
    html_text = soup.prettify().lower()

    # Lista de palabras clave a buscar
    keywords = ['cart', 'carrito', 'cesta', 'bolsa', 'bag', 'carro']

    # Dividir el HTML en líneas
    lines = html_text.splitlines()

    # Buscar y guardar las líneas que contengan alguna de las palabras clave
    found_lines = []
    for line in lines:
        for keyword in keywords:
            if keyword in line:
                found_lines.append(line.strip())
                break  # Evitar duplicados si hay varias keywords en la misma línea

    # Guardar los resultados en un fichero
    filename = "1_cart_analysis_html.txt"
    with open(filename, "w", encoding="utf-8") as f:
        if found_lines:
            f.write("Se han encontrado {} línea(s) con posibles coincidencias:\n\n".format(len(found_lines)))
            for l in found_lines:
                f.write(l + "\n")
        else:
            f.write("No se encontraron secciones de carrito en la página.\n")

    # Informar al usuario y preguntar si desea ver el contenido del fichero
    if found_lines:
        print(f"{bcolors.OKGREEN}Se han encontrado {len(found_lines)} línea(s) con posibles coincidencias.{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}No se encontraron secciones de carrito en la página.{bcolors.ENDC}")

    choice = input(f"{bcolors.BOLD}¿Deseas mostrar el contenido del análisis en pantalla? (y/n): {bcolors.ENDC}").strip().lower()
    if choice in ['y', 'yes']:
        try:
            with open(filename, "r", encoding="utf-8") as f:
                print("\n" + f.read())
        except Exception as e:
            print(f"{bcolors.FAIL}Error al leer el fichero: {e}{bcolors.ENDC}")

    return True