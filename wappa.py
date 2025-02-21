from wappalyzer import analyze
import json

def main():
    try:
        results = analyze('https://u-tad.com/', scan_type='full')
        print("Resultados del análisis:")
        # Formateamos la salida en JSON con indentación para que se lea mejor
        print(json.dumps(results, indent=4, sort_keys=True))
    except Exception as e:
        print("Se ha producido un error durante el análisis:", e)

if __name__ == '__main__':
    main()
