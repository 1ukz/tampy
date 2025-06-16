# 1. Instalar Java 11+ (necesario para OWASP ZAP)

Descarga e instala desde https://www.oracle.com/java/technologies/downloads/#jdk24-windows

# 2. Instalar OWASP ZAP

Windows: Descarga e instala el MSI desde https://github.com/zaproxy/zaproxy/releases/latest

Linux (Debian/Ubuntu): sudo apt install -y zaproxy

macOS (Homebrew): brew install owasp-zap

# 3. Instalar Firefox (si no lo tienes)

Windows / macOS: desde https://www.mozilla.org/firefox/

Linux (Debian/Ubuntu): sudo apt install -y firefox

# 4. Configurar variable de entorno ZAP_PATH (opcional)

### Sólo si ZAP no está en una ruta estándar:

export ZAP_PATH="/ruta/a/zap.sh" # Linux/macOS
setx ZAP_PATH "C:\Program Files\ZAP\Zed Attack Proxy\zap.bat" # Windows CMD/PowerShell

# 5. Crear y activar un entorno virtual de Python

python3 -m venv .venv
source .venv/bin/activate # Linux/macOS
.venv\Scripts\activate.bat # Windows

# 6. Instalar dependencias de Python

pip install -r requirements.txt

# 7. Ejecutar tu script

python main.py
