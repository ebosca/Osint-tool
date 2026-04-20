#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  OSINT Tool — avvio GUI con doppio click
# ─────────────────────────────────────────────────────────────

cd "$(dirname "$0")"

VENV_DIR="$(dirname "$0")/.venv"

echo "======================================"
echo "       OSINT TOOL — Avvio GUI"
echo "======================================"
echo ""

# ── 1. Controlla Python 3 ─────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[ERRORE] Python 3 non trovato."
    echo "  Scaricalo da: https://www.python.org/downloads/"
    read -p "Premi Invio per chiudere..."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1)
echo "[OK] $PYTHON_VERSION trovato."

# ── 2. Crea/attiva virtual environment ───────────────────────
if [ ! -d "$VENV_DIR" ]; then
    echo ""
    echo "[*] Prima esecuzione: creo ambiente virtuale..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "[ERRORE] Impossibile creare il virtual environment."
        read -p "Premi Invio per chiudere..."
        exit 1
    fi
    echo "[OK] Ambiente virtuale creato in .venv/"
fi

source "$VENV_DIR/bin/activate"
echo "[OK] Ambiente virtuale attivo."

# ── 3. Controlla e installa dipendenze Python ─────────────────
echo ""
echo "[*] Controllo dipendenze Python..."

PACKAGES=("requests" "bs4" "googlesearch" "dns" "dotenv")
INSTALL_NAMES=("requests" "beautifulsoup4" "googlesearch-python" "dnspython" "python-dotenv")
MISSING=()

for i in "${!PACKAGES[@]}"; do
    if ! python3 -c "import ${PACKAGES[$i]}" &>/dev/null; then
        echo "    [!] Mancante: ${INSTALL_NAMES[$i]}"
        MISSING+=("${INSTALL_NAMES[$i]}")
    else
        echo "    [OK] ${PACKAGES[$i]}"
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo ""
    echo "[*] Installo i pacchetti mancanti nel venv..."
    pip install "${MISSING[@]}"
    if [ $? -ne 0 ]; then
        echo "[ERRORE] Installazione fallita."
        read -p "Premi Invio per chiudere..."
        exit 1
    fi
    echo "[OK] Dipendenze installate."
else
    echo "[OK] Tutte le dipendenze sono presenti."
fi

# ── 4. Controlla tkinter ──────────────────────────────────────
echo ""
echo "[*] Controllo tkinter..."

if ! python3 -c "import tkinter" &>/dev/null; then
    echo ""
    echo "[ERRORE] tkinter non disponibile."
    echo ""

    # Rileva la versione di Python per dare il comando brew corretto
    PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
    PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
    echo "  Installalo con:"
    echo "    brew install python-tk@${PY_MAJOR}.${PY_MINOR}"
    echo ""
    echo "  Poi riapri questo file."
    read -p "Premi Invio per chiudere..."
    exit 1
fi

echo "[OK] tkinter disponibile."

# ── 5. Avvia la GUI ───────────────────────────────────────────
echo ""
echo "[*] Avvio interfaccia grafica..."
echo "    (questa finestra può essere chiusa)"
echo ""

python3 osint_gui.py
