#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  OSINT Tool — avvio con doppio click
#  Controlla i requisiti e lancia osint_tool.py
# ─────────────────────────────────────────────────────────────

# Vai nella cartella dello script (necessario quando si fa doppio click)
cd "$(dirname "$0")"

echo -e "\e[95m\e[1m"
echo "  ___  ____ ___ _   _ _____   _____ ___   ___  _     "
echo " / _ \/ ___|_ _| \ | |_   _| |_   _/ _ \ / _ \| |    "
echo "| | | \___ \| ||  \| | | |     | || | | | | | | |    "
echo "| |_| |___) | || |\  | | |     | || |_| | |_| | |___ "
echo " \___/|____/___|_| \_| |_|     |_| \___/ \___/|_____|"
echo -e "\e[0m"
echo -e "  \e[96mOpen Source Intelligence Gatherer\e[0m"
echo ""

# ── 1. Controlla Python 3 ─────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[ERRORE] Python 3 non trovato."
    echo "  Scaricalo da: https://www.python.org/downloads/"
    echo ""
    read -p "Premi Invio per chiudere..."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1)
echo "[OK] $PYTHON_VERSION trovato."

# ── 2. Crea/attiva virtual environment ───────────────────────
VENV_DIR="$(dirname "$0")/.venv"

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

# Attiva il venv
source "$VENV_DIR/bin/activate"
echo "[OK] Ambiente virtuale attivo."

# ── 3. Controlla e installa i requisiti ───────────────────────
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
        echo ""
        echo "[ERRORE] Installazione fallita."
        read -p "Premi Invio per chiudere..."
        exit 1
    fi
    echo "[OK] Dipendenze installate."
else
    echo "[OK] Tutte le dipendenze sono presenti."
fi

# ── 3. Chiedi il target ───────────────────────────────────────
echo ""
echo "======================================"
echo "  Cosa vuoi cercare?"
echo "  (email, IP, dominio, username, nome)"
echo "======================================"
read -p "  Target: " TARGET

if [ -z "$TARGET" ]; then
    echo "[ERRORE] Nessun target inserito."
    read -p "Premi Invio per chiudere..."
    exit 1
fi

# ── 4. Scegli il tipo di ricerca ──────────────────────────────
echo ""
echo "Tipo di ricerca:"
echo "  [1] Auto-detect (consigliato)"
echo "  [2] Email"
echo "  [3] Numero di telefono"
echo "  [4] Dominio"
echo "  [5] Indirizzo IP"
echo "  [6] Username"
echo "  [7] Nome persona"
echo "  [8] Comprensivo (tutto)"
echo ""
read -p "  Scelta [1-8, default 1]: " SCELTA

case "$SCELTA" in
    2) FLAG="--email" ;;
    3) FLAG="--phone" ;;
    4) FLAG="--domain" ;;
    5) FLAG="--ip" ;;
    6) FLAG="--username" ;;
    7) FLAG="--name" ;;
    8) FLAG="--comprehensive" ;;
    *) FLAG="" ;;
esac

# ── 5. Opzione salvataggio log ────────────────────────────────
echo ""
read -p "Salvare i risultati in un file .log? [s/N]: " SAVELOG
if [[ "$SAVELOG" =~ ^[Ss]$ ]]; then
    LOGFILE="osint_$(echo "$TARGET" | tr ' @.' '_')_$(date +%Y%m%d_%H%M%S).log"
    LOG_FLAG="-o $LOGFILE"
    echo "[*] Log: $LOGFILE"
else
    LOG_FLAG=""
fi

# ── 6. Avvia il tool ──────────────────────────────────────────
echo ""
echo "======================================"
echo "  Avvio ricerca su: $TARGET"
echo "======================================"
echo ""

python3 osint_tool.py "$TARGET" $FLAG $LOG_FLAG

echo ""
echo "======================================"
echo "  Ricerca completata."
echo "======================================"
read -p "Premi Invio per chiudere..."
