<div align="center">
<pre style="color: #c084fc; font-weight: bold;">
  ___  ____ ___ _   _ _____   _____ ___   ___  _     
 / _ \/ ___|_ _| \ | |_   _| |_   _/ _ \ / _ \| |    
| | | \___ \| ||  \| | | |     | || | | | | | | |    
| |_| |___) | || |\  | | |     | || |_| | |_| | |___ 
 \___/|____/___|_| \_| |_|     |_| \___/ \___/|_____|
</pre>

**Open Source Intelligence Gatherer**
</div>

# OSINT Tool

Strumento di **Open-Source Intelligence (OSINT)** avanzato, dotato di un'interfaccia grafica moderna (GUI) e una potentissima Command-Line Interface (CLI). Estrapola informazioni preziose su domini, IP, email, telefoni e username in maniera sicura, veloce e 100% gratuita.

## Requisiti

- Funziona su macOS, Linux e Windows
- Python 3.10+ con modulo `tkinter`

## Installazione

```bash
# 1. Clona o scarica il progetto
git clone https://github.com/emanueleboscaglia/Osint-tool.git
cd Osint-tool

# 2. Installa i pacchetti richiesti in un virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> Su Linux (Debian/Ubuntu), per l'interfaccia grafica è richiesto: `sudo apt-get install python3-tk`

## Configurazione

Copia il template `.env` e inserisci le tue chiavi API opzionali. **Il 90% del tool funziona gratis senza chiavi API.**

```bash
cp .env.example .env
```
*(Opzionale)* Puoi inserire in `.env` una chiave VirusTotal gratuita per la reputazione degli IP. Altri servizi (`Gravatar`, `crt.sh`, `BGPView`, `HackerTarget`, `LeakCheck`) funzionano senza alcuna registrazione.

## Avvio

**Metodo 1 — Doppio click (macOS):**
```bash
avvia_osint_gui.command  # Per avviare l'interfaccia grafica
avvia_osint.command      # Per avviare la procedura guidata da Terminale
```

**Metodo 2 — Terminale Multipiattaforma:**
```bash
# Interfaccia Grafica
python3 osint_gui.py

# CLI - Rilevamento automatico del target
python3 osint_tool.py example@test.com
python3 osint_tool.py apple.com
python3 osint_tool.py 8.8.8.8
```

## Funzionalità

### 🔴 Email OSINT
- **Gravatar Deep Scan**: Scopre l'identità, le foto profilo e gli account collegati all'email tramite analisi Hash MD5.
- **LeakCheck Breach Scan**: Cerca istantaneamente se l'indirizzo email e la password sono compromessi in noti data breach.
- **Search Engine**: Cerca tracce dell'email sui motori di ricerca.

### 🟡 Dominio OSINT
- **Sottodomini Invisibili (`crt.sh`)**: Interroga i registri di trasparenza SSL gratuiti per scoprire portali e sottodomini aziendali (es. `dev.domain.com`).
- **Wayback Machine**: Trova automaticamente copie storiche del sito su *Internet Archive*.
- **Reverse IP Lookup**: Scova tutti gli altri siti web di altri proprietari ospitati sullo stesso server (via *HackerTarget*).
- **WHOIS & DNS**: Estrazione diretta dei record A, MX, NS, TXT e informazioni di registrazione dominio.

### 🔵 IP e Network OSINT
- **BGP & ISP Intel**: Attraverso *BGPView*, estrapola l'Azienda Telecom (ISP), il blocco *RIR* assegnato e l'Autonomous System Number (ASN).
- **IP Geolocation**: Traccia città e stato da cui proviene.
- **VirusTotal Scan**: (Richiede API) Controlla la reputazione dell'IP per identificare nodi malevoli o server proxy.

### 🟢 Username e Social OSINT
- **GitHub Profiling**: Esegue una chiamata al database GitHub per estrapolare Azienda, Blog, Biografia, Location ed Email pubblica collegata all'username.
- **Social Media Presence**: Scannerizza la disponibilità dell'username su 10 piattaforme tra cui Reddit, YouTube, TikTok, Pinterest, Facebook.

## Struttura

```
Osint-tool/
├── osint_tool.py          # Core Engine ed esecuzione CLI
├── osint_gui.py           # Motore dell'Interfaccia Grafica (Tkinter)
├── .env.example           # Template per le tue credenziali API
├── requirements.txt       # Dipendenze Python
├── avvia_osint*.command   # Script launcher nativi (macOS)
└── Report/                # Cartella di output isolata (ignorata da git)
```

## Note, Sicurezza e Licenza

- **Privacy Dati**: Tutti i report vengono salvati localmente nella directory `Report/`. Questa cartella è esplicitamente esclusa dal versionamento Git per prevenire il caricamento accidentale di informazioni sensibili e pertinenti alle proprie indagini.
- **Sicurezza API**: Il file `.env`, deputato alla conservazione delle chiavi API, è inserito in `.gitignore`. Se effettui un fork, assicurati sempre di non pubblicare le tue chiavi primarie online.
- **OSINT Tool** è rilasciato sotto licenza esclusiva **Custom Source-Available License**.
  Consulta il file [LICENSE](LICENSE) per i termini completi. Il software può essere utilizzato, studiato e modificato **gratuitamente per scopi personali, educativi e di ricerca**. Ogni eventuale ridistribuzione richiede la formale e rigorosa menzione dell'autore originale. Usi a scopo di lucro, commerciale o aziendale sono severamente vietati senza espresso consenso scritto.
