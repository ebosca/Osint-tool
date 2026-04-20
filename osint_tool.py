#!/usr/bin/env python3
"""
OSINT Search Script with HTML and Text Reporting
A tool for gathering open-source intelligence from various platforms and sources.
"""

import requests
import json
import re
import time
import argparse
import sys
from urllib.parse import quote_plus, urlparse
from bs4 import BeautifulSoup
import googlesearch
from datetime import datetime
import os
import hashlib
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ── ANSI COLORS ───────────────────────────────────────────────────────────────
class C:
    BLU = '\033[94m'
    VRD = '\033[92m'
    GIA = '\033[93m'
    ROS = '\033[91m'
    CYA = '\033[96m'
    MAG = '\033[95m'
    RST = '\033[0m'
    BLD = '\033[1m'

import builtins
_orig_print = builtins.print
def _colored_print(*args, **kwargs):
    if args and isinstance(args[0], str):
        text = args[0]
        # Only use ANSI if outputting to a real terminal
        is_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        
        if is_tty:
            if text.lstrip('\n').startswith("[*]"):
                nl = '\n' * (len(text) - len(text.lstrip('\n')))
                body = text.lstrip('\n')[3:]
                text = f"{nl}{C.BLU}{C.BLD}[*]{C.RST}{C.BLU}{body}{C.RST}"
            elif text.lstrip('\n').startswith("[+]"):
                nl = '\n' * (len(text) - len(text.lstrip('\n')))
                body = text.lstrip('\n')[3:]
                text = f"{nl}{C.VRD}{C.BLD}[+]{C.RST}{C.VRD}{body}{C.RST}"
            elif text.lstrip('\n').startswith("[!]"):
                nl = '\n' * (len(text) - len(text.lstrip('\n')))
                body = text.lstrip('\n')[3:]
                text = f"{nl}{C.ROS}{C.BLD}[!]{C.RST}{C.ROS}{body}{C.RST}"
            elif text.lstrip('\n').startswith("==============="):
                text = f"{C.CYA}{C.BLD}{text}{C.RST}"
            elif re.match(r'^\[.*?\]\s*\{', text) or re.match(r'^\[.*?\]\s*\[', text):
                parts = text.split("]", 1)
                if len(parts) == 2:
                    text = f"{C.CYA}{C.BLD}{parts[0]}]{C.RST}{parts[1]}"
                    
        _orig_print(text, *args[1:], **kwargs)
    else:
        _orig_print(*args, **kwargs)

builtins.print = _colored_print
# ─────────────────────────────────────────────────────────────────────────────
# ── API KEYS ──────────────────────────────────────────────────────────────────
# Leave empty ("") to skip that check with a warning instead of failing.
#
# VirusTotal — free tier at https://www.virustotal.com/gui/join-us
# (500 req/day, 4 req/min — free personal account)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
# ─────────────────────────────────────────────────────────────────────────────


class OSINTSearcher:
    def __init__(self, output_file=None):
        self.results = []
        self.output_file = output_file
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def save_result(self, source, data):
        """Save a result to our collection"""
        result = {
            'source': source,
            'data': data,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.results.append(result)

        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(f"[{result['timestamp']}] {source}: {json.dumps(data)}\n")

        print(f"[{source}] {json.dumps(data)}")

    # ── Report directory ──────────────────────────────────────────────────────

    def _get_report_dir(self, target):
        """Create and return Report/<target>_<timestamp>/ subfolder."""
        safe = target.replace('.', '_').replace('@', '_').replace('/', '_').replace(' ', '_')
        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        folder = os.path.join('Report', f'{safe}_{ts}')
        os.makedirs(folder, exist_ok=True)
        return folder

    # ── HTML report ───────────────────────────────────────────────────────────

    def generate_html_report(self, target):
        """Generate a clean, readable HTML report."""
        report_dir = self._get_report_dir(target)
        html_file  = os.path.join(report_dir, 'report.html')

        SOCIAL_PLATFORMS = {
            'Twitter', 'Instagram', 'LinkedIn', 'Facebook',
            'GitHub', 'Reddit', 'YouTube', 'TikTok', 'Pinterest', 'Medium'
        }
        SOCIAL_ICONS = {
            'Twitter': '🐦', 'Instagram': '📸', 'LinkedIn': '💼',
            'Facebook': '👤', 'GitHub': '🐙', 'Reddit': '🤖',
            'YouTube': '▶️', 'TikTok': '🎵', 'Pinterest': '📌', 'Medium': '✍️',
        }

        # Bucket results
        leakcheck  = [r for r in self.results if r['source'] == 'LeakCheck']
        social     = [r for r in self.results if r['source'] in SOCIAL_PLATFORMS]
        google     = [r for r in self.results if r['source'] in ('Google', 'Google Reverse Image', 'TinEye')]
        whois_res  = [r for r in self.results if r['source'] == 'WHOIS']
        dns_res    = [r for r in self.results if r['source'] == 'DNS']
        ip_res     = [r for r in self.results if r['source'] == 'IP Geolocation']
        vt_res     = [r for r in self.results if r['source'] == 'VirusTotal']
        other      = [r for r in self.results if r['source'] not in
                      SOCIAL_PLATFORMS | {'LeakCheck','Google','Google Reverse Image',
                                          'TinEye','WHOIS','DNS','IP Geolocation','VirusTotal'}]

        # ── Breach banner ────────────────────────────────────────────────────
        breach_html = ''
        if leakcheck:
            d     = leakcheck[0]['data']
            found = d.get('found', 0)
            if found and found > 0:
                fields  = d.get('fields', [])
                sources = d.get('sources', [])
                has_pwd = 'password' in fields

                badge_color = '#dc2626' if has_pwd else '#d97706'
                badge_label = '🔴 COMPROMESSO' if has_pwd else '🟠 ATTENZIONE'
                badge_sub   = (f'Password trovata nei leak — cambiala subito!' if has_pwd
                               else f'Dati personali esposti in {found} breach')

                field_pills = ''.join(
                    f'<span class="pill pill-{'red' if f=='password' else 'gray'}">{f}</span>'
                    for f in fields
                )
                src_rows = ''.join(
                    f'<tr><td>{s.get("name","—")}</td>'
                    f'<td>{s.get("date","—") or "—"}</td></tr>'
                    for s in sources
                )
                breach_html = f"""
<section class="breach-banner" style="border-color:{badge_color}">
  <div class="breach-icon">{badge_label}</div>
  <div class="breach-body">
    <p class="breach-sub">{badge_sub}</p>
    <p class="breach-count">Trovato in <strong>{found}</strong> archivi &nbsp;·&nbsp; <strong>{len(sources)}</strong> sorgenti note</p>
    <div class="field-pills">{field_pills}</div>
    <details>
      <summary>Sorgenti ({len(sources)})</summary>
      <table class="breach-table">
        <thead><tr><th>Sorgente</th><th>Data breach</th></tr></thead>
        <tbody>{src_rows}</tbody>
      </table>
    </details>
  </div>
</section>"""
            else:
                breach_html = """
<section class="safe-banner">
  <span>✅ Nessuna violazione trovata</span>
  <p>L'indirizzo non risulta in archivi di leak conosciuti.</p>
</section>"""

        # ── Social media grid ────────────────────────────────────────────────
        social_html = ''
        if social:
            cards = ''
            for r in social:
                plat   = r['source']
                icon   = SOCIAL_ICONS.get(plat, '🌐')
                status = r['data'].get('status', '')
                url    = r['data'].get('url', '#')
                found  = status == 'found'
                cls    = 'social-card found' if found else 'social-card not-found'
                badge  = '<span class="badge-found">TROVATO</span>' if found else '<span class="badge-nf">NON TROVATO</span>'
                link   = f'<a href="{url}" target="_blank" class="open-link">Apri →</a>' if found else ''
                cards += f'<div class="{cls}"><div class="plat-icon">{icon}</div><div class="plat-name">{plat}</div>{badge}{link}</div>\n'
            social_html = f'<section class="section"><h2 class="section-title">Social Media</h2><div class="social-grid">{cards}</div></section>'

        # ── Google results ───────────────────────────────────────────────────
        google_html = ''
        if google:
            items = ''
            for r in google:
                url = r['data'].get('url', '')
                err = r['data'].get('error', '')
                if url:
                    items += f'<li><a href="{url}" target="_blank" class="glink">{url}</a></li>\n'
                elif err:
                    items += f'<li class="gerr">Errore: {err}</li>\n'
            if items:
                google_html = f'<section class="section"><h2 class="section-title">Google</h2><ul class="glist">{items}</ul></section>'

        # ── WHOIS ────────────────────────────────────────────────────────────
        whois_html = ''
        if whois_res:
            rows = ''
            data = whois_res[0]['data'].get('data', whois_res[0]['data'])
            if isinstance(data, dict):
                for k, v in data.items():
                    if v:
                        rows += f'<tr><td class="kv-key">{k}</td><td>{v}</td></tr>\n'
            whois_html = (f'<section class="section"><h2 class="section-title">WHOIS</h2>'
                          f'<table class="kv-table"><tbody>{rows}</tbody></table></section>'
                          if rows else '')

        # ── DNS ──────────────────────────────────────────────────────────────
        dns_html = ''
        if dns_res:
            records = dns_res[0]['data'].get('records', {})
            rows = ''
            for rtype, values in records.items():
                for v in values:
                    rows += f'<tr><td class="kv-key">{rtype}</td><td>{v}</td></tr>\n'
            dns_html = (f'<section class="section"><h2 class="section-title">DNS</h2>'
                        f'<table class="kv-table"><tbody>{rows}</tbody></table></section>'
                        if rows else '')

        # ── IP Geolocation ───────────────────────────────────────────────────
        ip_html = ''
        if ip_res:
            geo = ip_res[0]['data'].get('data', {})
            if isinstance(geo, dict):
                rows = ''.join(
                    f'<tr><td class="kv-key">{k}</td><td>{v}</td></tr>\n'
                    for k, v in geo.items() if v
                )
                ip_html = (f'<section class="section"><h2 class="section-title">IP Geolocation</h2>'
                           f'<table class="kv-table"><tbody>{rows}</tbody></table></section>')

        # ── VirusTotal ───────────────────────────────────────────────────────
        vt_html = ''
        if vt_res:
            vt_data = vt_res[0]['data'].get('data', {})
            detected = vt_data.get('detected_urls', [])
            score    = f'{len(detected)} URL malevoli rilevati' if detected else 'Nessun URL malevolo rilevato'
            country  = vt_data.get('country', '—')
            asn      = vt_data.get('asn', '—')
            vt_html  = f"""<section class="section"><h2 class="section-title">VirusTotal</h2>
<table class="kv-table"><tbody>
<tr><td class="kv-key">Reputazione</td><td>{score}</td></tr>
<tr><td class="kv-key">Paese</td><td>{country}</td></tr>
<tr><td class="kv-key">ASN</td><td>{asn}</td></tr>
</tbody></table></section>"""

        # ── Other ────────────────────────────────────────────────────────────
        other_html = ''
        if other:
            rows = ''
            for r in other:
                rows += f'<tr><td class="kv-key">{r["source"]}</td><td><pre class="raw">{json.dumps(r["data"], indent=2, ensure_ascii=False)}</pre></td></tr>\n'
            other_html = (f'<section class="section"><h2 class="section-title">Altri risultati</h2>'
                          f'<table class="kv-table"><tbody>{rows}</tbody></table></section>')

        # ── Assemble ─────────────────────────────────────────────────────────
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = f"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report — {target}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f172a; color: #e2e8f0; min-height: 100vh;
  }}
  a {{ color: #60a5fa; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Header */
  .header {{
    background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%);
    padding: 36px 40px 28px;
    border-bottom: 2px solid #4f46e5;
  }}
  .header-tag {{ font-size: 11px; letter-spacing: 3px; color: #a5b4fc; text-transform: uppercase; margin-bottom: 8px; }}
  .header h1 {{ font-size: 24px; font-weight: 700; color: #fff; word-break: break-all; }}
  .header-meta {{ margin-top: 10px; font-size: 13px; color: #818cf8; }}

  /* Layout */
  .content {{ max-width: 960px; margin: 0 auto; padding: 32px 24px 60px; }}
  .section {{ background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #334155; }}
  .section-title {{ font-size: 15px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 18px; }}

  /* Breach banner */
  .breach-banner {{
    background: #1c0a0a; border: 2px solid #dc2626; border-radius: 12px;
    padding: 24px 28px; margin-bottom: 24px; display: flex; gap: 20px; align-items: flex-start;
  }}
  .breach-icon {{ font-size: 20px; font-weight: 800; color: #fca5a5; white-space: nowrap; padding-top: 2px; }}
  .breach-body {{ flex: 1; }}
  .breach-sub {{ color: #fca5a5; font-weight: 600; font-size: 15px; margin-bottom: 6px; }}
  .breach-count {{ color: #94a3b8; font-size: 13px; margin-bottom: 14px; }}
  .field-pills {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 16px; }}
  .pill {{ padding: 3px 10px; border-radius: 99px; font-size: 12px; font-weight: 600; }}
  .pill-red {{ background: #450a0a; color: #fca5a5; border: 1px solid #dc2626; }}
  .pill-gray {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
  details summary {{ cursor: pointer; color: #60a5fa; font-size: 13px; margin-bottom: 10px; }}
  details summary:hover {{ text-decoration: underline; }}

  /* Safe banner */
  .safe-banner {{
    background: #052e16; border: 2px solid #16a34a; border-radius: 12px;
    padding: 20px 28px; margin-bottom: 24px; color: #86efac;
  }}
  .safe-banner span {{ font-size: 16px; font-weight: 700; }}
  .safe-banner p {{ margin-top: 6px; font-size: 13px; color: #4ade80; }}

  /* Social grid */
  .social-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px; }}
  .social-card {{
    border-radius: 10px; padding: 16px 12px; text-align: center;
    border: 1px solid #334155; display: flex; flex-direction: column;
    align-items: center; gap: 8px;
  }}
  .social-card.found {{ background: #0d1f12; border-color: #166534; }}
  .social-card.not-found {{ background: #1e293b; border-color: #334155; opacity: .6; }}
  .plat-icon {{ font-size: 24px; }}
  .plat-name {{ font-size: 13px; font-weight: 600; color: #e2e8f0; }}
  .badge-found {{ background: #166534; color: #86efac; font-size: 10px; font-weight: 700;
                  padding: 2px 8px; border-radius: 99px; letter-spacing: 1px; }}
  .badge-nf {{ background: #1e293b; color: #64748b; font-size: 10px; font-weight: 700;
               padding: 2px 8px; border-radius: 99px; letter-spacing: 1px; border: 1px solid #334155; }}
  .open-link {{ font-size: 11px; color: #60a5fa; }}

  /* Tables */
  .kv-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .kv-table tr {{ border-bottom: 1px solid #1e293b; }}
  .kv-table tr:last-child {{ border-bottom: none; }}
  .kv-table td {{ padding: 8px 10px; vertical-align: top; }}
  .kv-key {{ color: #94a3b8; font-weight: 600; width: 160px; white-space: nowrap; }}
  .breach-table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 6px; }}
  .breach-table th {{ background: #1e293b; color: #94a3b8; padding: 8px 12px; text-align: left; }}
  .breach-table td {{ padding: 8px 12px; border-bottom: 1px solid #1e293b; color: #e2e8f0; }}

  /* Google */
  .glist {{ list-style: none; display: flex; flex-direction: column; gap: 8px; }}
  .glist li {{ font-size: 13px; }}
  .glink {{ word-break: break-all; }}
  .gerr {{ color: #f87171; }}

  /* Raw fallback */
  .raw {{ font-family: monospace; font-size: 12px; color: #94a3b8; white-space: pre-wrap; word-break: break-all; }}

  /* Footer */
  .footer {{ margin-top: 40px; font-size: 12px; color: #475569; border-top: 1px solid #1e293b; padding-top: 20px; }}
</style>
</head>
<body>
<div class="header">
  <div class="header-tag">OSINT Report</div>
  <h1>{target}</h1>
  <div class="header-meta">Generato il {now} &nbsp;·&nbsp; {len(self.results)} risultati totali</div>
</div>
<div class="content">
  {breach_html}
  {social_html}
  {google_html}
  {whois_html}
  {dns_html}
  {ip_html}
  {vt_html}
  {other_html}
  <div class="footer">
    Questo report contiene informazioni raccolte da fonti pubblicamente disponibili.
    Utilizzare le informazioni in modo responsabile e in conformità con le leggi applicabili.
  </div>
</div>
</body>
</html>"""

        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html)

        return html_file

    # ── Text report ───────────────────────────────────────────────────────────

    def generate_text_report(self, target):
        """Generate a readable text report."""
        report_dir = self._get_report_dir(target)
        text_file  = os.path.join(report_dir, 'report.txt')

        SOCIAL_PLATFORMS = {
            'Twitter', 'Instagram', 'LinkedIn', 'Facebook',
            'GitHub', 'Reddit', 'YouTube', 'TikTok', 'Pinterest', 'Medium'
        }

        with open(text_file, 'w', encoding='utf-8') as f:
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            W = 60
            f.write('=' * W + '\n')
            f.write(f'  OSINT REPORT\n')
            f.write(f'  Target   : {target}\n')
            f.write(f'  Data     : {now}\n')
            f.write(f'  Risultati: {len(self.results)}\n')
            f.write('=' * W + '\n\n')

            # ── Breach status ────────────────────────────────────────────
            leakcheck = [r for r in self.results if r['source'] == 'LeakCheck']
            if leakcheck:
                d     = leakcheck[0]['data']
                found = d.get('found', 0)
                f.write('[ BREACH STATUS ]\n')
                f.write('-' * W + '\n')
                if found and found > 0:
                    fields  = d.get('fields', [])
                    sources = d.get('sources', [])
                    has_pwd = 'password' in fields
                    f.write(f'  ⚠  COMPROMESSO — trovato in {found} archivi\n')
                    if has_pwd:
                        f.write('  !! PASSWORD ESPOSTA — cambiarla immediatamente!\n')
                    f.write(f'\n  Dati esposti : {", ".join(fields)}\n')
                    f.write(f'\n  Sorgenti ({len(sources)}):\n')
                    for s in sources:
                        date = s.get('date') or '—'
                        f.write(f'    • {s.get("name","—"):<35} {date}\n')
                else:
                    f.write('  ✓  Nessuna violazione trovata\n')
                f.write('\n')

            # ── Social media ─────────────────────────────────────────────
            social = [r for r in self.results if r['source'] in SOCIAL_PLATFORMS]
            if social:
                found_soc  = [r for r in social if r['data'].get('status') == 'found']
                nfound_soc = [r for r in social if r['data'].get('status') != 'found']
                f.write('[ SOCIAL MEDIA ]\n')
                f.write('-' * W + '\n')
                if found_soc:
                    f.write('  Trovato:\n')
                    for r in found_soc:
                        f.write(f'    ✓ {r["source"]:<14} {r["data"].get("url","")}\n')
                if nfound_soc:
                    f.write('  Non trovato:\n')
                    for r in nfound_soc:
                        f.write(f'    ✗ {r["source"]}\n')
                f.write('\n')

            # ── Google ───────────────────────────────────────────────────
            google = [r for r in self.results
                      if r['source'] in ('Google', 'Google Reverse Image', 'TinEye')]
            if google:
                f.write('[ GOOGLE ]\n')
                f.write('-' * W + '\n')
                for r in google:
                    url = r['data'].get('url', '')
                    err = r['data'].get('error', '')
                    if url:
                        f.write(f'  {url}\n')
                    elif err:
                        f.write(f'  Errore: {err}\n')
                f.write('\n')

            # ── WHOIS ────────────────────────────────────────────────────
            whois_res = [r for r in self.results if r['source'] == 'WHOIS']
            if whois_res:
                f.write('[ WHOIS ]\n')
                f.write('-' * W + '\n')
                data = whois_res[0]['data'].get('data', whois_res[0]['data'])
                if isinstance(data, dict):
                    for k, v in data.items():
                        if v:
                            f.write(f'  {k:<20} {v}\n')
                f.write('\n')

            # ── DNS ──────────────────────────────────────────────────────
            dns_res = [r for r in self.results if r['source'] == 'DNS']
            if dns_res:
                f.write('[ DNS ]\n')
                f.write('-' * W + '\n')
                records = dns_res[0]['data'].get('records', {})
                for rtype, values in records.items():
                    for v in values:
                        f.write(f'  {rtype:<8} {v}\n')
                f.write('\n')

            # ── IP ───────────────────────────────────────────────────────
            ip_res = [r for r in self.results if r['source'] == 'IP Geolocation']
            if ip_res:
                geo = ip_res[0]['data'].get('data', {})
                if isinstance(geo, dict):
                    f.write('[ IP GEOLOCATION ]\n')
                    f.write('-' * W + '\n')
                    for k, v in geo.items():
                        if v:
                            f.write(f'  {k:<20} {v}\n')
                    f.write('\n')

            # ── Other ───────────────────────────────────────────────────────
            other_res = [r for r in self.results if r['source'] not in
                         SOCIAL_PLATFORMS | {'LeakCheck','Google','Google Reverse Image',
                                             'TinEye','WHOIS','DNS','IP Geolocation','VirusTotal'}]
            if other_res:
                f.write('[ ALTRI RISULTATI ]\n')
                f.write('-' * W + '\n')
                for r in other_res:
                    f.write(f'  [+] {r["source"]}:\n')
                    f.write(f'      {json.dumps(r["data"], indent=2, ensure_ascii=False).replace(chr(10), chr(10)+"      ")}\n\n')

            f.write('=' * W + '\n')
            f.write('Informazioni raccolte da fonti pubbliche. Uso responsabile.\n')
            f.write('=' * W + '\n')

        return text_file

    def google_search(self, query, num_results=10):
        """Perform a Google search"""
        print(f"[*] Performing Google search for: {query}")

        try:
            search_results = list(googlesearch.search(query, num_results=num_results))

            for result in search_results:
                self.save_result("Google", {"url": result})

        except Exception as e:
            self.save_result("Google", {"error": str(e)})

    def search_github(self, username):
        """Deep GitHub Profile Data Grab"""
        print(f"[*] Checking GitHub API for: {username}")
        try:
            req = self.session.get(f"https://api.github.com/users/{username}", timeout=10)
            if req.status_code == 200:
                data = req.json()
                info = {
                    "Name": data.get("name"),
                    "Company": data.get("company"),
                    "Blog/Site": data.get("blog"),
                    "Location": data.get("location"),
                    "Email": data.get("email"),
                    "Bio": data.get("bio"),
                    "Twitter": data.get("twitter_username"),
                    "Public Repos": data.get("public_repos"),
                    "Profile URL": data.get("html_url")
                }
                info = {k: v for k, v in info.items() if v}
                if info:
                    self.save_result("GitHub Deep", {"username": username, "data": info})
        except Exception as e:
            self.save_result("GitHub Deep", {"error": str(e)})

    def search_reverse_ip(self, target):
        """HackerTarget Reverse IP (Find domains hosted on same IP)"""
        print(f"[*] Reverse IP Lookup on HackerTarget: {target}")
        try:
            req = self.session.get(f"https://api.hackertarget.com/reverseiplookup/?q={target}", timeout=10)
            if req.status_code == 200:
                text = req.text.strip()
                if text and 'No DNS A records' not in text and 'API count exceeded' not in text and text != target:
                    domains = text.split('\n')
                    self.save_result("Reverse IP Hosted", {"count": len(domains), "domains": domains[:30]})
        except Exception as e:
            self.save_result("Reverse IP Hosted", {"error": str(e)})

    def search_bgp(self, ip):
        """BGPView IP deep info (ASN/ISP/Prefix)"""
        print(f"[*] Fetching BGP/ISP info via BGPView for: {ip}")
        try:
            req = self.session.get(f"https://api.bgpview.io/ip/{ip}", timeout=10)
            if req.status_code == 200:
                data = req.json()
                if data.get("status") == "ok":
                    data_obj = data.get("data", {})
                    asn = data_obj.get("asn", {})
                    info = {
                        "IP": ip,
                        "RIR Allocation": data_obj.get("rir_allocation", {}).get("rir_name"),
                        "Allocation Prefix": data_obj.get("rir_allocation", {}).get("prefix"),
                        "ASN Name": asn.get("name") if asn else None,
                        "ISP Description": asn.get("description") if asn else None,
                        "Country Code": asn.get("country_code") if asn else None
                    }
                    info = {k: v for k, v in info.items() if v}
                    self.save_result("BGP/ISP Info", {"data": info})
        except Exception as e:
            self.save_result("BGP/ISP Info", {"error": str(e)})

    def search_social_media(self, username):
        """Search for username across social media platforms"""
        print(f"[*] Searching for username: {username}")
        
        self.search_github(username)

        platforms = {
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://www.instagram.com/{username}",
            "LinkedIn": f"https://www.linkedin.com/in/{username}",
            "Facebook": f"https://www.facebook.com/{username}",
            "GitHub": f"https://github.com/{username}",
            "Reddit": f"https://www.reddit.com/user/{username}",
            "YouTube": f"https://www.youtube.com/user/{username}",
            "TikTok": f"https://www.tiktok.com/@{username}",
            "Pinterest": f"https://www.pinterest.com/{username}",
            "Medium": f"https://medium.com/@{username}"
        }

        for platform, url in platforms.items():
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    self.save_result(platform, {"url": url, "status": "found"})
                else:
                    self.save_result(platform, {"url": url, "status": "not found", "code": response.status_code})
            except Exception as e:
                self.save_result(platform, {"url": url, "error": str(e)})

    def search_gravatar(self, email):
        """Check Gravatar for profile info based on email hash"""
        print(f"[*] Checking Gravatar for email: {email}")
        hash_txt = hashlib.md5(email.lower().strip().encode('utf-8')).hexdigest()
        try:
            req = self.session.get(f"https://en.gravatar.com/{hash_txt}.json", timeout=10)
            if req.status_code == 200:
                data = req.json()
                profile = data.get("entry", [])[0]
                info = {
                    "displayName": profile.get("displayName"),
                    "profileUrl": profile.get("profileUrl"),
                }
                photos = [p.get("value") for p in profile.get("photos", [])]
                if photos: info["photos"] = photos
                accounts = [a.get("domain") for a in profile.get("accounts", [])]
                if accounts: info["accounts"] = accounts
                
                self.save_result("Gravatar", {"status": "found", "data": info})
            elif req.status_code == 404:
                self.save_result("Gravatar", {"status": "not found"})
            else:
                self.save_result("Gravatar", {"error": f"HTTP {req.status_code}"})
        except Exception as e:
            self.save_result("Gravatar", {"error": str(e)})

    def search_email(self, email):
        """Search for information related to an email address"""
        print(f"[*] Searching for email: {email}")

        self.search_gravatar(email)

        # Check if email appears in known breaches via LeakCheck public API
        # Free, no key required, 15 req/day — https://leakcheck.io/api/public
        try:
            url = f"https://leakcheck.io/api/public?check={quote_plus(email)}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    breach_data = {
                        "email": email,
                        "found": data.get("found", 0),
                        "fields": data.get("fields", []),
                        "sources": data.get("sources", []),
                    }
                    self.save_result("LeakCheck", breach_data)
                else:
                    self.save_result("LeakCheck", {"email": email, "status": "not found in breaches"})
            elif response.status_code == 429:
                self.save_result("LeakCheck", {"email": email, "error": "rate limit reached (15 req/day on free tier)"})
            else:
                self.save_result("LeakCheck", {"email": email, "error": f"HTTP {response.status_code}"})
        except Exception as e:
            self.save_result("LeakCheck", {"email": email, "error": str(e)})

        # Google search for the email
        self.google_search(f'"{email}"', 5)

    def search_phone(self, phone):
        """Search for information related to a phone number"""
        print(f"[*] Searching for phone: {phone}")

        # Format phone number for search
        formatted_phone = re.sub(r'[^\d+]', '', phone)

        # Google search for the phone number
        self.google_search(f'"{formatted_phone}"', 5)

    def search_crtsh(self, domain):
        """Find subdomains silently using Certificate Transparency Logs (crt.sh)"""
        print(f"[*] Searching for subdomains on crt.sh: {domain}")
        try:
            req = self.session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
            if req.status_code == 200:
                data = req.json()
                subdomains = set()
                if isinstance(data, list):
                    for entry in data:
                        name = entry.get("name_value", "")
                        if name:
                            for sub in name.split('\n'):
                                sub = sub.replace('*.', '')
                                if sub.endswith(domain) and sub != domain:
                                    subdomains.add(sub)
                if subdomains:
                    self.save_result("crt.sh Subdomains", {"count": len(subdomains), "subdomains": list(subdomains)[:50]})
                else:
                    self.save_result("crt.sh Subdomains", {"status": "No subdomains found"})
        except Exception as e:
            self.save_result("crt.sh Subdomains", {"error": str(e)})

    def search_wayback(self, domain):
        """Check if Internet Archive has snapshots of this domain"""
        print(f"[*] Checking Internet Archive for: {domain}")
        try:
            req = self.session.get(f"http://archive.org/wayback/available?url={domain}", timeout=10)
            if req.status_code == 200:
                data = req.json()
                snapshots = data.get("archived_snapshots", {})
                if "closest" in snapshots:
                    closest = snapshots["closest"]
                    self.save_result("Wayback Machine", {
                        "available": True,
                        "url": closest.get("url"),
                        "timestamp": closest.get("timestamp")
                    })
                else:
                    self.save_result("Wayback Machine", {"available": False})
        except Exception as e:
            self.save_result("Wayback Machine", {"error": str(e)})

    def search_domain(self, domain):
        """Gather information about a domain"""
        print(f"[*] Searching for domain: {domain}")

        self.search_crtsh(domain)
        self.search_wayback(domain)
        self.search_reverse_ip(domain)

        # WHOIS information
        try:
            url = f"https://api.whoisjson.com/v1/{domain}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                whois_data = response.json()
                self.save_result("WHOIS", {"domain": domain, "data": whois_data})
            else:
                self.save_result("WHOIS", {"domain": domain, "error": "API request failed"})
        except Exception as e:
            self.save_result("WHOIS", {"domain": domain, "error": str(e)})

        # DNS records
        try:
            import dns.resolver
            records = {}
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    pass

            self.save_result("DNS", {"domain": domain, "records": records})
        except Exception as e:
            self.save_result("DNS", {"domain": domain, "error": str(e)})

        # Subdomain search
        self.google_search(f"site:{domain}", 10)

    def search_ip(self, ip):
        """Gather information about an IP address"""
        print(f"[*] Searching for IP: {ip}")

        self.search_bgp(ip)
        self.search_reverse_ip(ip)

        # IP geolocation (no key required)
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                geo_data = response.json()
                self.save_result("IP Geolocation", {"ip": ip, "data": geo_data})
            else:
                self.save_result("IP Geolocation", {"ip": ip, "error": "API request failed"})
        except Exception as e:
            self.save_result("IP Geolocation", {"ip": ip, "error": str(e)})

        # VirusTotal check
        if not VIRUSTOTAL_API_KEY:
            print("[!] VIRUSTOTAL_API_KEY not set — skipping VirusTotal check. See SETUP.md.")
        else:
            try:
                url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
                params = {'apikey': VIRUSTOTAL_API_KEY, 'ip': ip}
                response = self.session.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    vt_data = response.json()
                    self.save_result("VirusTotal", {"ip": ip, "data": vt_data})
                else:
                    self.save_result("VirusTotal", {"ip": ip, "error": f"HTTP {response.status_code}"})
            except Exception as e:
                self.save_result("VirusTotal", {"ip": ip, "error": str(e)})

    def search_name(self, name):
        """Search for information about a person's name"""
        print(f"[*] Searching for name: {name}")

        # Google search for the name
        self.google_search(f'"{name}"', 10)

        # LinkedIn search
        linkedin_url = f"https://www.linkedin.com/search/results/all/?keywords={quote_plus(name)}"
        self.save_result("LinkedIn", {"url": linkedin_url, "type": "search"})

        # Facebook search
        facebook_url = f"https://www.facebook.com/public/{quote_plus(name)}"
        self.save_result("Facebook", {"url": facebook_url, "type": "search"})

    def search_image(self, image_url):
        """Perform reverse image search"""
        print(f"[*] Performing reverse image search for: {image_url}")

        # Google reverse image search
        google_url = f"https://www.google.com/searchbyimage?image_url={image_url}"
        self.save_result("Google Reverse Image", {"url": google_url})

        # TinEye reverse image search
        tineye_url = f"https://tineye.com/search?url={image_url}"
        self.save_result("TinEye", {"url": tineye_url})

    def search_document(self, query):
        """Search for documents related to a query"""
        print(f"[*] Searching for documents: {query}")

        # Search for PDFs
        self.google_search(f'filetype:pdf "{query}"', 5)

        # Search for DOCX files
        self.google_search(f'filetype:docx "{query}"', 5)

        # Search for PPT files
        self.google_search(f'filetype:ppt "{query}"', 5)

        # Search for XLS files
        self.google_search(f'filetype:xls "{query}"', 5)

    def run_comprehensive_search(self, target):
        """Run a comprehensive OSINT search on a target"""
        print(f"[*] Starting comprehensive OSINT search for: {target}")

        # Determine the type of target and run appropriate searches
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            # Email address
            self.search_email(target)

            # Extract username from email for social media search
            username = target.split('@')[0]
            self.search_social_media(username)

        elif re.match(r'^[\d\s\-\+\(\)]+$', target):
            # Phone number
            self.search_phone(target)

        elif re.match(r'^https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$', target):
            # URL
            parsed = urlparse(target)
            domain = parsed.netloc

            # Remove www. prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]

            self.search_domain(domain)

        elif re.match(r'^https?://.*\.(jpg|jpeg|png|gif|bmp|webp)$', target):
            # Image URL
            self.search_image(target)

        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            # IP address
            self.search_ip(target)

        elif '.' in target and ' ' not in target:
            # Likely a domain
            self.search_domain(target)

        else:
            # Assume it's a name or username
            self.search_name(target)
            self.search_social_media(target)

    def print_summary(self):
        """Print a summary of all results"""
        print("\n" + "="*50)
        print("OSINT SEARCH SUMMARY")
        print("="*50)

        sources = {}
        for result in self.results:
            source = result['source']
            if source not in sources:
                sources[source] = 0
            sources[source] += 1

        print(f"Total results: {len(self.results)}")
        print("Results by source:")
        for source, count in sources.items():
            print(f"  {source}: {count}")

        print("\nTop findings:")
        for result in self.results[:10]:
            print(f"[{result['source']}] {json.dumps(result['data'])}")


def main():
    if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
        print(f"{C.MAG}{C.BLD}")
        print(r"  ___  ____ ___ _   _ _____   _____ ___   ___  _     ")
        print(r" / _ \/ ___|_ _| \ | |_   _| |_   _/ _ \ / _ \| |    ")
        print(r"| | | \___ \| ||  \| | | |     | || | | | | | | |    ")
        print(r"| |_| |___) | || |\  | | |     | || |_| | |_| | |___ ")
        print(r" \___/|____/___|_| \_| |_|     |_| \___/ \___/|_____|")
        print(f"{C.RST}")
        print(f"  {C.CYA}Open Source Intelligence Gatherer{C.RST}\n")

    parser = argparse.ArgumentParser(description='OSINT Search Tool with HTML and Text Reporting')
    parser.add_argument('target', help='Target to search (email, phone, domain, IP, username, etc.)')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-e', '--email', action='store_true', help='Search as email address')
    parser.add_argument('-p', '--phone', action='store_true', help='Search as phone number')
    parser.add_argument('-d', '--domain', action='store_true', help='Search as domain')
    parser.add_argument('-i', '--ip', action='store_true', help='Search as IP address')
    parser.add_argument('-u', '--username', action='store_true', help='Search as username')
    parser.add_argument('-n', '--name', action='store_true', help='Search as person name')
    parser.add_argument('-c', '--comprehensive', action='store_true', help='Run comprehensive search')
    parser.add_argument('--no-reports', action='store_true', help='Skip generating HTML and text reports')

    args = parser.parse_args()

    searcher = OSINTSearcher(args.output)

    try:
        if args.comprehensive:
            searcher.run_comprehensive_search(args.target)
        elif args.email:
            searcher.search_email(args.target)
        elif args.phone:
            searcher.search_phone(args.target)
        elif args.domain:
            searcher.search_domain(args.target)
        elif args.ip:
            searcher.search_ip(args.target)
        elif args.username:
            searcher.search_social_media(args.target)
        elif args.name:
            searcher.search_name(args.target)
        else:
            # Auto-detect and run comprehensive search
            searcher.run_comprehensive_search(args.target)

        searcher.print_summary()

        # Generate reports unless explicitly disabled
        if not args.no_reports:
            print("\n[*] Generating reports...")
            html_report = searcher.generate_html_report(args.target)
            text_report = searcher.generate_text_report(args.target)

            print(f"\n[+] HTML report saved to: {html_report}")
            print(f"[+] Text report saved to: {text_report}")

            # Try to open HTML report in default browser
            try:
                import webbrowser
                webbrowser.open(f"file://{os.path.abspath(html_report)}")
                print("[+] HTML report opened in default browser")
            except Exception:
                print("[!] Could not open HTML report automatically")

    except KeyboardInterrupt:
        print("\n[*] Search interrupted by user")
        searcher.print_summary()

        # Generate reports even if interrupted
        if not args.no_reports:
            print("\n[*] Generating reports...")
            html_report = searcher.generate_html_report(args.target)
            text_report = searcher.generate_text_report(args.target)

            print(f"\n[+] HTML report saved to: {html_report}")
            print(f"[+] Text report saved to: {text_report}")

        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
