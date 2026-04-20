#!/usr/bin/env python3
"""
OSINT Tool — GUI (Tkinter)
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import queue
import sys
import os
import webbrowser
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from osint_tool import OSINTSearcher


# ── Redirect stdout al widget di output ───────────────────────────────────────
class QueueStream:
    def __init__(self, q):
        self.q = q
    def write(self, text):
        if text:
            self.q.put(text)
    def flush(self):
        pass


# ── App principale ─────────────────────────────────────────────────────────────
class OSINTApp:

    # Palette colori (Midnight Theme Modernizzato)
    BG       = "#0f172a"
    CARD     = "#1e293b"
    ACC      = "#6366f1"
    ACC2     = "#4f46e5"
    FG       = "#f1f5f9"
    MUTED    = "#94a3b8"
    ENTRY_BG = "#020617"
    GREEN    = "#10b981"
    BLUE     = "#0ea5e9"
    GRAY     = "#475569"
    TERM_BG  = "#020617"
    TERM_FG  = "#38bdf8"

    def __init__(self, root):
        self.root = root
        self.root.title("OSINT Tool")
        self.root.geometry("900x700")
        self.root.minsize(700, 550)
        self.root.configure(bg=self.BG)

        self.output_q = queue.Queue()
        self.running = False
        self.html_report_path = None
        self.text_report_path = None

        self._build_ui()
        self._poll_queue()

    # ── Costruzione interfaccia ───────────────────────────────────────────────

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=self.ACC, pady=14)
        header.pack(fill="x")
        tk.Label(header, text="OSINT TOOL",
                 font=("Segoe UI", 26, "bold"),
                 bg=self.ACC, fg=self.FG).pack()
        tk.Label(header, text="Open Source Intelligence Gatherer",
                 font=("Segoe UI", 11),
                 bg=self.ACC, fg="#c7d2fe").pack()

        # Contenitore principale
        main = tk.Frame(self.root, bg=self.BG, padx=22, pady=16)
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(5, weight=1)

        # ── Riga target ──
        self._label(main, "Target", 0)
        target_row = tk.Frame(main, bg=self.BG)
        target_row.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        target_row.columnconfigure(0, weight=1)

        self.target_var = tk.StringVar()
        entry = tk.Entry(target_row, textvariable=self.target_var,
                         font=("Segoe UI", 14),
                         bg=self.ENTRY_BG, fg=self.FG,
                         insertbackground=self.FG,
                         relief="flat", bd=0)
        entry.grid(row=0, column=0, sticky="ew", ipady=8, padx=(0, 10))
        entry.bind("<Return>", lambda _: self._start_search())

        kwargs_search = {
            "text": "CERCA",
            "font": ("Segoe UI", 12, "bold"),
            "command": self._start_search,
            "cursor": "hand2",
            "padx": 24,
            "pady": 8
        }
        if sys.platform != "darwin":
            kwargs_search.update({
                "bg": self.ACC,
                "fg": self.FG,
                "activebackground": self.ACC2,
                "activeforeground": self.FG,
                "relief": "flat"
            })
        else:
            kwargs_search.update({"fg": "black"})
            
        self.search_btn = tk.Button(target_row, **kwargs_search)
        self.search_btn.grid(row=0, column=1)

        # ── Tipo di ricerca ──
        self._label(main, "Tipo di ricerca", 2)
        type_card = tk.Frame(main, bg=self.CARD, padx=14, pady=10)
        type_card.grid(row=3, column=0, sticky="ew", pady=(0, 14))

        self.search_type = tk.StringVar(value="auto")
        types = [
            ("Auto-detect",   "auto"),
            ("Email",         "email"),
            ("Telefono",      "phone"),
            ("Dominio",       "domain"),
            ("IP",            "ip"),
            ("Username",      "username"),
            ("Nome persona",  "name"),
            ("Comprensivo",   "comprehensive"),
        ]
        for i, (label, val) in enumerate(types):
            rb = tk.Radiobutton(type_card, text=label,
                                variable=self.search_type, value=val,
                                bg=self.CARD, fg=self.FG,
                                selectcolor=self.ACC,
                                activebackground=self.CARD,
                                activeforeground=self.FG,
                                font=("Segoe UI", 11))
            rb.grid(row=i // 4, column=i % 4, sticky="w", padx=14, pady=3)

        # ── Opzioni ──
        opts = tk.Frame(main, bg=self.BG)
        opts.grid(row=4, column=0, sticky="ew", pady=(0, 14))

        self.save_log_var = tk.BooleanVar(value=False)
        self._checkbox(opts, "Salva log .txt", self.save_log_var)

        self.no_reports_var = tk.BooleanVar(value=False)
        self._checkbox(opts, "Salta generazione report", self.no_reports_var, padx=20)

        # ── Output ──
        self._label(main, "Output", 5, pady=(0, 4))
        self.output_text = scrolledtext.ScrolledText(
            main,
            font=("Consolas", 10),
            bg=self.TERM_BG, fg=self.TERM_FG,
            insertbackground=self.FG,
            relief="flat", bd=0,
            wrap="word",
            state="disabled",
        )
        self.output_text.grid(row=6, column=0, sticky="nsew", pady=(0, 12))
        main.rowconfigure(6, weight=1)

        # ── Bottoni report ──
        btn_row = tk.Frame(main, bg=self.BG)
        btn_row.grid(row=7, column=0, sticky="ew")

        self.html_btn = self._button(btn_row, "Apri Report HTML",
                                     self.GREEN, self._open_html_report,
                                     state="disabled")
        self.html_btn.pack(side="left", padx=(0, 8))

        self.txt_btn = self._button(btn_row, "Apri Report TXT",
                                    self.BLUE, self._open_txt_report,
                                    state="disabled")
        self.txt_btn.pack(side="left", padx=(0, 8))

        self._button(btn_row, "Pulisci", self.GRAY,
                     self._clear_output).pack(side="left")

        # ── Status bar ──
        self.status_var = tk.StringVar(value="Pronto.")
        tk.Label(self.root, textvariable=self.status_var,
                 font=("Segoe UI", 9),
                 bg="#0f0f1a", fg=self.MUTED,
                 anchor="w", padx=12, pady=5).pack(fill="x", side="bottom")

    # ── Helper widget ─────────────────────────────────────────────────────────

    def _label(self, parent, text, row, pady=(0, 6)):
        tk.Label(parent, text=text,
                 font=("Segoe UI", 11, "bold"),
                 bg=self.BG, fg=self.FG).grid(
                     row=row, column=0, sticky="w", pady=pady)

    def _checkbox(self, parent, text, var, padx=0):
        tk.Checkbutton(parent, text=text, variable=var,
                       bg=self.BG, fg=self.FG,
                       selectcolor=self.ACC,
                       activebackground=self.BG,
                       activeforeground=self.FG,
                       font=("Segoe UI", 10)).pack(side="left", padx=(padx, 0))

    def _button(self, parent, text, color, cmd, state="normal"):
        kwargs = {
            "text": text,
            "font": ("Segoe UI", 10, "bold"),
            "command": cmd,
            "state": state,
            "cursor": "hand2",
            "padx": 12,
            "pady": 5
        }
        if sys.platform != "darwin":
            kwargs.update({
                "bg": color,
                "fg": self.FG,
                "activebackground": color,
                "activeforeground": self.FG,
                "relief": "flat"
            })
        else:
            if state != "disabled":
                kwargs.update({"fg": "black"})
        return tk.Button(parent, **kwargs)

    # ── Logica di output ──────────────────────────────────────────────────────

    def _append_output(self, text):
        self.output_text.configure(state="normal")
        self.output_text.insert("end", text)
        self.output_text.see("end")
        self.output_text.configure(state="disabled")

    def _clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.configure(state="disabled")
        self.html_btn.configure(state="disabled")
        self.txt_btn.configure(state="disabled")
        self.html_report_path = None
        self.text_report_path = None

    def _poll_queue(self):
        try:
            while True:
                self._append_output(self.output_q.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    # ── Ricerca ──────────────────────────────────────────────────────────────

    def _start_search(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Target mancante",
                                   "Inserisci un target prima di cercare.")
            return
        if self.running:
            messagebox.showinfo("In corso", "Una ricerca è già in corso.")
            return

        self._clear_output()
        self.running = True
        self.search_btn.configure(state="disabled", text="RICERCA...")
        self.status_var.set(f"Ricerca in corso su: {target}")

        threading.Thread(target=self._run_search,
                         args=(target,), daemon=True).start()

    def _run_search(self, target):
        old_stdout = sys.stdout
        sys.stdout = QueueStream(self.output_q)

        try:
            log_file = None
            if self.save_log_var.get():
                safe = target.replace(".", "_").replace("@", "_").replace(" ", "_")
                log_file = f"osint_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

            searcher = OSINTSearcher(output_file=log_file)
            stype = self.search_type.get()

            dispatch = {
                "email":         searcher.search_email,
                "phone":         searcher.search_phone,
                "domain":        searcher.search_domain,
                "ip":            searcher.search_ip,
                "username":      searcher.search_social_media,
                "name":          searcher.search_name,
                "comprehensive": searcher.run_comprehensive_search,
            }
            fn = dispatch.get(stype, searcher.run_comprehensive_search)
            fn(target)

            searcher.print_summary()

            if not self.no_reports_var.get():
                print("\n[*] Generazione report...")
                self.html_report_path = searcher.generate_html_report(target)
                self.text_report_path = searcher.generate_text_report(target)
                print(f"[+] HTML → {self.html_report_path}")
                print(f"[+] TXT  → {self.text_report_path}")
                self.root.after(0, lambda: self.html_btn.configure(state="normal"))
                self.root.after(0, lambda: self.txt_btn.configure(state="normal"))

            count = len(searcher.results)
            self.root.after(0, lambda: self.status_var.set(
                f"Completato — {count} risultati trovati."))

        except Exception as e:
            print(f"\n[ERRORE] {e}")
            self.root.after(0, lambda: self.status_var.set(f"Errore: {e}"))

        finally:
            sys.stdout = old_stdout
            self.running = False
            self.root.after(0, lambda: self.search_btn.configure(
                state="normal", text="CERCA"))

    # ── Apertura report ───────────────────────────────────────────────────────

    def _open_html_report(self):
        if self.html_report_path and os.path.exists(self.html_report_path):
            webbrowser.open(f"file://{os.path.abspath(self.html_report_path)}")

    def _open_txt_report(self):
        if self.text_report_path and os.path.exists(self.text_report_path):
            path = os.path.abspath(self.text_report_path)
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                import subprocess
                subprocess.call(['xdg-open', path])


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    root = tk.Tk()
    app = OSINTApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
