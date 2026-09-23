"""CYBER CIPHER COMMAND CENTER - redesigned Tkinter interface.

This GUI wraps the existing cipher modules. The cryptanalysis algorithms are
not changed here; this file only improves presentation and usability.
Keep this file beside caesar.py, vigenere.py, and vigenere_attack.py.
"""

import re
import threading
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from collections import Counter
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from caesar import (
    automatic_caesar_analysis,
    decrypt_text as caesar_decrypt_text,
    encrypt_text as caesar_encrypt_text,
)
from vigenere import (
    decrypt_text as vigenere_decrypt_text,
    encrypt_text as vigenere_encrypt_text,
)
from vigenere_attack import recover_key_candidates, search_best_key, fast_english_score
from analysis import rank_key_lengths
from security_reporting import AuditLogger, SecurityReport

try:
    from main import evaluate_plaintext_plausibility, get_analysis_confidence
except ImportError:
    def evaluate_plaintext_plausibility(plaintext):
        letters = [c for c in plaintext if c.isalpha()]
        return {"status": "Unverified", "confidence": "Low", "reason": "GUI fallback evaluation.", "letter_count": len(letters)}

    def get_analysis_confidence(letter_count):
        return ("Low" if letter_count < 40 else "Moderate", "Statistical Candidate", "Manual Verification Required")


class CyberCipherGUI:
    BG = "#070B16"
    SIDEBAR = "#0A1020"
    PANEL = "#10182A"
    PANEL_ALT = "#0B1323"
    FIELD = "#060E1B"
    BORDER = "#233452"
    GRID = "#18263E"
    TEXT = "#E5F0FF"
    MUTED = "#8296B5"
    CYAN = "#27D9F2"
    BLUE = "#4B7BFF"
    GREEN = "#35E5A2"
    AMBER = "#F5C451"
    RED = "#FF647C"
    PURPLE = "#A58BFF"

    def __init__(self, root):
        self.root = root
        self.root.title("CIPHER//COMMAND CENTER")
        self.root.geometry("1540x930")
        self.root.minsize(1180, 760)
        self.root.configure(bg=self.BG)

        self.cipher_var = tk.StringVar(value="Caesar")
        self.operation_var = tk.StringVar(value="Encrypt")
        self.shift_var = tk.StringVar(value="3")
        self.key_var = tk.StringVar()
        self.key_length_var = tk.StringVar(value="7")
        self.status_var = tk.StringVar(value="SYSTEM READY")
        self.cipher_metric = tk.StringVar(value="CAESAR")
        self.length_metric = tk.StringVar(value="0")
        self.alpha_metric = tk.StringVar(value="0")
        self.mode_metric = tk.StringVar(value="IDLE")
        self.entropy_metric = tk.StringVar(value="--")
        self.keyspace_metric = tk.StringVar(value="26")
        self.busy = False
        self.last_result = {}
        self.last_operation = "GUI Analysis"
        self.audit_logger = AuditLogger()

        self._configure_styles()
        self._build_layout()
        self._update_fields()
        self._refresh_metrics()
        self._log("System initialized. Awaiting input.")

    # ---------- Styling ----------
    def _configure_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Cyber.TFrame", background=self.BG)
        style.configure("Cyber.TButton", background="#16253D", foreground=self.TEXT,
                        bordercolor=self.BORDER, padding=(12, 8), font=("Segoe UI", 9, "bold"))
        style.map("Cyber.TButton", background=[("active", "#244666")], foreground=[("active", self.CYAN)])
        style.configure("Primary.TButton", background="#12566C", foreground="#F0FDFF",
                        bordercolor=self.CYAN, padding=(13, 9), font=("Segoe UI", 9, "bold"))
        style.map("Primary.TButton", background=[("active", "#1A7890")])
        style.configure("Cyber.TCombobox", fieldbackground=self.FIELD, background="#17273C",
                        foreground=self.TEXT, arrowcolor=self.CYAN)
        style.map("Cyber.TCombobox", fieldbackground=[("readonly", self.FIELD)],
                  foreground=[("readonly", self.TEXT)])
        style.configure("Cyber.TEntry", fieldbackground=self.FIELD, foreground=self.TEXT,
                        insertcolor=self.CYAN)

    def _panel(self, parent, title, row, column, rowspan=1, columnspan=1, padx=6, pady=6):
        frame = tk.Frame(parent, bg=self.PANEL, highlightbackground=self.BORDER,
                         highlightthickness=1, bd=0)
        frame.grid(row=row, column=column, rowspan=rowspan, columnspan=columnspan,
                   sticky="nsew", padx=padx, pady=pady)
        frame.columnconfigure(0, weight=1)
        header = tk.Frame(frame, bg=self.PANEL, height=32)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.columnconfigure(0, weight=1)
        tk.Label(header, text=title, bg=self.PANEL, fg=self.CYAN,
                 font=("Consolas", 9, "bold"), anchor="w").grid(
                     row=0, column=0, sticky="w", padx=10)
        tk.Label(header, text="●", bg=self.PANEL, fg=self.GREEN,
                 font=("Consolas", 9, "bold")).grid(row=0, column=1, padx=10)
        return frame

    def _label(self, parent, text, row, column, columnspan=1):
        tk.Label(parent, text=text.upper(), bg=self.PANEL, fg=self.MUTED,
                 font=("Consolas", 8, "bold"), anchor="w").grid(
                     row=row, column=column, columnspan=columnspan, sticky="w",
                     padx=10, pady=(8, 4))

    def _metric_card(self, parent, column, title, variable, accent, subtitle):
        card = tk.Frame(parent, bg=self.PANEL, highlightbackground=self.BORDER,
                        highlightthickness=1, bd=0)
        card.grid(row=0, column=column, sticky="nsew", padx=5)
        tk.Frame(card, bg=accent, height=3).pack(fill="x")
        tk.Label(card, text=title, bg=self.PANEL, fg=self.MUTED,
                 font=("Consolas", 8, "bold"), anchor="w").pack(fill="x", padx=12, pady=(10, 1))
        tk.Label(card, textvariable=variable, bg=self.PANEL, fg=accent,
                 font=("Segoe UI", 17, "bold"), anchor="w").pack(fill="x", padx=12)
        tk.Label(card, text=subtitle, bg=self.PANEL, fg=self.MUTED,
                 font=("Consolas", 7), anchor="w").pack(fill="x", padx=12, pady=(1, 10))

    # ---------- Layout ----------
    def _build_layout(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        shell = tk.Frame(self.root, bg=self.BG)
        shell.grid(row=0, column=0, sticky="nsew")
        shell.columnconfigure(1, weight=1)
        shell.rowconfigure(0, weight=1)

        self._build_sidebar(shell)

        main = tk.Frame(shell, bg=self.BG)
        main.grid(row=0, column=1, sticky="nsew", padx=(0, 12), pady=10)
        main.columnconfigure(0, weight=1)
        # Give the result area more vertical space so long analysis output
        # and report summaries are easier to read.
        main.rowconfigure(3, weight=5)
        # Telemetry is placed in the sidebar in this layout.
        main.rowconfigure(5, weight=0)

        self._build_header(main)
        self._build_metrics(main)
        self._build_configuration(main)
        self._build_workspace(main)
        self._build_actions(main)
        self._build_bottom_workspace(main)
        self._build_statusbar(main)

    def _build_sidebar(self, parent):
        side = tk.Frame(parent, bg=self.SIDEBAR, width=180,
                        highlightbackground=self.BORDER, highlightthickness=1)
        side.grid(row=0, column=0, sticky="ns", padx=(10, 12), pady=10)
        side.grid_propagate(False)

        tk.Label(side, text="◈", bg=self.SIDEBAR, fg=self.CYAN,
                 font=("Segoe UI", 25, "bold")).pack(pady=(24, 0))
        tk.Label(side, text="CIPHER LAB", bg=self.SIDEBAR, fg=self.TEXT,
                 font=("Segoe UI", 11, "bold")).pack(pady=(2, 0))
        tk.Label(side, text="SECURITY WORKSTATION", bg=self.SIDEBAR, fg=self.MUTED,
                 font=("Consolas", 7)).pack(pady=(2, 28))

        nav_items = [
            ("01", "DASHBOARD", self.CYAN),
            ("02", "INPUT STREAM", self.BLUE),
            ("03", "FREQUENCY", self.GREEN),
            ("04", "RECOVERY", self.PURPLE),
            ("05", "AUDIT LOG", self.AMBER),
        ]
        for number, label, color in nav_items:
            item = tk.Frame(side, bg=self.SIDEBAR, height=42)
            item.pack(fill="x", padx=10, pady=3)
            tk.Label(item, text=number, bg=self.SIDEBAR, fg=color,
                     font=("Consolas", 8, "bold"), width=4, anchor="w").pack(side="left", padx=(8, 0))
            tk.Label(item, text=label, bg=self.SIDEBAR, fg=self.TEXT,
                     font=("Consolas", 8), anchor="w").pack(side="left")

        # Compact telemetry is kept in the sidebar so the main workspace
        # can dedicate more vertical space to input and analysis results.
        telemetry_title = tk.Frame(side, bg=self.SIDEBAR)
        telemetry_title.pack(fill="x", padx=12, pady=(18, 4))
        tk.Label(telemetry_title, text="SYSTEM TELEMETRY", bg=self.SIDEBAR,
                 fg=self.CYAN, font=("Consolas", 7, "bold"),
                 anchor="w").pack(side="left")
        tk.Label(telemetry_title, text="●", bg=self.SIDEBAR, fg=self.GREEN,
                 font=("Consolas", 7, "bold")).pack(side="right")

        self.terminal = ScrolledText(
            side, height=7, width=19, wrap="word", bg=self.FIELD,
            fg="#7FB5FF", insertbackground=self.CYAN,
            selectbackground="#164D69", relief="flat", borderwidth=0,
            font=("Consolas", 7), padx=5, pady=5
        )
        self.terminal.pack(fill="x", padx=10, pady=(0, 8))
        self.terminal.configure(state="disabled")

        spacer = tk.Frame(side, bg=self.SIDEBAR)
        spacer.pack(fill="both", expand=True)
        tk.Label(side, text="LOCAL PROCESSING", bg=self.SIDEBAR, fg=self.GREEN,
                 font=("Consolas", 8, "bold")).pack(pady=(0, 4))
        tk.Label(side, text="NO CLOUD TRANSFER", bg=self.SIDEBAR, fg=self.MUTED,
                 font=("Consolas", 7)).pack(pady=(0, 22))

    def _build_header(self, parent):
        header = tk.Frame(parent, bg=self.BG)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.columnconfigure(0, weight=1)
        tk.Label(header, text="CIPHER//COMMAND CENTER", bg=self.BG, fg=self.CYAN,
                 font=("Segoe UI", 24, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
        tk.Label(header, text="CLASSICAL CIPHER SECURITY ANALYSIS  /  INTELLIGENCE DASHBOARD",
                 bg=self.BG, fg=self.MUTED, font=("Consolas", 9), anchor="w").grid(
                     row=1, column=0, sticky="w", pady=(3, 0))
        right = tk.Frame(header, bg=self.BG)
        right.grid(row=0, column=1, rowspan=2, sticky="e")
        tk.Label(right, text="● LIVE ACTIVE", bg=self.BG, fg=self.GREEN,
                 font=("Consolas", 9, "bold")).pack(anchor="e")
        tk.Label(right, text="LOCAL ENGINE  /  PYTHON 3", bg=self.BG, fg=self.MUTED,
                 font=("Consolas", 8)).pack(anchor="e", pady=(4, 0))

    def _build_metrics(self, parent):
        metrics = tk.Frame(parent, bg=self.BG)
        metrics.grid(row=1, column=0, sticky="ew", pady=(0, 5))
        for i in range(6):
            metrics.columnconfigure(i, weight=1)
        self._metric_card(metrics, 0, "CIPHER MODULE", self.cipher_metric, self.CYAN, "ACTIVE MODULE")
        self._metric_card(metrics, 1, "INPUT LENGTH", self.length_metric, self.BLUE, "ALL CHARACTERS")
        self._metric_card(metrics, 2, "ALPHABETIC", self.alpha_metric, self.GREEN, "ANALYZABLE CHARS")
        self._metric_card(metrics, 3, "OPERATION", self.mode_metric, self.AMBER, "ENGINE STATE")
        self._metric_card(metrics, 4, "TEXT DIVERSITY", self.entropy_metric, self.PURPLE, "UNIQUE LETTERS")
        self._metric_card(metrics, 5, "KEYSPACE", self.keyspace_metric, self.RED, "PER KEY POSITION")

    def _build_configuration(self, parent):
        config = self._panel(parent, "01  ANALYSIS CONFIGURATION", 2, 0)
        for i in range(10):
            config.columnconfigure(i, weight=1 if i in (1, 3, 5, 7, 9) else 0)

        self._label(config, "Cipher", 1, 0)
        self.cipher_box = ttk.Combobox(config, textvariable=self.cipher_var,
                                       values=["Caesar", "Vigenere"], state="readonly",
                                       style="Cyber.TCombobox", width=14)
        self.cipher_box.grid(row=2, column=0, sticky="ew", padx=(10, 8), pady=(0, 10))
        self.cipher_box.bind("<<ComboboxSelected>>", lambda _event: self._update_fields())

        self._label(config, "Operation", 1, 2)
        self.operation_box = ttk.Combobox(config, textvariable=self.operation_var,
                                          values=["Encrypt", "Decrypt"], state="readonly",
                                          style="Cyber.TCombobox", width=14)
        self.operation_box.grid(row=2, column=2, sticky="ew", padx=(10, 8), pady=(0, 10))

        self.shift_label = tk.Label(config, text="SHIFT", bg=self.PANEL, fg=self.MUTED,
                                    font=("Consolas", 8, "bold"), anchor="w")
        self.shift_label.grid(row=1, column=4, sticky="w", padx=10, pady=(8, 4))
        self.shift_entry = ttk.Entry(config, textvariable=self.shift_var,
                                     style="Cyber.TEntry", width=12)
        self.shift_entry.grid(row=2, column=4, sticky="ew", padx=(10, 8), pady=(0, 10))

        self.key_label = tk.Label(config, text="KEY", bg=self.PANEL, fg=self.MUTED,
                                  font=("Consolas", 8, "bold"), anchor="w")
        self.key_label.grid(row=1, column=6, sticky="w", padx=10, pady=(8, 4))
        self.key_entry = ttk.Entry(config, textvariable=self.key_var,
                                   style="Cyber.TEntry", width=16)
        self.key_entry.grid(row=2, column=6, sticky="ew", padx=(10, 8), pady=(0, 10))

        self._label(config, "Recovery key length", 1, 8)
        self.recovery_length_entry = ttk.Entry(config, textvariable=self.key_length_var,
                                               style="Cyber.TEntry", width=10)
        self.recovery_length_entry.grid(row=2, column=8, sticky="ew", padx=(10, 8), pady=(0, 10))
        tk.Label(config, text="Existing backend limits preserved", bg=self.PANEL, fg=self.MUTED,
                 font=("Consolas", 8)).grid(row=2, column=9, sticky="e", padx=10, pady=(0, 10))

    def _build_workspace(self, parent):
        """Create a two-column analysis workspace.

        Left column: input stream above the frequency monitor.
        Right column: tall primary result console spanning both left panels.
        """
        workspace = tk.Frame(parent, bg=self.BG)
        workspace.grid(row=3, column=0, sticky="nsew")
        workspace.columnconfigure(0, weight=3)
        workspace.columnconfigure(1, weight=2)
        # Give the input stream more room; keep the frequency monitor
        # directly below it as a compact analysis panel.
        workspace.rowconfigure(0, weight=5)
        workspace.rowconfigure(1, weight=3)

        # Left-top: input stream
        input_panel = self._panel(workspace, "02  INPUT STREAM", 0, 0)
        input_panel.rowconfigure(1, weight=1)
        input_panel.columnconfigure(0, weight=1)
        self.input_text = ScrolledText(
            input_panel, height=8, wrap="word", bg=self.FIELD,
            fg=self.TEXT, insertbackground=self.CYAN,
            selectbackground="#164D69", relief="flat", borderwidth=0,
            font=("Consolas", 11), padx=12, pady=12
        )
        self.input_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 8))
        self.input_text.bind("<KeyRelease>", lambda _event: self._refresh_metrics())
        tk.Label(
            input_panel, text="PASTE OR TYPE YOUR PLAINTEXT / CIPHERTEXT",
            bg=self.PANEL, fg=self.MUTED, font=("Consolas", 7)
        ).grid(row=2, column=0, sticky="w", padx=10, pady=(0, 8))

        # Left-bottom: frequency monitor
        chart_panel = self._panel(workspace, "03  FREQUENCY MONITOR", 1, 0)
        chart_panel.rowconfigure(1, weight=1)
        chart_panel.columnconfigure(0, weight=1)
        self.chart = tk.Canvas(
            chart_panel, bg=self.FIELD, highlightthickness=0, height=155
        )
        self.chart.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 8))
        self.chart.bind("<Configure>", lambda _event: self._draw_frequency_chart())
        tk.Label(
            chart_panel, text="REAL LETTER COUNTS  /  A-Z DISTRIBUTION",
            bg=self.PANEL, fg=self.MUTED, font=("Consolas", 7)
        ).grid(row=2, column=0, sticky="w", padx=10, pady=(0, 8))

        # Right: tall result console, spanning input and frequency panels
        result_panel = self._panel(
            workspace, "04  RESULT CONSOLE  /  PRIMARY OUTPUT",
            0, 1, rowspan=2
        )
        result_panel.rowconfigure(1, weight=1)
        result_panel.columnconfigure(0, weight=1)
        self.result_text = ScrolledText(
            result_panel, height=22, wrap="word", bg=self.FIELD,
            fg=self.GREEN, insertbackground=self.CYAN,
            selectbackground="#164D69", relief="flat", borderwidth=0,
            font=("Consolas", 11), padx=14, pady=12,
            spacing1=2, spacing3=2
        )
        self.result_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.result_text.configure(state="disabled")

    def _build_actions(self, parent):
        action_bar = tk.Frame(parent, bg=self.BG)
        action_bar.grid(row=4, column=0, sticky="ew", pady=8)
        buttons = [
            ("▶  ENCRYPT / DECRYPT", self.process_text, "Primary.TButton"),
            ("⌁  CAESAR ANALYSIS", self.run_caesar_analysis, "Cyber.TButton"),
            ("⌁  VIGENERE RECOVERY", self.run_vigenere_recovery, "Cyber.TButton"),
            ("◈  AUTO DETECTION", self.run_automatic_detection, "Primary.TButton"),
            ("⌗  KEY LENGTHS", self.run_key_length_analysis, "Cyber.TButton"),
            ("↺  CLEAR", self.clear_all, "Cyber.TButton"),
            ("⇩  SAVE RESULT", self.save_result, "Cyber.TButton"),
            ("▣  GENERATE REPORT", self.generate_report, "Cyber.TButton"),
        ]
        for text, command, style in buttons:
            ttk.Button(action_bar, text=text, command=command, style=style).pack(side="left", padx=(0, 8))
        tk.Label(action_bar, text="ANALYSIS ENGINE ONLINE", bg=self.BG, fg=self.GREEN,
                 font=("Consolas", 8, "bold")).pack(side="right", padx=5)

    def _build_bottom_workspace(self, parent):
        """Telemetry is rendered in the sidebar for a cleaner main workspace."""
        return

    def _build_statusbar(self, parent):
        status = tk.Frame(parent, bg=self.PANEL, highlightbackground=self.BORDER,
                          highlightthickness=1, height=32)
        status.grid(row=6, column=0, sticky="ew", pady=(8, 0))
        status.grid_propagate(False)
        status.columnconfigure(0, weight=1)
        tk.Label(status, textvariable=self.status_var, bg=self.PANEL, fg=self.GREEN,
                 font=("Consolas", 8, "bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=12)
        tk.Label(status, text="LOCAL PROCESSING   |   CLASSICAL CIPHER LAB", bg=self.PANEL,
                 fg=self.MUTED, font=("Consolas", 7), anchor="e").grid(row=0, column=1, sticky="e", padx=12)

    # ---------- Helpers ----------
    def _update_fields(self):
        is_caesar = self.cipher_var.get() == "Caesar"
        if is_caesar:
            self.shift_label.grid()
            self.shift_entry.grid()
            self.key_label.grid_remove()
            self.key_entry.grid_remove()
            self.keyspace_metric.set("26")
        else:
            self.shift_label.grid_remove()
            self.shift_entry.grid_remove()
            self.key_label.grid()
            self.key_entry.grid()
            self.keyspace_metric.set("26^k")
        self.cipher_metric.set(self.cipher_var.get().upper())
        self._log(f"Cipher module selected: {self.cipher_var.get()}")

    def _get_input(self):
        return self.input_text.get("1.0", "end-1c")

    def _show_result(self, text):
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", text)
        self.result_text.configure(state="disabled")

    def _log(self, message):
        def write():
            if not hasattr(self, "terminal"):
                return
            self.terminal.configure(state="normal")
            self.terminal.insert("end", f"[SYSTEM] {message}\n")
            self.terminal.see("end")
            self.terminal.configure(state="disabled")
        self.root.after(0, write)

    def _set_status(self, status, mode=None):
        self.status_var.set(status)
        if mode:
            self.mode_metric.set(mode)

    def _refresh_metrics(self):
        if not hasattr(self, "input_text"):
            return
        text = self._get_input()
        letters = re.findall(r"[A-Za-z]", text)
        unique = len(set(ch.upper() for ch in letters))
        self.length_metric.set(str(len(text)))
        self.alpha_metric.set(str(len(letters)))
        self.entropy_metric.set(str(unique))
        self._draw_frequency_chart()

    def _draw_frequency_chart(self):
        if not hasattr(self, "chart"):
            return
        self.chart.delete("all")
        text = self._get_input() if hasattr(self, "input_text") else ""
        counts = Counter(ch.upper() for ch in text if ch.isalpha() and ch.isascii())
        width = max(self.chart.winfo_width(), 300)
        height = max(self.chart.winfo_height(), 180)
        left, right, top, bottom = 26, 12, 24, 30
        plot_w = width - left - right
        plot_h = height - top - bottom
        max_count = max(counts.values(), default=1)

        for tick in range(1, 4):
            y = top + plot_h - (tick / 3) * plot_h
            self.chart.create_line(left, y, width - right, y, fill=self.GRID, dash=(2, 4))

        self.chart.create_line(left, top + plot_h, width - right, top + plot_h, fill=self.BORDER)
        bar_w = max(plot_w / 26 - 3, 3)
        for index, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
            count = counts.get(letter, 0)
            x0 = left + index * (plot_w / 26) + 2
            x1 = x0 + bar_w
            y1 = top + plot_h - (count / max_count) * (plot_h - 8)
            fill = self.CYAN if count else "#18283C"
            self.chart.create_rectangle(x0, y1, x1, top + plot_h, fill=fill, outline="")
            self.chart.create_text((x0 + x1) / 2, top + plot_h + 12, text=letter,
                                   fill=self.MUTED, font=("Consolas", 7))
        self.chart.create_text(left, 9, anchor="w", text="LETTER DISTRIBUTION",
                               fill=self.MUTED, font=("Consolas", 8))
        self.chart.create_text(width - right, 9, anchor="e", text=f"MAX: {max_count}",
                               fill=self.MUTED, font=("Consolas", 8))

    def _validate_input(self):
        text = self._get_input()
        if not text.strip():
            messagebox.showwarning("Missing input", "Please enter text first.")
            return None
        return text

    # ---------- Operations ----------
    def process_text(self):
        if self.busy:
            return
        text = self._validate_input()
        if text is None:
            return
        try:
            if self.cipher_var.get() == "Caesar":
                shift = int(self.shift_var.get())
                result = (caesar_encrypt_text(text, shift) if self.operation_var.get() == "Encrypt"
                          else caesar_decrypt_text(text, shift))
                detail = f"Caesar {self.operation_var.get().lower()} completed with shift {shift}."
            else:
                key = self.key_var.get().strip()
                if not key.isalpha():
                    raise ValueError("Vigenere key must contain alphabetic characters only.")
                result = (vigenere_encrypt_text(text, key) if self.operation_var.get() == "Encrypt"
                          else vigenere_decrypt_text(text, key))
                detail = f"Vigenere {self.operation_var.get().lower()} completed."
            self._show_result(result)
            self.last_result = {
                "operation": self.operation_var.get(),
                "cipher_type": self.cipher_var.get(),
                "encrypted_or_decrypted_text": result,
            }
            self.last_operation = f"{self.cipher_var.get()} {self.operation_var.get()}"
            self.audit_logger.log("Text operation completed", detail, "SUCCESS")
            self._set_status("OPERATION COMPLETE", "COMPLETE")
            self._log(detail)
        except Exception as exc:
            messagebox.showerror("Operation error", str(exc))
            self._set_status("OPERATION FAILED", "ERROR")
            self._log(f"Operation error: {exc}")

    def run_caesar_analysis(self):
        if self.busy:
            return
        text = self._validate_input()
        if text is None:
            return
        self.busy = True
        self._set_status("CAESAR ANALYSIS RUNNING", "PROCESSING")
        self._show_result("Running automatic Caesar analysis...\nPlease wait.\n")
        self._log("Automatic Caesar analysis started.")
        threading.Thread(target=self._caesar_worker, args=(text,), daemon=True).start()

    def _caesar_worker(self, text):
        try:
            result = automatic_caesar_analysis(text)
            self.last_result = dict(result) if isinstance(result, dict) else {"result": result}
            self.last_result["cipher_type"] = "Caesar"
            self.last_result["operation"] = "Automatic Caesar Analysis"
            self.last_operation = "Automatic Caesar Analysis"
            self.audit_logger.log("Caesar analysis completed", "All 26 shifts evaluated", "SUCCESS")
            output = "AUTOMATIC CAESAR ANALYSIS\n" + "=" * 34 + "\n" + str(result)
            self.root.after(0, lambda: self._show_result(output))
            self.root.after(0, lambda: self._set_status("CAESAR ANALYSIS COMPLETE", "COMPLETE"))
            self._log("Automatic Caesar analysis completed.")
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Analysis error", str(exc)))
            self.root.after(0, lambda: self._set_status("CAESAR ANALYSIS FAILED", "ERROR"))
            self._log(f"Caesar analysis error: {exc}")
        finally:
            self.root.after(0, lambda: setattr(self, "busy", False))

    def run_vigenere_recovery(self):
        if self.busy:
            return
        text = self._validate_input()
        if text is None:
            return
        try:
            key_length = int(self.key_length_var.get())
            if key_length < 1:
                raise ValueError("Key length must be positive.")
        except ValueError as exc:
            messagebox.showerror("Invalid key length", str(exc))
            return

        self.busy = True
        self._set_status("VIGENERE RECOVERY RUNNING", "PROCESSING")
        self._show_result("Running Vigenere recovery...\nThis may take time.\n")
        self._log(f"Vigenere recovery started for key length {key_length}.")
        threading.Thread(target=self._vigenere_worker, args=(text, key_length), daemon=True).start()

    def _vigenere_worker(self, text, key_length):
        try:
            candidates = recover_key_candidates(text, key_length, top_n=10)
            result = search_best_key(text, candidates, max_combinations=3000000, screening_limit=1000)
            self.last_result = dict(result) if isinstance(result, dict) else {"result": result}
            self.last_result["cipher_type"] = "Vigenere"
            self.last_result["operation"] = "Automatic Vigenere Recovery"
            self.last_result["key_length"] = key_length
            self.last_operation = "Automatic Vigenere Recovery"
            self.audit_logger.log(
                "Vigenere recovery completed",
                f"Key length: {key_length}; combinations tested: {result.get('combinations_tested', 'N/A')}",
                "SUCCESS",
            )
            output = (
                "AUTOMATIC VIGENERE RECOVERY\n"
                + "=" * 36
                + "\n"
                + f"Key length: {key_length}\n"
                + f"Recovered key: {result.get('key')}\n"
                + f"Plaintext: {result.get('plaintext')}\n"
                + f"Score: {result.get('score')}\n"
                + f"Combinations tested: {result.get('combinations_tested')}\n"
                + f"Shortlisted candidates: {result.get('shortlisted_candidates')}\n"
            )
            self.root.after(0, lambda: self._show_result(output))
            self.root.after(0, lambda: self._set_status("VIGENERE RECOVERY COMPLETE", "COMPLETE"))
            self._log("Vigenere recovery completed.")
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Recovery error", str(exc)))
            self.root.after(0, lambda: self._set_status("VIGENERE RECOVERY FAILED", "ERROR"))
            self._log(f"Vigenere recovery error: {exc}")
        finally:
            self.root.after(0, lambda: setattr(self, "busy", False))

    def run_key_length_analysis(self):
        """Display the real IC-based Vigenere key-length ranking."""
        if self.busy:
            return
        text = self._validate_input()
        if text is None:
            return
        try:
            max_key_length = int(self.key_length_var.get())
            if max_key_length < 1:
                raise ValueError("Maximum key length must be positive.")
        except ValueError as exc:
            messagebox.showerror("Invalid key length", str(exc))
            return

        self.busy = True
        self._set_status("KEY LENGTH ANALYSIS RUNNING", "PROCESSING")
        self._show_result("VIGENERE KEY-LENGTH ANALYSIS\n" + "=" * 36 + "\nPlease wait...\n")
        self._log(f"Key-length analysis started up to length {max_key_length}.")
        threading.Thread(
            target=self._key_length_worker,
            args=(text, max_key_length),
            daemon=True,
        ).start()

    def _key_length_worker(self, text, max_key_length):
        try:
            results = rank_key_lengths(text, max_key_length)
            top_results = results[:10]
            lines = [
                "VIGENERE KEY-LENGTH ANALYSIS",
                "=" * 36,
                f"Maximum key length: {max_key_length}",
                "",
                "Rank | Key Length | Average IC",
                "-" * 36,
            ]
            for rank, item in enumerate(top_results, start=1):
                lines.append(
                    f"{rank:>4} | {item.get('key_length', 'N/A'):>10} | "
                    f"{item.get('average_ic', 0.0):.6f}"
                )
            if not top_results:
                lines.append("No key-length results were produced.")
            self.last_result = {
                "operation": "Vigenere Key-Length Analysis",
                "cipher_type": "Vigenere",
                "max_key_length": max_key_length,
                "key_length_results": top_results,
            }
            self.last_operation = "Vigenere Key-Length Analysis"
            self.audit_logger.log(
                "Key-length analysis completed",
                f"Maximum key length: {max_key_length}",
                "SUCCESS",
            )
            output = "\n".join(lines) + "\n\nNote: IC ranking is statistical evidence, not proof of the key length."
            self.root.after(0, lambda output=output: self._show_result(output))
            self.root.after(0, lambda: self._set_status("KEY LENGTH ANALYSIS COMPLETE", "COMPLETE"))
            self._log("Key-length analysis completed.")
        except Exception as exc:
            self.root.after(0, lambda exc=exc: messagebox.showerror("Key-length analysis error", str(exc)))
            self.root.after(0, lambda: self._set_status("KEY LENGTH ANALYSIS FAILED", "ERROR"))
            self._log(f"Key-length analysis error: {exc}")
        finally:
            self.root.after(0, lambda: setattr(self, "busy", False))

    def run_automatic_detection(self):
        """Run the same bounded automatic detection workflow used by main.py."""
        if self.busy:
            return
        text = self._validate_input()
        if text is None:
            return
        try:
            max_key_length = int(self.key_length_var.get())
            if max_key_length < 1:
                raise ValueError("Maximum key length must be positive.")
        except ValueError as exc:
            messagebox.showerror("Invalid key length", str(exc))
            return

        self.busy = True
        self._set_status("AUTOMATIC DETECTION RUNNING", "PROCESSING")
        self._show_result("INTELLIGENT AUTOMATIC CIPHER ANALYSIS\n" + "=" * 42 + "\nPlease wait...\n")
        self._log("Intelligent automatic cipher analysis started.")
        threading.Thread(
            target=self._automatic_detection_worker,
            args=(text, max_key_length),
            daemon=True,
        ).start()

    def _automatic_detection_worker(self, ciphertext, max_key_length):
        try:
            letter_count = sum(1 for character in ciphertext if character.isalpha())
            caesar_result = automatic_caesar_analysis(ciphertext)
            caesar_plaintext = ""
            caesar_shift = None
            caesar_score = float("-inf")
            if caesar_result.get("success"):
                caesar_plaintext = caesar_result.get("recovered_text", "")
                caesar_shift = caesar_result.get("estimated_shift")
                caesar_score = fast_english_score(caesar_plaintext)

            key_length_results = rank_key_lengths(ciphertext, max_key_length)
            top_key_lengths = [item["key_length"] for item in key_length_results[:3]]
            candidate_count = 10
            max_combinations = 3_000_000
            screening_limit = 1000
            attempts = []
            best_vigenere_result = None
            best_vigenere_score = float("-inf")

            for key_length in top_key_lengths:
                total_combinations = candidate_count ** key_length
                search_limit = min(total_combinations, max_combinations)
                try:
                    candidate_data = recover_key_candidates(
                        ciphertext=ciphertext,
                        key_length=key_length,
                        top_n=candidate_count,
                    )
                    result = search_best_key(
                        ciphertext=ciphertext,
                        candidate_data=candidate_data,
                        max_combinations=search_limit,
                        screening_limit=screening_limit,
                    )
                    if result is None:
                        continue
                    plaintext = result.get("plaintext", "")
                    comparable_score = fast_english_score(plaintext)
                    plausibility = evaluate_plaintext_plausibility(plaintext)
                    combinations_tested = result.get("combinations_tested", search_limit)
                    limit_reached = total_combinations > search_limit and combinations_tested >= search_limit
                    attempts.append({
                        "key_length": key_length,
                        "key": result.get("key", ""),
                        "plaintext": plaintext,
                        "score": comparable_score,
                        "search_score": result.get("score", 0.0),
                        "combinations_tested": combinations_tested,
                        "total_combinations": total_combinations,
                        "search_limit": search_limit,
                        "search_limit_reached": limit_reached,
                        "plausibility_status": plausibility.get("status", "Unverified"),
                        "confidence": plausibility.get("confidence", "Low"),
                    })
                    if comparable_score > best_vigenere_score:
                        best_vigenere_score = comparable_score
                        best_vigenere_result = dict(result)
                        best_vigenere_result.update({
                            "comparable_score": comparable_score,
                            "tested_key_length": key_length,
                            "plausibility": plausibility,
                            "total_combinations": total_combinations,
                            "search_limit": search_limit,
                            "search_limit_reached": limit_reached,
                        })
                except Exception as error:
                    self._log(f"Skipped Vigenere key length {key_length}: {error}")

            if best_vigenere_result is None and not caesar_result.get("success"):
                raise RuntimeError("Unable to produce an automatic analysis result.")

            confidence, recovery_status, verification_status = get_analysis_confidence(letter_count)
            if best_vigenere_result is not None and best_vigenere_score > caesar_score:
                detected_type = "VIGENERE"
                recovered_key = best_vigenere_result.get("key", "")
                recovered_plaintext = best_vigenere_result.get("plaintext", "")
                selected_score = best_vigenere_score
                plausibility = best_vigenere_result.get("plausibility", {})
                verification_status = plausibility.get("status", verification_status)
            else:
                detected_type = "CAESAR"
                recovered_key = f"Shift {caesar_shift}" if caesar_shift is not None else "Not available"
                recovered_plaintext = caesar_plaintext
                selected_score = caesar_score
                plausibility = evaluate_plaintext_plausibility(recovered_plaintext)
                verification_status = plausibility.get("status", verification_status)

            result_payload = {
                "detected_type": detected_type,
                "recovered_key_or_shift": recovered_key,
                "plaintext": recovered_plaintext,
                "comparable_english_score": selected_score,
                "tested_vigenere_key_lengths": top_key_lengths,
                "detection_status": "Statistical Estimate",
                "recovery_status": recovery_status,
                "verification_status": verification_status,
                "analysis_confidence": confidence,
                "letter_count": letter_count,
                "plaintext_plausibility": plausibility,
                "vigenere_attempts": attempts,
            }
            self.last_result = result_payload
            self.last_operation = "Intelligent Automatic Cipher Analysis"
            self.audit_logger.log("Automatic detection completed", f"Estimated type: {detected_type}", "SUCCESS")

            evidence = "\n".join(
                f"{index}. Length {item['key_length']} | Average IC: {item.get('average_ic', 'N/A')}"
                for index, item in enumerate(key_length_results[:3], start=1)
            ) or "No key-length evidence available."
            output = (
                "INTELLIGENT AUTOMATIC CIPHER ANALYSIS\n"
                + "=" * 42
                + f"\nDetected type: {detected_type}"
                + f"\nRecovery status: {recovery_status}"
                + f"\nVerification status: {verification_status}"
                + f"\nAnalysis confidence: {confidence}"
                + f"\nRecovered key / shift: {recovered_key}"
                + f"\nComparable English score: {selected_score:.4f}"
                + "\n\nRecovered plaintext:\n"
                + recovered_plaintext
                + "\n\nVigenere key-length evidence:\n"
                + evidence
                + "\n\nNote: This is a statistical estimate. Manual verification is required.\n"
            )
            self.root.after(0, lambda output=output: self._show_result(output))
            self.root.after(0, lambda: self._set_status("AUTOMATIC DETECTION COMPLETE", "COMPLETE"))
            self._log("Automatic detection completed.")
        except Exception as exc:
            self.root.after(0, lambda exc=exc: messagebox.showerror("Automatic detection error", str(exc)))
            self.root.after(0, lambda: self._set_status("AUTOMATIC DETECTION FAILED", "ERROR"))
            self._log(f"Automatic detection error: {exc}")
        finally:
            self.root.after(0, lambda: setattr(self, "busy", False))

    def clear_all(self):
        self.input_text.delete("1.0", "end")
        self._show_result("")
        self._set_status("SYSTEM READY", "IDLE")
        self._refresh_metrics()
        self._log("Input and result panels cleared.")

    def generate_report(self):
        """Generate redacted HTML, text, JSON, and audit reports from the latest result."""
        text = self._get_input()
        if not text.strip():
            messagebox.showwarning("Missing input", "Enter text before generating a report.")
            return
        if not self.last_result:
            messagebox.showwarning(
                "No analysis result",
                "Run encryption/decryption or an analysis operation before generating a report.",
            )
            return

        def redact(value):
            sensitive = {
                "key", "recovered_key", "plaintext", "recovered_plaintext",
                "encrypted_or_decrypted_text", "ciphertext", "shift",
            }
            if isinstance(value, dict):
                return {
                    key: "[REDACTED]" if key.lower() in sensitive else redact(item)
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [redact(item) for item in value]
            return value

        safe_result = redact(self.last_result)
        cipher_type = self.last_result.get("detected_type", self.cipher_var.get())
        findings = [
            "The result is based on the existing cipher implementation and statistical analysis where applicable.",
            "Sensitive key and plaintext fields are redacted in this GUI-generated report.",
        ]
        limitations = [
            "Cipher identification and plaintext plausibility are not guaranteed.",
            "Short or unusual ciphertexts may produce unreliable statistical results.",
            "Recovered results should be manually verified.",
        ]
        configuration = {
            "gui_operation": self.last_operation,
            "cipher_type": cipher_type,
            "vigenere_recovery_key_length": self.key_length_var.get(),
            "vigenere_max_combinations": 3000000,
            "vigenere_screening_limit": 1000,
        }
        alphabetic_count = sum(1 for char in text if char.isalpha())
        report = SecurityReport(
            operation=self.last_operation,
            cipher_type=cipher_type,
            ciphertext_length=len(text),
            letter_count=alphabetic_count,
            result=safe_result,
            findings=findings,
            limitations=limitations,
            audit_events=self.audit_logger.to_dict(),
            configuration=configuration,
            security_assessment=(
                "Classical cipher analysis; heuristic assessment based on algorithm and sample length."
            ),
            strength_rating=("Very Weak" if cipher_type == "Caesar" else "Context Dependent"),
        )
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_directory = Path("reports")
        try:
            html_path = report.save_html(output_directory / f"gui_security_report_{timestamp}.html")
            text_path = report.save_text(output_directory / f"gui_security_report_{timestamp}.txt")
            json_path = report.save_json(output_directory / f"gui_security_report_{timestamp}.json")
            audit_path = self.audit_logger.save_json(output_directory / f"gui_audit_log_{timestamp}.json")
            self._set_status("REPORT GENERATED", "COMPLETE")
            self._log("Security report and audit log generated.")
            messagebox.showinfo(
                "Report generated",
                "Reports saved successfully:\n\n"
                f"HTML: {html_path}\n"
                f"Text: {text_path}\n"
                f"JSON: {json_path}\n"
                f"Audit: {audit_path}",
            )
        except OSError as exc:
            self._set_status("REPORT GENERATION FAILED", "ERROR")
            self._log(f"Report generation error: {exc}")
            messagebox.showerror("Report error", str(exc))

    def save_result(self):
        content = self.result_text.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showwarning("No result", "There is no result to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as file:
                    file.write(content)
                self._set_status("RESULT SAVED", "COMPLETE")
                self._log(f"Result saved to: {path}")
            except OSError as exc:
                messagebox.showerror("Save error", str(exc))
                self._log(f"Save error: {exc}")


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberCipherGUI(root)
    root.mainloop()
