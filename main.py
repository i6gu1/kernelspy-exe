import os
import sys
import threading
import queue
import json
import webbrowser
from pathlib import Path
import customtkinter as ctk
from tkinter import filedialog, Menu
from core import Scanner, Finding, export_csv, export_html, export_json, export_sarif
from core.engine.ai_analyzer import AIConfig, ChatMessage
from core.engine.tree_sitter_parser import is_tree_sitter_available
from core.engine.sast_orchestrator import get_sast_orchestrator

# ──────────────────────── APP CONFIG ────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

ACCENT      = "#0ea5e9"
ACCENT_DIM  = "#075985"
ACCENT_LIGHT = "#38bdf8"
BG_DARK     = "#0a0a0f"
BG_CARD     = "#12121a"
BG_SIDEBAR  = "#06060a"
BG_HOVER    = "#1a1a25"
CLR_TEXT    = "#f1f5f9"
CLR_TEXT2   = "#94a3b8"
CLR_DANGER  = "#f43f5e"
CLR_WARNING = "#f97316"
CLR_MEDIUM  = "#eab308"
CLR_SUCCESS = "#22c55e"
FOOTER_TEXT = "Programmed by The L house"
VERSION = "1.2.0"

LANGS = {
    "en": {
        "title": "KernelSpy Scanner", "subtitle": "Detect leaked secrets and security vulnerabilities",
        "scan": "Scan", "results": "Results", "reports": "Reports", "settings": "Settings",
        "ai_chat": "AI Chat", "tree_sitter": "Tree-sitter",
        "drag_drop": "Drag your project folder here", "or_browse": "or click to browse",
        "start_scan": "Start Scan", "scanning": "Scanning...", "clear": "Clear",
        "export_csv": "Export CSV", "export_html": "Export HTML", "export_json": "Export JSON", "export_sarif": "Export SARIF",
        "total": "Total", "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
        "found_issues": "issues found", "no_results": "No results yet",
        "output_dir": "Output Directory", "version": "Version",
        "file": "File", "line": "Line", "threat": "Threat Type",
        "description": "Description", "severity": "Severity",
        "category": "Category", "analyzer": "Analyzer",
        "no_data": "No data to export", "done": "Report saved", "fail": "Export failed",
        "ready": "Ready", "complete": "Complete", "select_folder": "Select Project Folder",
        "ai_title": "AI Security Assistant", "ai_subtitle": "Analyze code with AI",
        "google_api_key": "Google AI Studio API Key", "gguf_model": "GGUF Model Path",
        "load_model": "Load Model", "unload_model": "Unload Model",
        "model_status": "Model Status", "model_loaded": "Loaded", "model_not_loaded": "Not Loaded",
        "chat_placeholder": "Ask about code security...", "send": "Send", "clear_chat": "Clear Chat",
        "analyze_findings": "Analyze Findings with AI", "ai_analyzing": "AI is analyzing...",
        "ts_title": "Tree-sitter Multi-Language Parser", "ts_supported": "Supported Languages",
        "ts_available": "Tree-sitter Available", "ts_not_available": "Tree-sitter Not Available",
        "sast_engines": "SAST Engines", "semgrep": "Semgrep", "trivy": "Trivy", "sonar": "SonarScanner",
        "engine_available": "Available", "engine_not_available": "Not Available",
        "enable_sast": "Enable External SAST Engines",
        "settings_title": "Settings", "save_settings": "Save Settings",
        "settings_saved": "Settings saved successfully",
        "provider_google": "Google AI Studio", "provider_gguf": "Local GGUF Model",
        "analyze_code": "Analyze Code", "paste_code": "Paste code here...",
        "language": "Language", "context": "Context (optional)",
    },
    "ar": {
        "title": "KernelSpy Scanner", "subtitle": "كشف الأسرار المتسربة والثغرات الأمنية",
        "scan": "الفحص", "results": "النتائج", "reports": "التقارير", "settings": "الإعدادات",
        "ai_chat": "المحادثة الذكية", "tree_sitter": "شجرة القواعد",
        "drag_drop": "اسحب مجلد مشروعك هنا", "or_browse": "أو اضغط للتصفح",
        "start_scan": "بدء الفحص", "scanning": "جاري الفحص...", "clear": "مسح",
        "export_csv": "تصدير CSV", "export_html": "تصدير HTML", "export_json": "تصدير JSON", "export_sarif": "تصدير SARIF",
        "total": "الإجمالي", "critical": "حرج", "high": "عالي", "medium": "متوسط", "low": "منخفض",
        "found_issues": "مشكلات", "no_results": "لا توجد نتائج",
        "output_dir": "مجلد الإخراج", "version": "الإصدار",
        "file": "الملف", "line": "السطر", "threat": "التهديد",
        "description": "الشرح", "severity": "الخطورة",
        "category": "الفئة", "analyzer": "المحلل",
        "no_data": "لا توجد بيانات", "done": "تم الحفظ", "fail": "فشل التصدير",
        "ready": "جاهز", "complete": "مكتمل", "select_folder": "اختر مجلد المشروع",
        "ai_title": "مساعد الأمان الذكي", "ai_subtitle": "تحليل الكود بالذكاء الاصطناعي",
        "google_api_key": "مفتاح Google AI Studio", "gguf_model": "مسار ملف GGUF",
        "load_model": "تحميل النموذج", "unload_model": "إلغاء تحميل النموذج",
        "model_status": "حالة النموذج", "model_loaded": "تم التحميل", "model_not_loaded": "غير محمل",
        "chat_placeholder": "اسأل عن أمان الكود...", "send": "إرسال", "clear_chat": "مسح المحادثة",
        "analyze_findings": "تحليل النتائج بالذكاء الاصطناعي", "ai_analyzing": "الذكاء الاصطناعي يحلل...",
        "ts_title": "محلل شجرة القواعد الموحدة", "ts_supported": "اللغات المدعومة",
        "ts_available": "شجرة القواعد متاحة", "ts_not_available": "شجرة القواعد غير متاحة",
        "sast_engines": "محركات الفحص", "semgrep": "Semgrep", "trivy": "Trivy", "sonar": "SonarScanner",
        "engine_available": "متاح", "engine_not_available": "غير متاح",
        "enable_sast": "تفعيل محركات الفحص الخارجية",
        "settings_title": "الإعدادات", "save_settings": "حفظ الإعدادات",
        "settings_saved": "تم حفظ الإعدادات بنجاح",
        "provider_google": "Google AI Studio", "provider_gguf": "نموذج محلي GGUF",
        "analyze_code": "تحليل الكود", "paste_code": "الصق الكود هنا...",
        "language": "اللغة", "context": "السياق (اختياري)",
    },
}


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("KernelSpy Scanner")
        self.geometry("1280x800")
        self.minsize(950, 620)
        self.configure(fg_color=BG_DARK)

        icon_path = self._resource_path("icon.ico")
        if os.path.exists(icon_path):
            self.iconbitmap(icon_path)

        self.lang = LANGS["en"]
        self.lang_code = "en"
        self.scanner = Scanner()
        self.results = []
        self.scanning = False
        self._cancel = False
        self.output_dir = str(Path.home() / "KernelSpy_Output")
        os.makedirs(self.output_dir, exist_ok=True)

        # AI config
        self.ai_config = AIConfig()
        self._load_settings()

        self._build_sidebar()
        self._build_pages()
        self.show_page("home")
        
        # Enable copy/paste keyboard shortcuts
        self._setup_copy_paste()

        if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
            target = sys.argv[1]
            self.after(300, lambda: (self.show_page("scan"), self._start_scan(target)))

    def _resource_path(self, rel):
        base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, rel)

    def _setup_copy_paste(self):
        """Setup copy/paste keyboard shortcuts and context menus."""
        # Global keyboard shortcuts
        self.bind('<Control-c>', self._copy_selection)
        self.bind('<Control-v>', self._paste_from_clipboard)
        self.bind('<Control-a>', self._select_all)
        self.bind('<Control-C>', self._copy_selection)
        self.bind('<Control-V>', self._paste_from_clipboard)
        self.bind('<Control-A>', self._select_all)

    def _copy_selection(self, event=None):
        """Copy selected text to clipboard."""
        try:
            widget = self.focus_get()
            if widget:
                if hasattr(widget, 'selection_present') and widget.selection_present():
                    selected = widget.selection_get()
                    self.clipboard_clear()
                    self.clipboard_append(selected)
                elif hasattr(widget, 'get'):
                    # For CTkEntry, copy all text
                    content = widget.get()
                    if content:
                        self.clipboard_clear()
                        self.clipboard_append(content)
        except Exception:
            pass

    def _paste_from_clipboard(self, event=None):
        """Paste text from clipboard."""
        try:
            widget = self.focus_get()
            if widget and hasattr(widget, 'insert'):
                try:
                    text = self.clipboard_get()
                    if text:
                        # If there's a selection, replace it
                        if hasattr(widget, 'selection_present') and widget.selection_present():
                            try:
                                widget.delete("sel.first", "sel.last")
                            except Exception:
                                pass
                        widget.insert("insert", text)
                except Exception:
                    pass
        except Exception:
            pass

    def _select_all(self, event=None):
        """Select all text in focused widget."""
        try:
            widget = self.focus_get()
            if widget:
                if hasattr(widget, 'tag_add'):
                    widget.tag_add("sel", "1.0", "end")
                elif hasattr(widget, 'select_range'):
                    widget.select_range(0, 'end')
        except Exception:
            pass

    def _copy_results_to_clipboard(self):
        """Copy all scan results to clipboard."""
        if not self.results:
            return
        lines = []
        for r in self.results:
            lines.append(f"{r.file}:{r.line} | {r.severity} | {r.type} | {r.description}")
        self.clipboard_clear()
        self.clipboard_append('\n'.join(lines))

    def _add_context_menu(self, widget):
        """Add right-click context menu to a widget."""
        menu = Menu(widget, tearoff=0)
        menu.add_command(label="Copy", command=lambda: self._copy_selection())
        menu.add_command(label="Paste", command=lambda: self._paste_from_clipboard())
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: self._select_all())
        
        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        
        widget.bind('<Button-3>', show_menu)
        widget.bind('<Button-2>', show_menu)

    def _settings_path(self):
        return os.path.join(Path.home(), ".kernelspy_settings.json")

    def _save_settings(self):
        try:
            data = {
                "output_dir": self.output_dir,
                "ai_provider": self.ai_config.provider,
                "google_api_key": self.ai_config.google_api_key,
                "google_model": self.ai_config.google_model,
                "gguf_model_path": self.ai_config.gguf_model_path,
                "gguf_n_ctx": self.ai_config.gguf_n_ctx,
                "gguf_n_threads": self.ai_config.gguf_n_threads,
                "use_sast": self.scanner.use_sast,
            }
            with open(self._settings_path(), 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _load_settings(self):
        try:
            path = self._settings_path()
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.output_dir = data.get("output_dir", self.output_dir)
                self.ai_config.provider = data.get("ai_provider", "google")
                self.ai_config.google_api_key = data.get("google_api_key", "")
                self.ai_config.google_model = data.get("google_model", "gemini-2.0-flash")
                self.ai_config.gguf_model_path = data.get("gguf_model_path", "")
                self.ai_config.gguf_n_ctx = data.get("gguf_n_ctx", 4096)
                self.ai_config.gguf_n_threads = data.get("gguf_n_threads", 4)
                self.scanner.use_sast = data.get("use_sast", False)
                from core.engine.ai_analyzer import get_ai_analyzer
                get_ai_analyzer().config = self.ai_config
        except Exception:
            pass

    # ───────────── SIDEBAR ─────────────
    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=70, corner_radius=0, fg_color=BG_SIDEBAR)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        self.sidebar_btns = {}
        icons = ["\u2302", "\u2922", "\u25A3", "\u2261", "\u2699", "\u2728", "\u2699"]
        pages = ["home", "scan", "results", "reports", "settings", "ai_chat", "tree_sitter"]
        for i, (icon, page) in enumerate(zip(icons, pages)):
            btn = ctk.CTkButton(
                self.sidebar, text=icon, font=ctk.CTkFont(size=22),
                width=70, height=55, corner_radius=0,
                fg_color="transparent", hover_color=BG_HOVER,
                text_color=CLR_TEXT2, command=lambda p=page: self.show_page(p),
            )
            btn.pack(pady=(8 if i == 0 else 0, 0))
            self.sidebar_btns[page] = btn

    # ───────────── PAGES ─────────────
    def _build_pages(self):
        self.page_frame = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        self.page_frame.pack(side="left", fill="both", expand=True)

        self.pages = {}
        for name in ["home", "scan", "results", "reports", "settings", "ai_chat", "tree_sitter"]:
            frame = ctk.CTkFrame(self.page_frame, fg_color=BG_DARK, corner_radius=0)
            self.pages[name] = frame

        self._build_home()
        self._build_scan()
        self._build_results()
        self._build_reports()
        self._build_settings()
        self._build_ai_chat()
        self._build_tree_sitter()

    def show_page(self, name):
        for pg_name, frame in self.pages.items():
            if pg_name == name:
                frame.pack(fill="both", expand=True)
            else:
                frame.pack_forget()
        for pg_name, btn in self.sidebar_btns.items():
            if pg_name == name:
                btn.configure(fg_color=BG_HOVER, text_color=ACCENT)
            else:
                btn.configure(fg_color="transparent", text_color=CLR_TEXT2)

    # ───────────── HOME PAGE ─────────────
    def _build_home(self):
        pg = self.pages["home"]

        ctk.CTkLabel(pg, text=self.lang["title"], font=ctk.CTkFont(size=28, weight="bold"),
                      text_color=ACCENT).pack(anchor="w", padx=40, pady=(30, 5))
        ctk.CTkLabel(pg, text=self.lang["subtitle"], font=ctk.CTkFont(size=14),
                      text_color=CLR_TEXT2).pack(anchor="w", padx=40)

        ctk.CTkFrame(pg, height=1, fg_color="#1e1e1e").pack(fill="x", padx=40, pady=15)

        cards_frame = ctk.CTkFrame(pg, fg_color="transparent")
        cards_frame.pack(fill="x", padx=40, pady=(0, 15))

        self.home_cards = {}
        card_data = [
            ("CRITICAL", CLR_DANGER), ("HIGH", CLR_WARNING),
            ("MEDIUM", CLR_MEDIUM), ("LOW", CLR_SUCCESS),
        ]
        for i, (label, color) in enumerate(card_data):
            card = ctk.CTkFrame(cards_frame, fg_color=BG_CARD, corner_radius=10, height=80)
            card.pack(side="left", fill="x", expand=True, padx=(0 if i == 0 else 10, 0))
            card.pack_propagate(False)

            ctk.CTkFrame(card, width=4, fg_color=color, corner_radius=0).pack(side="left", fill="y")
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(side="left", fill="both", expand=True, padx=10)
            ctk.CTkLabel(inner, text=label, font=ctk.CTkFont(size=11, weight="bold"),
                          text_color=color).pack(anchor="w", pady=(8, 0))
            val = ctk.CTkLabel(inner, text="0", font=ctk.CTkFont(size=28, weight="bold"),
                               text_color=color)
            val.pack(anchor="w")
            self.home_cards[label] = val

        self.home_cards["home_cards_frame"] = cards_frame

        drop = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=16, height=160, border_width=2,
                             border_color="#333333")
        drop.pack(fill="x", padx=40, pady=(0, 15))
        drop.pack_propagate(False)

        ctk.CTkLabel(drop, text="\u2B22", font=ctk.CTkFont(size=40), text_color=ACCENT).pack(pady=(20, 5))
        ctk.CTkLabel(drop, text=self.lang["drag_drop"],
                      font=ctk.CTkFont(size=15, weight="bold"), text_color=CLR_TEXT).pack()
        ctk.CTkLabel(drop, text=self.lang["or_browse"],
                      font=ctk.CTkFont(size=12), text_color=CLR_TEXT2).pack(pady=(0, 8))

        ctk.CTkButton(
            drop, text=self.lang["start_scan"], font=ctk.CTkFont(size=14, weight="bold"),
            width=200, height=40, corner_radius=10,
            fg_color=ACCENT, hover_color=ACCENT_DIM, text_color=BG_DARK,
            command=self._browse_folder,
        ).pack()

        # Feature status row
        feat_row = ctk.CTkFrame(pg, fg_color="transparent")
        feat_row.pack(fill="x", padx=40, pady=(0, 5))

        ts_status = "Tree-sitter: ON" if is_tree_sitter_available() else "Tree-sitter: OFF"
        ts_color = CLR_SUCCESS if is_tree_sitter_available() else CLR_TEXT2
        ctk.CTkLabel(feat_row, text=ts_status, font=ctk.CTkFont(size=11),
                      text_color=ts_color).pack(side="left", padx=(0, 15))

        sast_status = "SAST Engines: ON" if self.scanner.use_sast else "SAST Engines: OFF"
        sast_color = CLR_SUCCESS if self.scanner.use_sast else CLR_TEXT2
        ctk.CTkLabel(feat_row, text=sast_status, font=ctk.CTkFont(size=11),
                      text_color=sast_color).pack(side="left", padx=(0, 15))

        ai_eng = self._get_ai().active_provider
        ai_status = f"AI: {ai_eng.upper()}" if ai_eng != "none" else "AI: OFF"
        ai_color = CLR_SUCCESS if ai_eng != "none" else CLR_TEXT2
        ctk.CTkLabel(feat_row, text=ai_status, font=ctk.CTkFont(size=11),
                      text_color=ai_color).pack(side="left")

        ctk.CTkLabel(pg, text=FOOTER_TEXT, font=ctk.CTkFont(size=11),
                      text_color="#444444").pack(side="bottom", pady=10)

    # ───────────── SCAN PAGE ─────────────
    def _build_scan(self):
        pg = self.pages["scan"]

        ctk.CTkLabel(pg, text=self.lang["scan"], font=ctk.CTkFont(size=22, weight="bold"),
                      text_color=ACCENT).pack(anchor="w", padx=40, pady=(20, 5))
        ctk.CTkFrame(pg, height=1, fg_color="#1e1e1e").pack(fill="x", padx=40)

        btn_row = ctk.CTkFrame(pg, fg_color="transparent")
        btn_row.pack(fill="x", padx=40, pady=10)

        self.scan_browse_btn = ctk.CTkButton(
            btn_row, text=self.lang["start_scan"], font=ctk.CTkFont(size=14, weight="bold"),
            width=180, height=42, corner_radius=10,
            fg_color=ACCENT, hover_color=ACCENT_DIM, text_color=BG_DARK,
            command=self._browse_folder,
        )
        self.scan_browse_btn.pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row, text=self.lang["clear"], font=ctk.CTkFont(size=14, weight="bold"),
            width=120, height=42, corner_radius=10,
            fg_color=BG_CARD, hover_color=BG_HOVER, text_color=CLR_TEXT,
            border_width=1, border_color="#333",
            command=self._clear_results,
        ).pack(side="left", padx=(0, 10))

        self.cancel_btn = ctk.CTkButton(
            btn_row, text="Cancel", font=ctk.CTkFont(size=14, weight="bold"),
            width=110, height=42, corner_radius=10,
            fg_color=CLR_DANGER, hover_color="#8f0f24", text_color=CLR_TEXT,
            state="disabled",
            command=self._cancel_scan,
        )
        self.cancel_btn.pack(side="left")

        ctk.CTkButton(
            btn_row, text="EN / AR", font=ctk.CTkFont(size=14, weight="bold"),
            width=100, height=42, corner_radius=10,
            fg_color=BG_CARD, hover_color=BG_HOVER, text_color=CLR_TEXT,
            border_width=1, border_color="#333",
            command=self._toggle_lang,
        ).pack(side="right")

        self.progress_bar = ctk.CTkProgressBar(pg, height=6, corner_radius=3,
                                                fg_color="#141414", progress_color=ACCENT)
        self.progress_bar.pack(fill="x", padx=40, pady=(5, 5))
        self.progress_bar.set(0)

        prog_row = ctk.CTkFrame(pg, fg_color="transparent")
        prog_row.pack(fill="x", padx=40)
        self.progress_text = ctk.CTkLabel(prog_row, text=self.lang["ready"],
                                           font=ctk.CTkFont(size=13), text_color=CLR_TEXT2)
        self.progress_text.pack(side="left")
        self.progress_pct = ctk.CTkLabel(prog_row, text="0%",
                                          font=ctk.CTkFont(size=13, weight="bold"), text_color=ACCENT)
        self.progress_pct.pack(side="right")

        self.scan_summary = ctk.CTkLabel(pg, text="", font=ctk.CTkFont(size=13),
                                          text_color=CLR_TEXT)
        self.scan_summary.pack(anchor="w", padx=40, pady=(5, 5))

        self.scan_tree = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=8)
        self.scan_tree.pack(fill="both", expand=True, padx=40, pady=(0, 20))

        cols = (self.lang["file"], self.lang["line"], self.lang["threat"],
                self.lang["category"], self.lang["severity"], self.lang["description"])
        widths = (160, 55, 170, 80, 85, 460)
        self._build_table(self.scan_tree, cols, widths, "scan")

    def _build_table(self, parent, cols, widths, prefix):
        header = ctk.CTkFrame(parent, fg_color="#0a0a0a", corner_radius=0, height=36)
        header.pack(fill="x")
        header.pack_propagate(False)
        for c, w in zip(cols, widths):
            ctk.CTkLabel(header, text=c, font=ctk.CTkFont(size=12, weight="bold"),
                          text_color=ACCENT, width=w, anchor="w").pack(side="left", padx=8)

        canvas = ctk.CTkCanvas(parent, bg="#000000", highlightthickness=0)
        scrollbar = ctk.CTkScrollbar(parent, orientation="vertical", command=canvas.yview)
        scroll_frame = ctk.CTkFrame(canvas, fg_color="#000000", corner_radius=0)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        setattr(self, f"{prefix}_canvas", canvas)
        setattr(self, f"{prefix}_scroll_frame", scroll_frame)

    def _populate_table(self, prefix, results):
        sf = getattr(self, f"{prefix}_scroll_frame")
        for w in sf.winfo_children():
            w.destroy()

        sev_colors = {"CRITICAL": CLR_DANGER, "HIGH": CLR_WARNING, "MEDIUM": CLR_MEDIUM, "LOW": CLR_SUCCESS}
        col_widths = [160, 55, 170, 80, 85, 460]

        for r in results:
            if len(sf.winfo_children()) >= 500: break
            row = ctk.CTkFrame(sf, fg_color="#000000", corner_radius=0)
            row.pack(fill="x", padx=2, pady=1)

            inner = ctk.CTkFrame(row, fg_color="#0a0a0a", corner_radius=4)
            inner.pack(fill="x", padx=2, pady=2)

            vals = [r.file, str(r.line), r.type, r.category, r.severity, r.description]
            for i, (v, w) in enumerate(zip(vals, col_widths)):
                if i == 4:
                    color = sev_colors.get(r.severity, CLR_TEXT)
                elif i == 3:
                    color = "#c9a84c"
                elif i == 5:
                    color = CLR_TEXT2
                else:
                    color = CLR_TEXT

                if i == 0 and len(v) > 30:
                    v = "..." + v[-27:]
                elif i == 5 and len(v) > 80:
                    v = v[:77] + "..."
                elif i == 2 and len(v) > 35:
                    v = v[:32] + "..."

                lbl = ctk.CTkLabel(inner, text=v, font=ctk.CTkFont(size=12),
                                    text_color=color, width=w, anchor="w",
                                    wraplength=w - 16)
                lbl.pack(side="left", padx=6, pady=4)

    # ───────────── RESULTS PAGE ─────────────
    def _build_results(self):
        pg = self.pages["results"]

        ctk.CTkLabel(pg, text=self.lang["results"], font=ctk.CTkFont(size=22, weight="bold"),
                      text_color=ACCENT).pack(anchor="w", padx=40, pady=(20, 5))
        ctk.CTkFrame(pg, height=1, fg_color="#1e1e1e").pack(fill="x", padx=40)

        stats = ctk.CTkFrame(pg, fg_color="transparent")
        stats.pack(fill="x", padx=40, pady=10)

        self.res_vals = {}
        res_data = [
            ("total", CLR_TEXT), ("critical", CLR_DANGER), ("high", CLR_WARNING),
            ("medium", CLR_MEDIUM), ("low", CLR_SUCCESS),
        ]
        for key, color in res_data:
            f = ctk.CTkFrame(stats, fg_color="transparent")
            f.pack(side="left", padx=(0, 20))
            ctk.CTkLabel(f, text=self.lang[key], font=ctk.CTkFont(size=11, weight="bold"),
                          text_color=color).pack(anchor="w")
            val = ctk.CTkLabel(f, text="0", font=ctk.CTkFont(size=26, weight="bold"),
                               text_color=color)
            val.pack(anchor="w")
            self.res_vals[key] = val

        btn_row = ctk.CTkFrame(pg, fg_color="transparent")
        btn_row.pack(fill="x", padx=40, pady=(5, 5))
        
        ctk.CTkButton(
            btn_row, text="Copy Results", font=ctk.CTkFont(size=12, weight="bold"),
            width=140, height=36, corner_radius=8,
            fg_color=BG_CARD, hover_color=BG_HOVER, text_color=CLR_TEXT,
            border_width=1, border_color="#333",
            command=self._copy_results_to_clipboard,
        ).pack(side="right")

        self.res_tree = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=8)
        self.res_tree.pack(fill="both", expand=True, padx=40, pady=(0, 20))

        cols = (self.lang["file"], self.lang["line"], self.lang["threat"],
                self.lang["category"], self.lang["severity"], self.lang["description"])
        widths = (160, 55, 170, 80, 85, 460)
        self._build_table(self.res_tree, cols, widths, "res")

    # ───────────── REPORTS PAGE ─────────────
    def _build_reports(self):
        pg = self.pages["reports"]

        ctk.CTkLabel(pg, text=self.lang["reports"], font=ctk.CTkFont(size=22, weight="bold"),
                      text_color=ACCENT).pack(anchor="w", padx=40, pady=(20, 5))
        ctk.CTkFrame(pg, height=1, fg_color="#1e1e1e").pack(fill="x", padx=40)

        btn_row = ctk.CTkFrame(pg, fg_color="transparent")
        btn_row.pack(fill="x", padx=40, pady=15)

        ctk.CTkButton(
            btn_row, text=self.lang["export_csv"], font=ctk.CTkFont(size=13, weight="bold"),
            width=160, height=42, corner_radius=10,
            fg_color=ACCENT, hover_color=ACCENT_DIM, text_color=BG_DARK,
            command=lambda: self._export("csv"),
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row, text=self.lang["export_html"], font=ctk.CTkFont(size=13, weight="bold"),
            width=160, height=42, corner_radius=10,
            fg_color=ACCENT, hover_color=ACCENT_DIM, text_color=BG_DARK,
            command=lambda: self._export("html"),
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row, text=self.lang["export_json"], font=ctk.CTkFont(size=13, weight="bold"),
            width=160, height=42, corner_radius=10,
            fg_color=BG_CARD, hover_color=BG_HOVER, text_color=CLR_TEXT,
            border_width=1, border_color="#333",
            command=lambda: self._export("json"),
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row, text=self.lang["export_sarif"], font=ctk.CTkFont(size=13, weight="bold"),
            width=160, height=42, corner_radius=10,
            fg_color=BG_CARD, hover_color=BG_HOVER, text_color=CLR_TEXT,
            border_width=1, border_color="#333",
            command=lambda: self._export("sarif"),
        ).pack(side="left")

        self.report_status = ctk.CTkLabel(pg, text="", font=ctk.CTkFont(size=13),
                                           text_color=CLR_TEXT2)
        self.report_status.pack(anchor="w", padx=40, pady=10)

    # ───────────── AI CHAT PAGE ─────────────
    def _build_ai_chat(self):
        pg = self.pages["ai_chat"]

        ctk.CTkLabel(pg, text=self.lang["ai_title"], font=ctk.CTkFont(size=22, weight="bold"),
                      text_color=ACCENT).pack(anchor="w", padx=40, pady=(20, 5))
        ctk.CTkLabel(pg, text=self.lang["ai_subtitle"], font=ctk.CTkFont(size=13),
                      text_color=CLR_TEXT2).pack(anchor="w", padx=40)
        ctk.CTkFrame(pg, height=1, fg_color="#1e1e1e").pack(fill="x", padx=40, pady=10)

        # Provider selection
        provider_row = ctk.CTkFrame(pg, fg_color="transparent")
        provider_row.pack(fill="x", padx=40, pady=(0, 10))

        ctk.CTkLabel(provider_row, text="Provider:", font=ctk.CTkFont(size=13, weight="bold"),
                      text_color=CLR_TEXT).pack(side="left", padx=(0, 10))

        self.ai_provider_var = ctk.StringVar(value=self.ai_config.provider)
        ctk.CTkRadioButton(provider_row, text=self.lang["provider_google"],
                            variable=self.ai_provider_var, value="google",
                            text_color=CLR_TEXT, fg_color=ACCENT,
                            command=self._on_provider_change).pack(side="left", padx=(0, 15))
        ctk.CTkRadioButton(provider_row, text=self.lang["provider_gguf"],
                            variable=self.ai_provider_var, value="gguf",
                            text_color=CLR_TEXT, fg_color=ACCENT,
                            command=self._on_provider_change).pack(side="left")

        # Google API Key section
        self.google_frame = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=10)
        self.google_frame.pack(fill="x", padx=40, pady=(0, 10))

        ctk.CTkLabel(self.google_frame, text=self.lang["google_api_key"] + ":",
                      font=ctk.CTkFont(size=12, weight="bold"), text_color=CLR_TEXT
                      ).pack(anchor="w", padx=15, pady=(10, 3))

        api_row = ctk.CTkFrame(self.google_frame, fg_color="transparent")
        api_row.pack(fill="x", padx=15, pady=(0, 10))

        self.api_key_entry = ctk.CTkEntry(api_row, font=ctk.CTkFont(size=12),
                                           fg_color="#0a0a0a", border_color="#333",
                                           text_color=CLR_TEXT, height=36, width=400,
                                           placeholder_text="Enter your Google AI Studio API key...")
        self.api_key_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        if self.ai_config.google_api_key:
            self.api_key_entry.insert(0, self.ai_config.google_api_key)
        self._add_context_menu(self.api_key_entry)

        ctk.CTkButton(api_row, text="Save", font=ctk.CTkFont(size=12, weight="bold"),
                       width=80, height=36, corner_radius=8,
                       fg_color=ACCENT, hover_color=ACCENT_DIM, text_color=BG_DARK,
                       command=self._save_api_key).pack(side="right")

        # GGUF Model section
        self.gguf_frame = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=10)

        ctk.CTkLabel(self.gguf_frame, text=self.lang["gguf_model"] + ":",
                      font=ctk.CTkFont(size=12, weight="bold"), text_color=CLR_TEXT
                      ).pack(anchor="w", padx=15, pady=(10, 3))

        gguf_row = ctk.CTkFrame(self.gguf_frame, fg_color="transparent")
        gguf_row.pack(fill="x", padx=15, pady=(0, 5))

        self.model_path_entry = ctk.CTkEntry(gguf_row, font=ctk.CTkFont(size=12),
                                              fg_color="#0a0a0a", border_color="#333",
                                              text_color=CLR_TEXT, height=36,
                                              placeholder_text="Path to .gguf model file...")
        self.model_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        if self.ai_config.gguf_model_path:
            self.model_path_entry.insert(0, self.ai_config.gguf_model_path)

        ctk.CTkButton(gguf_row, text="Browse", font=ctk.CTkFont(size=12, weight="bold"),
                       width=80, height=36, corner_radius=8,
                       fg_color=BG_CARD, hover_color=BG_HOVER, text_color=CLR_TEXT,
                       border_width=1, border_color="#333",
                       command=self._browse_gguf_model).pack(side="right")

        btn_row = ctk.CTkFrame(self.gguf_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(5, 10))

        self.load_model_btn = ctk.CTkButton(
            btn_row, text=self.lang["load_model"], font=ctk.CTkFont(size=12, weight="bold"),
            width=140, height=36, corner_radius=8,
            fg_color=ACCENT, hover_color=ACCENT_DIM, text_color=BG_DARK,
            command=self._load_gguf_model,
        )
        self.load_model_btn.pack(side="left", padx=(0, 10))

        self.unload_model_btn = ctk.CTkButton(
            btn_row, text=self.lang["unload_model"], font=ctk.CTkFont(size=12, weight="bold"),
            width=140, height=36, corner_radius=8,
            fg_color=BG_CARD, hover_color=BG_HOVER, text_color=CLR_TEXT,
            border_width=1, border_color="#333",
            command=self._unload_gguf_model,
        )
        self.unload_model_btn.pack(side="left", padx=(0, 10))

        self.model_status_label = ctk.CTkLabel(btn_row, text="", font=ctk.CTkFont(size=12),
                                                text_color=CLR_TEXT2)
        self.model_status_label.pack(side="left", padx=10)

        # Show/hide frames based on provider
        self._on_provider_change()

        # Chat area
        self.chat_frame = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=10)
        self.chat_frame.pack(fill="both", expand=True, padx=40, pady=(10, 10))

        self.chat_scroll = ctk.CTkScrollableFrame(self.chat_frame, fg_color="#0a0a0a",
                                                   corner_radius=8)
        self.chat_scroll.pack(fill="both", expand=True, padx=10, pady=10)

        # Chat input
        input_row = ctk.CTkFrame(pg, fg_color="transparent")
        input_row.pack(fill="x", padx=40, pady=(0, 15))

        self.chat_input = ctk.CTkTextbox(input_row, font=ctk.CTkFont(size=13),
                                          fg_color=BG_CARD, text_color=CLR_TEXT,
                                          height=60, corner_radius=10,
                                          border_width=1, border_color="#333")
        self.chat_input.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.chat_input.insert("1.0", self.lang["chat_placeholder"])
        self._add_context_menu(self.chat_input)

        btn_col = ctk.CTkFrame(input_row, fg_color="transparent")
        btn_col.pack(side="right")

        ctk.CTkButton(
            btn_col, text=self.lang["send"], font=ctk.CTkFont(size=13, weight="bold"),
            width=100, height=28, corner_radius=8,
            fg_color=ACCENT, hover_color=ACCENT_DIM, text_color=BG_DARK,
            command=self._send_chat,
        ).pack(pady=(0, 5))

        ctk.CTkButton(
            btn_col, text=self.lang["clear_chat"], font=ctk.CTkFont(size=11),
            width=100, height=24, corner_radius=8,
            fg_color=BG_CARD, hover_color=BG_HOVER, text_color=CLR_TEXT2,
            border_width=1, border_color="#333",
            command=self._clear_chat,
        ).pack()

    def _on_provider_change(self):
        provider = self.ai_provider_var.get()
        self.ai_config.provider = provider
        if provider == "google":
            self.google_frame.pack(fill="x", padx=40, pady=(0, 10))
            self.gguf_frame.pack_forget()
        else:
            self.google_frame.pack_forget()
            self.gguf_frame.pack(fill="x", padx=40, pady=(0, 10))

    def _save_api_key(self):
        key = self.api_key_entry.get().strip()
        self.ai_config.google_api_key = key
        from core.engine.ai_analyzer import get_ai_analyzer
        get_ai_analyzer().config = self.ai_config
        self._save_settings()

    def _browse_gguf_model(self):
        path = filedialog.askopenfilename(
            title="Select GGUF Model",
            filetypes=[("GGUF files", "*.gguf"), ("All files", "*.*")]
        )
        if path:
            self.model_path_entry.delete(0, "end")
            self.model_path_entry.insert(0, path)
            self.ai_config.gguf_model_path = path

    def _load_gguf_model(self):
        path = self.model_path_entry.get().strip()
        if not path:
            return
        self.ai_config.gguf_model_path = path
        from core.engine.ai_analyzer import get_ai_analyzer
        analyzer = get_ai_analyzer()
        analyzer.config = self.ai_config

        self.model_status_label.configure(text="Loading...", text_color=CLR_WARNING)
        self.load_model_btn.configure(state="disabled")

        def on_load(success, msg):
            self.after(0, lambda: self._on_model_loaded(success, msg))

        analyzer.gguf.load_model(path, callback=on_load)

    def _on_model_loaded(self, success, msg):
        self.load_model_btn.configure(state="normal")
        if success:
            self.model_status_label.configure(text=self.lang["model_loaded"], text_color=CLR_SUCCESS)
        else:
            self.model_status_label.configure(text=f"Error: {msg[:50]}", text_color=CLR_DANGER)

    def _unload_gguf_model(self):
        from core.engine.ai_analyzer import get_ai_analyzer
        get_ai_analyzer().gguf.unload_model()
        self.model_status_label.configure(text=self.lang["model_not_loaded"], text_color=CLR_TEXT2)

    def _get_ai(self):
        from core.engine.ai_analyzer import get_ai_analyzer
        return get_ai_analyzer()

    def _add_chat_message(self, role, content):
        colors = {"user": ACCENT, "assistant": CLR_SUCCESS, "system": CLR_TEXT2, "error": CLR_DANGER}
        bg_colors = {"user": "#0a1a2a", "assistant": "#0a1a0a", "system": "#1a1a1a", "error": "#1a0a0a"}

        msg_frame = ctk.CTkFrame(self.chat_scroll, fg_color=bg_colors.get(role, "#0a0a0a"),
                                  corner_radius=8)
        msg_frame.pack(fill="x", pady=5, padx=5)

        role_label = ctk.CTkLabel(msg_frame, text=role.upper(),
                                   font=ctk.CTkFont(size=11, weight="bold"),
                                   text_color=colors.get(role, CLR_TEXT))
        role_label.pack(anchor="w", padx=10, pady=(8, 2))

        content_label = ctk.CTkLabel(msg_frame, text=content,
                                      font=ctk.CTkFont(size=13),
                                      text_color=CLR_TEXT, wraplength=700, justify="left")
        content_label.pack(anchor="w", padx=10, pady=(0, 8))

        self.chat_scroll._parent_canvas.yview_moveto(1.0)

    def _send_chat(self):
        text = self.chat_input.get("1.0", "end").strip()
        if not text or text == self.lang["chat_placeholder"]:
            return
        self.chat_input.delete("1.0", "end")

        self._add_chat_message("user", text)

        threading.Thread(target=self._ai_chat_thread, args=(text,), daemon=True).start()

    def _ai_chat_thread(self, text):
        try:
            ai = self._get_ai()
            response = ai.chat(text)
            self.after(0, lambda: self._add_chat_message(
                "assistant" if response.success else "error",
                response.content if response.success else response.error
            ))
        except Exception as e:
            self.after(0, lambda: self._add_chat_message("error", str(e)))

    def _clear_chat(self):
        for w in self.chat_scroll.winfo_children():
            w.destroy()
        self._get_ai().clear_history()

    # ───────────── TREE-SITTER PAGE ─────────────
    def _build_tree_sitter(self):
        pg = self.pages["tree_sitter"]

        ctk.CTkLabel(pg, text=self.lang["ts_title"], font=ctk.CTkFont(size=22, weight="bold"),
                      text_color=ACCENT).pack(anchor="w", padx=40, pady=(20, 5))
        ctk.CTkFrame(pg, height=1, fg_color="#1e1e1e").pack(fill="x", padx=40, pady=(0, 15))

        # Status
        status = is_tree_sitter_available()
        status_color = CLR_SUCCESS if status else CLR_DANGER
        status_text = self.lang["ts_available"] if status else self.lang["ts_not_available"]

        status_frame = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=10)
        status_frame.pack(fill="x", padx=40, pady=(0, 15))

        ctk.CTkLabel(status_frame, text=f"{self.lang['ts_available']}:",
                      font=ctk.CTkFont(size=14, weight="bold"), text_color=CLR_TEXT
                      ).pack(anchor="w", padx=15, pady=(10, 5))

        dot = "\u25CF" if status else "\u25CB"
        ctk.CTkLabel(status_frame, text=f"{dot} {status_text}",
                      font=ctk.CTkFont(size=13), text_color=status_color
                      ).pack(anchor="w", padx=25, pady=(0, 10))

        # Supported languages
        ctk.CTkLabel(pg, text=self.lang["ts_supported"] + ":",
                      font=ctk.CTkFont(size=14, weight="bold"), text_color=CLR_TEXT
                      ).pack(anchor="w", padx=40, pady=(10, 5))

        lang_frame = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=10)
        lang_frame.pack(fill="x", padx=40, pady=(0, 15))

        if status:
            from core.engine.tree_sitter_parser import get_parser, LANGUAGE_DISPLAY_NAMES
            parser = get_parser()
            langs = parser.supported_languages
            for i, lang in enumerate(langs):
                row = i // 4
                col = i % 4
                name = LANGUAGE_DISPLAY_NAMES.get(lang, lang)
                color = CLR_SUCCESS
                ctk.CTkLabel(lang_frame, text=f"\u25CF {name}",
                              font=ctk.CTkFont(size=12), text_color=color
                              ).grid(row=row, column=col, sticky="w", padx=20, pady=5)
        else:
            ctk.CTkLabel(lang_frame, text="Install tree-sitter packages to enable multi-language parsing",
                          font=ctk.CTkFont(size=12), text_color=CLR_TEXT2
                          ).pack(anchor="w", padx=20, pady=10)

        # SAST Engines section
        ctk.CTkLabel(pg, text=self.lang["sast_engines"] + ":",
                      font=ctk.CTkFont(size=14, weight="bold"), text_color=CLR_TEXT
                      ).pack(anchor="w", padx=40, pady=(15, 5))

        sast_frame = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=10)
        sast_frame.pack(fill="x", padx=40, pady=(0, 15))

        sast = get_sast_orchestrator()
        engines = sast.available_engines

        for i, (name, available) in enumerate(engines.items()):
            engine_frame = ctk.CTkFrame(sast_frame, fg_color="transparent")
            engine_frame.pack(fill="x", padx=15, pady=5)

            dot = "\u25CF" if available else "\u25CB"
            color = CLR_SUCCESS if available else CLR_DANGER
            status = self.lang["engine_available"] if available else self.lang["engine_not_available"]

            ctk.CTkLabel(engine_frame, text=f"{dot} {name.upper()}",
                          font=ctk.CTkFont(size=13, weight="bold"), text_color=color
                          ).pack(side="left")
            ctk.CTkLabel(engine_frame, text=f"({status})",
                          font=ctk.CTkFont(size=11), text_color=CLR_TEXT2
                          ).pack(side="left", padx=10)

        # CPG info
        ctk.CTkLabel(pg, text="Code Property Graph (CPG):",
                      font=ctk.CTkFont(size=14, weight="bold"), text_color=CLR_TEXT
                      ).pack(anchor="w", padx=40, pady=(15, 5))

        cpg_frame = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=10)
        cpg_frame.pack(fill="x", padx=40, pady=(0, 15))

        cpg_info = [
            "\u25CF AST (Abstract Syntax Tree): Code structure analysis",
            "\u25CF CFG (Control Flow Graph): Execution path analysis",
            "\u25CF DDG (Data Dependency Graph): Variable flow tracking",
            "\u25CF Taint Analysis: Source-to-sink vulnerability detection",
        ]
        for info in cpg_info:
            ctk.CTkLabel(cpg_frame, text=info, font=ctk.CTkFont(size=12),
                          text_color=CLR_TEXT2).pack(anchor="w", padx=20, pady=3)

    # ───────────── SETTINGS PAGE ─────────────
    def _build_settings(self):
        pg = self.pages["settings"]

        ctk.CTkLabel(pg, text=self.lang["settings_title"], font=ctk.CTkFont(size=22, weight="bold"),
                      text_color=ACCENT).pack(anchor="w", padx=40, pady=(20, 5))
        ctk.CTkFrame(pg, height=1, fg_color="#1e1e1e").pack(fill="x", padx=40)

        # Output directory
        ctk.CTkLabel(pg, text=self.lang["output_dir"] + ":", font=ctk.CTkFont(size=14),
                      text_color=CLR_TEXT).pack(anchor="w", padx=40, pady=(20, 5))

        dir_row = ctk.CTkFrame(pg, fg_color="transparent")
        dir_row.pack(fill="x", padx=40)

        self.dir_entry = ctk.CTkEntry(dir_row, font=ctk.CTkFont(size=13),
                                       fg_color=BG_CARD, border_color="#333",
                                       text_color=CLR_TEXT, height=36)
        self.dir_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.dir_entry.insert(0, self.output_dir)

        ctk.CTkButton(
            dir_row, text="Browse", font=ctk.CTkFont(size=13, weight="bold"),
            width=100, height=36, corner_radius=8,
            fg_color=BG_CARD, hover_color=BG_HOVER, text_color=CLR_TEXT,
            border_width=1, border_color="#333",
            command=self._browse_output,
        ).pack(side="right")

        # SAST toggle
        sast_frame = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=10)
        sast_frame.pack(fill="x", padx=40, pady=(20, 10))

        self.sast_toggle_var = ctk.BooleanVar(value=self.scanner.use_sast)
        ctk.CTkSwitch(sast_frame, text=self.lang["enable_sast"],
                       variable=self.sast_toggle_var,
                       text_color=CLR_TEXT, fg_color="#333",
                       progress_color=ACCENT,
                       command=self._toggle_sast).pack(anchor="w", padx=15, pady=10)

        # AI Config
        ctk.CTkLabel(pg, text="AI Configuration:", font=ctk.CTkFont(size=14, weight="bold"),
                      text_color=CLR_TEXT).pack(anchor="w", padx=40, pady=(15, 5))

        ai_frame = ctk.CTkFrame(pg, fg_color=BG_CARD, corner_radius=10)
        ai_frame.pack(fill="x", padx=40, pady=(0, 10))

        # Provider selection
        prov_row = ctk.CTkFrame(ai_frame, fg_color="transparent")
        prov_row.pack(fill="x", padx=15, pady=(10, 5))

        ctk.CTkLabel(prov_row, text="AI Provider:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=CLR_TEXT).pack(side="left", padx=(0, 10))

        self.settings_provider_var = ctk.StringVar(value=self.ai_config.provider)
        ctk.CTkRadioButton(prov_row, text="Google AI Studio",
                            variable=self.settings_provider_var, value="google",
                            text_color=CLR_TEXT, fg_color=ACCENT).pack(side="left", padx=(0, 15))
        ctk.CTkRadioButton(prov_row, text="Local GGUF",
                            variable=self.settings_provider_var, value="gguf",
                            text_color=CLR_TEXT, fg_color=ACCENT).pack(side="left")

        # Google API Key
        gkey_row = ctk.CTkFrame(ai_frame, fg_color="transparent")
        gkey_row.pack(fill="x", padx=15, pady=5)

        ctk.CTkLabel(gkey_row, text="Google API Key:", font=ctk.CTkFont(size=12),
                      text_color=CLR_TEXT2).pack(side="left", padx=(0, 10))

        self.settings_api_key = ctk.CTkEntry(gkey_row, font=ctk.CTkFont(size=12),
                                              fg_color="#0a0a0a", border_color="#333",
                                              text_color=CLR_TEXT, height=32, width=350,
                                              show="*")
        self.settings_api_key.pack(side="left", fill="x", expand=True, padx=(0, 10))
        if self.ai_config.google_api_key:
            self.settings_api_key.insert(0, self.ai_config.google_api_key)

        # GGUF path
        gpath_row = ctk.CTkFrame(ai_frame, fg_color="transparent")
        gpath_row.pack(fill="x", padx=15, pady=(5, 10))

        ctk.CTkLabel(gpath_row, text="GGUF Model:", font=ctk.CTkFont(size=12),
                      text_color=CLR_TEXT2).pack(side="left", padx=(0, 10))

        self.settings_gguf_path = ctk.CTkEntry(gpath_row, font=ctk.CTkFont(size=12),
                                                fg_color="#0a0a0a", border_color="#333",
                                                text_color=CLR_TEXT, height=32)
        self.settings_gguf_path.pack(side="left", fill="x", expand=True, padx=(0, 10))
        if self.ai_config.gguf_model_path:
            self.settings_gguf_path.insert(0, self.ai_config.gguf_model_path)

        ctk.CTkButton(gpath_row, text="Browse", font=ctk.CTkFont(size=11, weight="bold"),
                       width=80, height=32, corner_radius=8,
                       fg_color=BG_CARD, hover_color=BG_HOVER, text_color=CLR_TEXT,
                       border_width=1, border_color="#333",
                       command=self._browse_gguf_settings).pack(side="right")

        # Save button
        ctk.CTkButton(
            pg, text=self.lang["save_settings"], font=ctk.CTkFont(size=14, weight="bold"),
            width=180, height=42, corner_radius=10,
            fg_color=ACCENT, hover_color=ACCENT_DIM, text_color=BG_DARK,
            command=self._save_all_settings,
        ).pack(anchor="w", padx=40, pady=(15, 10))

        self.settings_status = ctk.CTkLabel(pg, text="", font=ctk.CTkFont(size=12),
                                             text_color=CLR_SUCCESS)
        self.settings_status.pack(anchor="w", padx=40)

        ctk.CTkLabel(pg, text=f"{self.lang['version']}: {VERSION}",
                      font=ctk.CTkFont(size=14), text_color=CLR_TEXT2).pack(anchor="w", padx=40, pady=20)
        ctk.CTkLabel(pg, text=FOOTER_TEXT,
                      font=ctk.CTkFont(size=12), text_color="#444444").pack(anchor="w", padx=40)

    def _toggle_sast(self):
        self.scanner.use_sast = self.sast_toggle_var.get()

    def _browse_gguf_settings(self):
        path = filedialog.askopenfilename(
            title="Select GGUF Model",
            filetypes=[("GGUF files", "*.gguf"), ("All files", "*.*")]
        )
        if path:
            self.settings_gguf_path.delete(0, "end")
            self.settings_gguf_path.insert(0, path)

    def _save_all_settings(self):
        self.output_dir = self.dir_entry.get().strip()
        self.ai_config.provider = self.settings_provider_var.get()
        self.ai_config.google_api_key = self.settings_api_key.get().strip()
        self.ai_config.gguf_model_path = self.settings_gguf_path.get().strip()
        self.scanner.use_sast = self.sast_toggle_var.get()

        from core.engine.ai_analyzer import get_ai_analyzer
        get_ai_analyzer().config = self.ai_config

        self._save_settings()
        self.settings_status.configure(text=self.lang["settings_saved"])

    # ───────────── ACTIONS ─────────────
    def _browse_folder(self):
        if self.scanning:
            return
        folder = filedialog.askdirectory(title=self.lang["select_folder"])
        if folder:
            self.show_page("scan")
            self._start_scan(folder)

    def _browse_output(self):
        folder = filedialog.askdirectory(title="Select Output Directory")
        if folder:
            self.output_dir = folder
            self.dir_entry.delete(0, "end")
            self.dir_entry.insert(0, folder)

    def _cancel_scan(self):
        self._cancel = True
        self.progress_text.configure(text="Cancelling...")

    def _start_scan(self, folder):
        if self.scanning:
            return
        self.scanning = True
        self._cancel = False
        self._scan_generation = getattr(self, '_scan_generation', 0) + 1
        self.results = []
        self._seen_exact = set()
        self.last_scan_stats = None
        self.result_queue = queue.Queue()

        self.scan_browse_btn.configure(text=self.lang["scanning"], state="disabled")
        if hasattr(self, 'cancel_btn'):
            self.cancel_btn.configure(state="normal")
        self.progress_bar.set(0)
        self.progress_pct.configure(text="0%")
        self.scan_summary.configure(text="")

        self._process_queue()

        self.scanner.scan_threaded(
            folder, self.result_queue, lambda: self._cancel)

    def _update_progress(self, pct, msg):
        self.progress_bar.set(max(0.0, min(1.0, pct / 100.0)))
        self.progress_pct.configure(text=f"{pct}%")
        if msg:
            self.progress_text.configure(text=msg)

    def _process_queue(self):
        if not self.scanning:
            return

        try:
            while True:
                msg = self.result_queue.get_nowait()
                kind = msg[0]
                if kind == "findings":
                    fresh = []
                    for f in msg[1]:
                        key = (f.file, f.line, f.type)
                        if key in self._seen_exact:
                            continue
                        self._seen_exact.add(key)
                        fresh.append(f)
                    if fresh:
                        self.results.extend(fresh)
                        total = len(self.results)
                        self.scan_summary.configure(
                            text=f"{self.lang['found_issues']}: {total}")
                elif kind == "progress":
                    self._update_progress(msg[1], msg[2])
                elif kind == "done":
                    self._on_scan_complete(msg[1])
                    return
        except queue.Empty:
            pass

        self.after(100, self._process_queue)

    def _on_scan_complete(self, payload):
        if not self.scanning:
            return
        payload = payload or {}

        self.results = list(payload.get('results') or [])
        self.last_scan_stats = payload.get('stats') or {}
        cancelled = bool(payload.get('cancelled'))
        error = payload.get('error')

        self.scanning = False
        self.scan_browse_btn.configure(text=self.lang["start_scan"], state="normal")
        if hasattr(self, 'cancel_btn'):
            self.cancel_btn.configure(state="disabled")

        total = len(self.results)

        if error:
            self.progress_text.configure(text=f"{self.lang['fail']}: {error}")
            self.progress_pct.configure(text="")
        elif cancelled:
            self.progress_text.configure(text=f"{self.lang['complete']} ({total} {self.lang['found_issues']}) - cancelled")
            self.progress_pct.configure(text="")
        else:
            self.progress_bar.set(1.0)
            self.progress_pct.configure(text="100%")
            self.progress_text.configure(text=f"{self.lang['complete']}: {total} {self.lang['found_issues']}")

        st = self.last_scan_stats
        cov = ""
        if st:
            cov = (f" | files: {st.get('analyzed', 0)}/{st.get('discovered', 0)} analyzed"
                   f", {st.get('failed', 0)} failed, {st.get('skipped', 0)} skipped")
        self.scan_summary.configure(
            text=f"{self.lang['found_issues']}: {total}{cov}")

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in self.results:
            counts[r.severity] = counts.get(r.severity, 0) + 1

        for key, val in [("critical", counts["CRITICAL"]), ("high", counts["HIGH"]),
                         ("medium", counts["MEDIUM"]), ("low", counts["LOW"])]:
            if key in self.home_cards:
                self.home_cards[key].configure(text=str(val))

        self.res_vals["total"].configure(text=str(total))
        for key, sev in [("critical", "CRITICAL"), ("high", "HIGH"),
                         ("medium", "MEDIUM"), ("low", "LOW")]:
            self.res_vals[key].configure(text=str(counts[sev]))

        self._populate_table("scan", self.results)
        self._populate_table("res", self.results)

    def _clear_results(self):
        self.results = []
        self._seen_exact = set()
        for w in self.scan_scroll_frame.winfo_children():
            w.destroy()
        for w in self.res_scroll_frame.winfo_children():
            w.destroy()
        self.progress_bar.set(0)
        self.progress_text.configure(text=self.lang["ready"])
        self.progress_pct.configure(text="0%")
        self.scan_summary.configure(text="")
        self.report_status.configure(text="")
        for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if key in self.home_cards:
                self.home_cards[key].configure(text="0")
        for key in self.res_vals:
            self.res_vals[key].configure(text="0")

    def _toggle_lang(self):
        self.lang_code = "ar" if self.lang_code == "en" else "en"
        self.lang = LANGS[self.lang_code]
        self._refresh_ui()

    def _refresh_ui(self):
        self.lang_btn = None
        for pg_name, frame in self.pages.items():
            for w in frame.winfo_children():
                w.destroy()

        self._build_home()
        self._build_scan()
        self._build_results()
        self._build_reports()
        self._build_settings()
        self._build_ai_chat()
        self._build_tree_sitter()
        self.show_page("scan" if self.scanning else "home")

        if self.results:
            self._populate_table("scan", self.results)
            self._populate_table("res", self.results)

    def _export(self, fmt):
        if not self.results:
            self.report_status.configure(text=self.lang["no_data"])
            return
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, f"KernelSpy_Report.{fmt}")
        if fmt == "csv":
            ok = export_csv(path, self.results)
        elif fmt == "html":
            ok = export_html(path, self.results)
        elif fmt == "json":
            ok = export_json(path, self.results)
        elif fmt == "sarif":
            ok = export_sarif(path, self.results)
        else:
            ok = False
        self.report_status.configure(
            text=f"{self.lang['done']}: {path}" if ok else self.lang["fail"]
        )


if __name__ == "__main__":
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.CreateMutexW(None, False, "KernelSpyScannerRunning")
    app = App()
    app.mainloop()
