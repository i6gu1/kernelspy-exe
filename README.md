<div align="center">

<img src="https://img.shields.io/badge/KernelSpy-Scanner-0ea5e9?style=for-the-badge&logo=security&logoColor=white" alt="KernelSpy">

# KernelSpy Scanner

### Advanced Code Security Scanner — SAST Engines, Taint Tracking & AI Analysis

![Version](https://img.shields.io/badge/version-1.4.3-0ea5e9?style=flat&logo=github)
![Python](https://img.shields.io/badge/python-3.10%2B-3776ab?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-22c55e?style=flat&logo=opensourceinitiative&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows-0078d4?style=flat&logo=windows&logoColor=white)
![Languages](https://img.shields.io/badge/languages-30%2B-8b5cf6?style=flat&logo=codio&logoColor=white)
![AI](https://img.shields.io/badge/AI-Gemini%20%7C%20Local%20GGUF-f43f5e?style=flat&logo=googlegemini&logoColor=white)

**Detect leaked secrets, injections, XSS, SQLi, SSRF, unsafe deserialization and misconfigurations
across 30+ programming languages — with a modern dark UI in English and Arabic.**

[Download Installer](https://kernelspy.duckdns.org) • [Report a Bug](https://github.com/i6gu1/kernelspy-exe/issues) • [Request a Feature](https://github.com/i6gu1/kernelspy-exe/issues)

</div>

---

## Table of Contents

- [Highlights](#highlights)
- [What's New in 1.4.3](#whats-new-in-143)
- [Detection Engines](#detection-engines)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [AI Integration](#ai-integration)
- [SAST Engines](#sast-engines)
- [Export Formats](#export-formats)
- [Supported Languages](#supported-languages)
- [Configuration](#configuration)
- [Building from Source](#building-from-source)
- [Contributing](#contributing)
- [License](#license)

---

## Highlights

| | |
|:--|:--|
| ![Engines](https://img.shields.io/badge/6-engines-E11d48?style=flat) | Pattern, AST, Lexer, Taint, Tree-sitter, CPG working together |
| ![Languages](https://img.shields.io/badge/18-tree--sitter-7c3aed?style=flat) | Parsed languages with concrete syntax trees |
| ![Rules](https://img.shields.io/badge/100%2B-security%20rules-059669?style=flat) | Secrets, injection, crypto, traversal, SSRF, config |
| ![Dedup](https://img.shields.io/badge/one%20record%20per%20bug-2563eb?style=flat) | Cross-analyzer deduplication and severity layering |
| ![UI](https://img.shields.io/badge/EN%20%2B%20AR%20UI-0891b2?style=flat) | Full RTL-aware bilingual interface, dark theme |
| ![Offline](https://img.shields.io/badge/100%25%20offline-capable-4f46e5?style=flat) | Scanners never phone home; AI is fully optional |

---

## What's New in 1.4.3

### Go — Tainted Channel Tracking

A value pushed into a channel keeps its taint, and every receiver inherits it:

```go
ch := make(chan string)
go func() { ch <- r.URL.Query().Get("q") }()   // channel becomes tainted
v := <-ch                                      // v inherits the taint
db.Query("SELECT " + v)                        // CRITICAL: Taint v -> sql.Query
```

`for v := range ch` over a poisoned channel is tracked the same way.

### Node.js — Object Reference Tracking

Handler tables are remembered while parsing, so an indirect call resolves to
the real sink before the taint check:

```js
const renderHandlers = { html: (x) => res.send(x) };
const key = "html";                 // constant folding included
renderHandlers[key](req.query.t);   // resolves to res.send(tainted)
```

Result: `ObjRef: renderHandlers['html'] -> res.send`. Folded keys such as
`"ex" + "ec"` resolve to `child_process.exec` as well.

### Python — Constant Folding & Propagation

String concatenation is folded while the AST is scanned, and the folded value
unlocks dynamic dispatch:

```python
part1 = "ev"
part2 = "al"
name = part1 + part2                # folds to "eval"
globals()[name](...)                # CRITICAL: ConstFold -> eval
getattr(os, "os" + ".system")       # CRITICAL: ConstFold -> os.system
```

`globals().get("join")` and other harmless lookups stay quiet.

### AI — Honest Error Reporting

Google answers region blocks with *"User location is not supported"*. That
string used to be mistaken for a bad model name, which burned every fallback
and ended with a misleading *"model X is not available for this API key"*.
The app now detects the geography block and tells you to use a VPN or a local
GGUF model instead.

### Design

- New application icon (shield + magnifier)
- Model dropdowns resync automatically after a fallback reply
- Bounded AI chat history — no more HTTP 400 on long conversations

---

## Detection Engines

| Engine | Scope | What it does |
|:--|:--|:--|
| **Pattern** | 30+ languages | 100+ rules for secrets, weak crypto, dangerous APIs |
| **AST** | Python | Deep syntax analysis, constant folding, dynamic dispatch |
| **Lexer** | PHP, JS, TS, Java | Token-level classification of sinks and sources |
| **Taint** | 20+ languages | Source-to-sink flow with channels, objects, sanitizers |
| **Tree-sitter** | 18 languages | Concrete syntax trees for structural rules |
| **CPG** | Python, JS, Go | AST + CFG + DDG combined into a property graph |
| **Context** | Cross-language | Framework awareness, prepared statements, test files |
| **SAST** | External | Semgrep, Trivy and SonarScanner orchestration |

Every finding passes through a **deduplication layer** (one record per bug,
analyzers merged) and a **severity matrix** that raises or lowers scores from
context, then receives ready-to-apply remediation guidance.

---

## Architecture

```
kernelspy-exe/
├── core/
│   ├── engine/
│   │   ├── scanner.py              # Main scanning orchestrator
│   │   ├── patterns.py             # Pattern matching engine
│   │   ├── context.py              # Comment/string stripping
│   │   ├── context_analyzer.py     # Cross-language detectors
│   │   ├── ast_analyzer.py         # Python AST + constant folding
│   │   ├── lexer_analyzer.py       # Token-based analysis
│   │   ├── taint_tracker.py        # Multi-language taint analysis
│   │   ├── flow_refine.py          # Channels, object refs, const folding
│   │   ├── dedup.py                # Cross-analyzer deduplication
│   │   ├── filters.py              # Suppressions / scope gates
│   │   ├── sanitizers.py           # Sanitizer registry
│   │   ├── severity_matrix.py      # Context-aware severity scoring
│   │   ├── remediation.py          # Fix guidance engine
│   │   ├── tree_sitter_parser.py   # Tree-sitter integration
│   │   ├── cpg.py                  # Code Property Graph builder
│   │   ├── sast_orchestrator.py    # External SAST tools integration
│   │   └── ai_analyzer.py          # AI integration (Gemini + GGUF)
│   ├── analyzers/                  # Per-language analyzers
│   ├── rules/                      # Security rules + remediation data
│   └── reporting/                  # CSV / HTML / JSON / SARIF
├── main.py                         # GUI application
├── KernelSpy Scanner.spec          # PyInstaller configuration
└── KernelSpy_pro_1.4.3.iss         # Inno Setup installer script
```

---

## Installation

### Option 1 — Installer (recommended)

Download `KernelSpy_Scanner_Setup_PRO_1.4.3_MultiLang.exe` from
[kernelspy.duckdns.org](https://kernelspy.duckdns.org), run it, and you get:

- Per-user install (no admin rights required)
- Desktop icon and optional Explorer right-click *Scan with KernelSpy*
- Clean upgrade over any previous version

### Option 2 — Run from source

```bash
git clone https://github.com/i6gu1/kernelspy-exe.git
cd kernelspy-exe
pip install -r requirements.txt
python main.py
```

### Option 3 — Build the executable

```bash
pip install pyinstaller
pyinstaller "KernelSpy Scanner.spec"
# result: dist/KernelSpy Scanner.exe
```

---

## Quick Start

1. Launch **KernelSpy Scanner**
2. Drop a project folder on the home page (or press **Start Scan**)
3. Watch findings stream into the results table with live severity counts
4. Open a finding for its explanation and ready-to-paste fix code
5. Export **CSV / HTML / JSON / SARIF**

Command line and Explorer integration:

```bash
"./KernelSpy Scanner.exe" "C:\path\to\project"
# after install: right-click any folder -> "Scan with KernelSpy"
```

---

## AI Integration

AI is **optional** — every built-in engine works offline without a key.

### Google Gemini

1. Create a key at [Google AI Studio](https://aistudio.google.com/apikey)
2. Paste it on the **AI Chat** page and press **Test**
3. Pick any model from the live list (refreshable) and chat about your code

> **Region note:** the Generative Language API is not available in every
> country. If the app reports a geography block, connect through a VPN or use
> a local GGUF model below.

### Local GGUF models

1. Download a coder model from [Hugging Face](https://huggingface.co/models?search=gguf+coder)
2. Recommended: `Qwen2.5-Coder-1.5B-Instruct` (1 GB RAM),
   `DeepSeek-Coder-6.7B-Instruct` (8 GB RAM),
   `Qwen2.5-Coder-32B-Instruct` (24 GB RAM)
3. **AI Chat** → *Browse* → select the `.gguf` file

### AI Chat page

| Capability | |
|:--|:--|
| Interactive security assistant | Chat about findings, code and fixes |
| **Analyze Findings with AI** | One-click report summary on the Results page |
| Bounded history | Long conversations stay inside the model context |
| Model fallback | Automatic switch to a working model on HTTP 404 |

---

## SAST Engines

| Engine | Status | Coverage |
|:--|:--|:--|
| **Semgrep** | Optional | Pattern rules across 30+ languages |
| **Trivy** | Optional | Dependency vulnerabilities |
| **SonarScanner** | Optional | Code quality and smells |

Enable them in **Settings → Enable External SAST Engines** (auto-detected when
installed on PATH).

---

## Export Formats

| Format | Extension | Notes |
|:--|:--|:--|
| CSV | `.csv` | Spreadsheet friendly |
| HTML | `.html` | Self-contained dark report |
| JSON | `.json` | Structured, machine readable |
| SARIF | `.sarif` | GitHub / Microsoft compatible |

---

## Supported Languages

**Tree-sitter (18):** Python, JavaScript, TypeScript, Java, Go, Rust, C, C++,
C#, PHP, Ruby, Kotlin, Swift, Lua, Perl, Dart, Scala, Solidity

**Pattern-based (30+):** everything above plus Shell, SQL, HTML, CSS, YAML,
JSON, XML, Dockerfile, Terraform and more

---

## Configuration

Settings live in `~/.kernelspy_settings.json` (never committed):

```json
{
  "output_dir": "~/KernelSpy_Output",
  "ai_provider": "google",
  "google_api_key": "<your-key-here>",
  "gguf_model_path": "path/to/model.gguf",
  "use_sast": false
}
```

Scan reports are written to `~/KernelSpy_Output` and are preserved across
uninstalls.

---

## Building from Source

**Prerequisites:** Python 3.10+, pip, [Inno Setup 6](https://jrsoftware.org/isinfo.php)

```bash
# 1. build the executable
pip install pyinstaller customtkinter
pyinstaller "KernelSpy Scanner.spec" --noconfirm --clean

# 2. build the installer
ISCC.exe KernelSpy_pro_1.4.3.iss
# result: installer/KernelSpy_Scanner_Setup_PRO_1.4.3_MultiLang.exe
```

Run the regression matrix before releasing:

```bash
python test_correctness_matrix.py     # 33 checks, exit code 0 = pass
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit: `git commit -m "Add amazing feature"`
4. Push: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please keep secrets, API keys and personal settings out of the tree — the
settings file belongs in `~/.kernelspy_settings.json`, not in the repo.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgments

[Tree-sitter](https://tree-sitter.github.io/),
[CustomTkinter](https://github.com/TomSchimansky/CustomTkinter),
[llama-cpp-python](https://github.com/abetlen/llama-cpp-python),
[Semgrep](https://semgrep.dev/),
[Trivy](https://github.com/aquasecurity/trivy),
[SARIF](https://sarifweb.azurewebsites.net/)

---

<div align="center">

Built by **The L house**

![Stars](https://img.shields.io/github/stars/i6gu1/kernelspy-exe?style=for-the-badge&logo=github&color=0ea5e9)
![Issues](https://img.shields.io/github/issues/i6gu1/kernelspy-exe?style=for-the-badge&color=f43f5e)
![License](https://img.shields.io/github/license/i6gu1/kernelspy-exe?style=for-the-badge&color=22c55e)

</div>
