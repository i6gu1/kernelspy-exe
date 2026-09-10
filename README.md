<div align="center">

# 🔒 KernelSpy Scanner v1.1.0

### Advanced Code Security Scanner with AI & Multi-Engine Analysis

![Python](https://img.shields.io/badge/Python-3.13-blue?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Version](https://img.shields.io/badge/Version-1.1.0-orange?style=flat)
![Platform](https://img.shields.io/badge/Platform-Windows-blue?style=flat&logo=windows&logoColor=white)
![Tree-sitter](https://img.shields.io/badge/Tree--sitter-Multi--Language-purple?style=flat)
![AI](https://img.shields.io/badge/AI-Google%20Gemini%20%7C%20Local%20GGUF-red?style=flat)

**Detect leaked secrets, security vulnerabilities, and code vulnerabilities across 30+ programming languages.**

[Download Installer](https://github.com/i6gu1/kernelspy-exe/releases) • [Report Bug](https://github.com/i6gu1/kernelspy-exe/issues) • [Request Feature](https://github.com/i6gu1/kernelspy-exe/issues)

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Screenshots](#-screenshots)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [AI Integration](#-ai-integration)
- [SAST Engines](#-sast-engines)
- [Export Formats](#-export-formats)
- [Supported Languages](#-supported-languages)
- [Configuration](#-configuration)
- [Building from Source](#-building-from-source)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### 🔍 Core Scanning Engine
- **Pattern-Based Detection**: 100+ security rules for secrets, vulnerabilities, and misconfigurations
- **AST Analysis**: Python Abstract Syntax Tree deep analysis
- **Lexer Analysis**: Token-based analysis for PHP, JavaScript, TypeScript, Java
- **Taint Tracking**: Multi-language source-to-sink vulnerability detection
- **Context-Aware Analysis**: Eliminates false positives by understanding code context

### 🌳 Tree-sitter Integration
- **Unified Parsing**: Single parser for 18+ programming languages
- **Concrete Syntax Tree**: Accurate code structure analysis
- **Cross-Language Rules**: Write security rules once, apply to all languages

### 📊 Code Property Graph (CPG)
- **AST**: Abstract Syntax Tree for code structure
- **CFG**: Control Flow Graph for execution path analysis
- **DDG**: Data Dependency Graph for variable flow tracking
- **Taint Analysis**: Precise source-to-sink vulnerability detection

### 🛡️ SAST Engine Orchestration
- **Semgrep**: Pattern-based security scanning (30+ languages)
- **Trivy**: Dependency vulnerability scanning
- **SonarScanner**: Code quality and security analysis

### 🤖 AI-Powered Analysis
- **Google AI Studio**: Gemini API integration for intelligent code analysis
- **Local GGUF Models**: Offline AI analysis via llama-cpp-python
- **AI Chat**: Interactive security assistant for code review

### 📦 Professional Features
- **SARIF Export**: Industry-standard JSON format (GitHub/Microsoft compatible)
- **Multi-Language UI**: English & Arabic support
- **Dark Theme**: Professional cyber-security aesthetic
- **Explorer Integration**: Right-click folder scanning
- **Zero Dependencies at Runtime**: Only requires `customtkinter`

---

## 🏗️ Architecture

```
KernelSpy Scanner v1.1.0
├── core/
│   ├── engine/
│   │   ├── scanner.py              # Main scanning orchestrator
│   │   ├── patterns.py             # Pattern matching engine
│   │   ├── context.py              # Comment/string stripping
│   │   ├── context_analyzer.py     # Cross-language detectors
│   │   ├── ast_analyzer.py         # Python AST analysis
│   │   ├── lexer_analyzer.py       # Token-based analysis
│   │   ├── taint_tracker.py        # Multi-language taint analysis
│   │   ├── tree_sitter_parser.py   # Tree-sitter integration
│   │   ├── cpg.py                  # Code Property Graph builder
│   │   ├── sast_orchestrator.py    # External SAST tools integration
│   │   └── ai_analyzer.py          # AI integration (Google + GGUF)
│   ├── analyzers/                  # Per-language analyzers
│   ├── rules/                      # Security rule definitions
│   └── reporting/                  # Report generation
│       ├── html_report.py
│       ├── csv_report.py
│       ├── json_report.py
│       └── sarif_report.py
├── main.py                         # GUI application
├── requirements.txt                # Python dependencies
└── KernelSpy Scanner.spec          # PyInstaller configuration
```

---

## 📸 Screenshots

<div align="center">

| Home | Scan | Results |
|:---:|:---:|:---:|
| ![Home](ui%20pic/1.jpg) | ![Scan](ui%20pic/2.jpg) | ![Results](ui%20pic/less.jpg) |

</div>

---

## 🚀 Installation

### Option 1: Download Installer (Recommended)

Download the latest installer from [Releases](https://github.com/i6gu1/kernelspy-exe/releases):

```
KernelSpy_Scanner_Setup_PRO_1.1.0.exe
```

### Option 2: Run from Source

```bash
# Clone the repository
git clone https://github.com/i6gu1/kernelspy-exe.git
cd kernelspy-exe

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Option 3: Build Executable

```bash
# Install PyInstaller
pip install pyinstaller

# Build the executable
pyinstaller "KernelSpy Scanner.spec"

# The executable will be in the dist/ folder
```

---

## 🎯 Quick Start

1. **Launch** KernelSpy Scanner
2. **Click** "Start Scan" or drag a project folder
3. **View** real-time results in the scan table
4. **Export** reports in CSV, HTML, JSON, or SARIF format

### Command Line

```bash
# Scan a specific folder
"./KernelSpy Scanner.exe" "C:\path\to\project"

# Via Explorer context menu (after installation)
# Right-click any folder → "Scan with KernelSpy"
```

---

## 🤖 AI Integration

### Google AI Studio

1. Get an API key from [Google AI Studio](https://aistudio.google.com/apikey)
2. Open Settings → Enter your API key
3. Use the AI Chat page for intelligent code analysis

### Local GGUF Models

1. Download a GGUF model from [Hugging Face](https://huggingface.co/models?search=gguf+coder)
2. Recommended models:
   - `Qwen2.5-Coder-1.5B-Instruct` (Lightweight, 1GB RAM)
   - `DeepSeek-Coder-6.7B-Instruct` (Balanced, 8GB RAM)
   - `Qwen2.5-Coder-32B-Instruct` (Advanced, 24GB RAM)
3. Open Settings → Load Model → Select your .gguf file

---

## 🛡️ SAST Engines

| Engine | Status | Description |
|--------|--------|-------------|
| **Semgrep** | Optional | Pattern-based security scanning |
| **Trivy** | Optional | Dependency vulnerability scanning |
| **SonarScanner** | Optional | Code quality and security analysis |

Enable in Settings → "Enable External SAST Engines"

---

## 📦 Export Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| **CSV** | `.csv` | Spreadsheet-compatible format |
| **HTML** | `.html` | Professional dark-themed report |
| **JSON** | `.json` | Structured data format |
| **SARIF** | `.sarif` | Industry standard (GitHub/Microsoft) |

---

## 🌐 Supported Languages

### Tree-sitter (18 Languages)
Python • JavaScript • TypeScript • Java • Go • Rust • C • C++ • C# • PHP • Ruby • Kotlin • Swift • Lua • Perl • Dart • Scala • Solidity

### Pattern-Based (30+ Languages)
All above plus: Shell • SQL • HTML • CSS • YAML • JSON • XML • Dockerfile • Terraform • And more

---

## ⚙️ Configuration

Settings are saved to `~/.kernelspy_settings.json`:

```json
{
  "output_dir": "~/KernelSpy_Output",
  "ai_provider": "google",
  "google_api_key": "your-api-key",
  "gguf_model_path": "path/to/model.gguf",
  "use_sast": false
}
```

---

## 🔧 Building from Source

### Prerequisites
- Python 3.10+
- pip
- Inno Setup 6 (for installer)

### Build Steps

```bash
# 1. Install build dependencies
pip install pyinstaller customtkinter

# 2. Build executable
pyinstaller "KernelSpy Scanner.spec"

# 3. Build installer (optional)
# Open KernelSpy_pro.iss with Inno Setup Compiler
# Or run: ISCC.exe KernelSpy_pro.iss
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Tree-sitter](https://tree-sitter.github.io/) - Multi-language parsing
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - Modern UI framework
- [llama-cpp-python](https://github.com/abetlen/llama-cpp-python) - Local AI inference
- [Semgrep](https://semgrep.dev/) - Pattern-based analysis
- [Trivy](https://github.com/aquasecurity/trivy) - Dependency scanning
- [SARIF](https://sarifweb.azurewebsites.net/) - Standard reporting format

---

<div align="center">

**Programmed with ❤️ by The L house**

[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/i6gu1/kernelspy-exe)

</div>
