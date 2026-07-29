```text
   ___   ___  ____   ____ _   _   _    ____  ____ 
  / _ \ / _ \|  _ \ / ___| | | | / \  |  _ \|  _ \
 | | | | | | | |_) | |  _| | | |/ _ \ | |_) | | | |
 | |_| | |_| |  _ <| |_| | |_| / ___ \|  _ <| |_| |
  \___/ \___/|_| \_\\____|\___/_/   \_\_| \_\____/ 
  🛡️  Laravel Security Scanner — OorGuard
```

# 🛡️ OorGuard

[![CI Status](https://github.com/AliMosbah/oorguard/actions/workflows/ci.yml/badge.svg)](https://github.com/AliMosbah/oorguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Advanced security auditing CLI for Laravel projects.**

OorGuard is a developer-facing security scanner that analyzes your Laravel project for vulnerabilities, misconfigurations, exposed secrets, and dangerous code patterns — including full support for **Laravel + Inertia.js + React + SSR + Livewire** stacks.

---

## ✨ Features

- **11 Security Check Categories** — Environment, File Exposure, Dependencies, Laravel Core, Code Patterns, Secrets, Inertia.js, React/Frontend, SSR, Livewire, Live Exposure
- **Automatic Package Inventory Table** — Automatically displays installed Composer (PHP) and NPM (JS) packages with their installed vs. required/latest versions at the very top of scan reports
- **Interactive Wizard** — run just `oorguard` for a guided scanning experience with ASCII art banner
- **Rich Terminal Output** — Colored severity badges, category grouping, summary panel, progress spinners
- **Multiple Export Formats** — Terminal, JSON, HTML (dark-themed)
- **Plugin Architecture** — Each check is independent; add custom checks without touching the core
- **CI/CD Ready** — Non-zero exit code when Critical/High issues found
- **Configurable** — `.oorguard.yml` to disable checks, ignore paths, set thresholds
- **Live Scanning** — Optional HTTP probes for exposed paths (opt-in via `--url`)
- **Dependency Auditing** — Runs `composer audit` + `npm audit` automatically

## 📦 Global Installation

To make `oorguard` available globally across your entire system (so typing `oorguard` in any terminal or cmd works immediately):

### Option 1: Install globally via `pipx` (Recommended for macOS / Linux / Windows)

`pipx` installs CLI tools in isolated environments and automatically adds them to your global PATH:

```bash
# On macOS (via Homebrew)
brew install pipx && pipx ensurepath

# Or via python3 / pip3
python3 -m pip install --user pipx && python3 -m pipx ensurepath

# Then install OorGuard directly from GitHub:
pipx install git+https://github.com/AliMosbah/oorguard.git
```

### Option 2: Install directly via `pip3` from GitHub

```bash
pip3 install git+https://github.com/AliMosbah/oorguard.git
```

### Option 3: Local Clone & Development Install

```bash
git clone https://github.com/AliMosbah/oorguard.git
cd oorguard
pip install -e .
```

After installation, the `oorguard` command is registered globally in your system PATH and can be executed from any folder!

## 🚀 Usage

### Interactive mode (recommended)

```bash
oorguard
```

This launches a guided wizard with:
- 🎨 ASCII art banner
- ☑️ Category selection (pick which checks to run)
- 📁 Project path input
- 📊 Output format choice
- 🌐 Optional live scan URL

### Direct scan

```bash
oorguard scan /path/to/laravel/project
```

### With options

```bash
# Only show High and Critical findings
oorguard scan . --min-severity high

# Export as HTML and open in browser
oorguard scan . --format html --output report.html --open

# Export as JSON for CI pipelines
oorguard scan . --format json --output results.json

# Include live exposure checks
oorguard scan . --url https://myapp.com

# Exclude specific categories
oorguard scan . --exclude-category "Live Exposure" --exclude-category "SSR"

# Use custom config
oorguard scan . --config /path/to/.oorguard.yml

# Verbose mode
oorguard scan . -v
```

### List all checks

```bash
oorguard list-checks
```

### Show version

```bash
oorguard version
```

## 🔍 Check Categories

| Category | What it detects |
|----------|----------------|
| **Environment** | .env permissions, APP_DEBUG in production, missing APP_KEY, VITE_* secrets, Laravel EOL |
| **File Exposure** | .git in public/, missing .htaccess, unsafe storage symlinks, Vite dev server exposure |
| **Dependencies** | Known vulnerabilities via `composer audit` and `npm audit` |
| **Laravel Core** | Mass assignment ($guarded=[]), CORS wildcards, CSRF exceptions, Telescope/Horizon/Debugbar |
| **Code Patterns** | Raw SQL injection, eval(), unserialize() on input, dynamic includes, Blade {!! !!} |
| **Secrets** | AWS keys, Stripe keys, GitHub tokens, hardcoded passwords in any file |
| **Inertia** | Full model sharing in props, raw Eloquent in Inertia::render(), Sanctum stateful domains |
| **React/Frontend** | dangerouslySetInnerHTML without sanitizer, eval()/new Function(), missing CSP |
| **SSR** | SSR server bound to 0.0.0.0, DoS risk notes |
| **Livewire** | Public properties without #[Locked], unprotected actions, file uploads, SQL injection, rate limiting |
| **Live Exposure** | HTTP probes for /.env, /.git, /telescope, /horizon, /debugbar (opt-in) |

## ⚙️ Configuration

Create a `.oorguard.yml` in your project root:

```yaml
# Checks to disable
disabled_checks:
  - live_exposure_scan
  - npm_audit

# Paths to ignore
ignore_paths:
  - "storage/logs/*"
  - "tests/*"

# Minimum severity
min_severity: low

# Categories to exclude
exclude_categories:
  - "SSR"
```

## 🔄 CI/CD Integration

OorGuard returns exit code `1` when Critical or High findings exist:

```bash
# In your CI pipeline
oorguard scan . --format json --output results.json || exit 1
```

### GitHub Actions example

```yaml
- name: Security Scan
  run: |
    pip install ./oorguard
    oorguard scan . --min-severity high --format json --output security-report.json
```

## 🔌 Extensibility & Custom Checks (Plugin Architecture)

OorGuard is built with a plugin-style architecture. Adding a new security check takes only a few lines using the `@register_check` decorator:

```python
# oorguard/checks/custom_check.py
from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check

@register_check(
    category="Custom",
    name="my_custom_check",
    description="Detects specific internal security compliance rule.",
)
def check_custom_rule(ctx: ScanContext) -> list[Finding]:
    findings = []
    # Check project files effortlessly
    if not ctx.file_exists("security.txt"):
        findings.append(Finding(
            severity=Severity.LOW,
            category="Custom",
            title="Missing security.txt file",
            description="Project is missing public/security.txt declaration.",
            recommendation="Add a security.txt file as per RFC 9116.",
        ))
    return findings
```

## 📊 Report Formats & Previews

### Terminal Output
A color-coded terminal interface powered by `Rich` with progress spinners, summary counts, and category tables:

```text
🛡️  OorGuard — Laravel Security Scanner

📦 Installed Packages & Available Versions
┌─────────────────────┬──────────────────┬───────────┬───────────┬──────────────────┬────────────┐
│ Package             │ Type             │ Installed │ Required  │ Latest Available │   Status   │
├─────────────────────┼──────────────────┼───────────┼───────────┼──────────────────┼────────────┤
│ laravel/framework   │ PHP (Composer)   │ 11.0.0    │ ^11.0     │ 11.4.0           │  Outdated  │
│ livewire/livewire   │ PHP (Composer)   │ 3.4.0     │ ^3.4      │ 3.4.0            │ Up-to-date │
└─────────────────────┴──────────────────┴───────────┴───────────┴──────────────────┴────────────┘

📂 Environment
┌──────────┬───────────────────────────────────────────┬────────────────┬────────────────────────────────────────────────────────┐
│ Severity │ Title                                     │ Location       │ Details                                                │
├──────────┼───────────────────────────────────────────┼────────────────┼────────────────────────────────────────────────────────┤
│ CRITICAL │ APP_DEBUG is enabled in production        │ .env:4         │ Stack traces and environment variables exposed.        │
│ CRITICAL │ VITE_* variable 'VITE_STRIPE_SECRET'      │ .env:6         │ Secret key inlined into client JS bundle by Vite.      │
└──────────┴───────────────────────────────────────────┴────────────────┴────────────────────────────────────────────────────────┘
```

### HTML Report
Dark-themed standalone HTML report with interactive cards, severity tags, and package table export (`--format html --open`).

## 🛠 Tech Stack

- **Python 3.11+**
- **Click** — CLI framework
- **Rich** — Terminal formatting
- **Requests** — HTTP live checks
- **PyYAML** — Configuration
- **Jinja2** — HTML report templates

## 👤 Author

**Ali Mosbah**
- GitHub: [@AliMosbah](https://github.com/AliMosbah)

## 📄 License

MIT License — Copyright (c) 2026 Ali Mosbah
