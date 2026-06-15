#  WebGuardian - Malware & Security Scanner

**WebGuardian** is a comprehensive security scanning tool designed to detect malware, backdoors, vulnerabilities, and security misconfigurations in PHP-based web applications, including **WordPress**, **Laravel**, **Symfony**, and other CMS/framework projects.

> **Language:** English (full documentation)  
> **Author:** WebGuardian Team  
> **License:** MIT

---

##  Features

###  Malware Detection
- **Signature-based scanning** ΓÇö known malware patterns, web shells, and backdoors
- **Heuristic analysis** ΓÇö behavior-based scoring to detect suspicious code that may not match known signatures
- **Obfuscation detection** ΓÇö identifies base64-encoded payloads, hex-encoded strings, nested deobfuscation functions (`gzinflate`, `str_rot13`, `gzuncompress`)
- **Cryptojacking detection** ΓÇö finds cryptocurrency mining scripts and mining pool connections

###  CMS-Specific Scanning
| CMS | Checks |
|-----|--------|
| **WordPress** | Core integrity, version vulnerabilities, plugin/theme analysis, upload directory security, wp-config hardening, user enumeration, must-use plugin inspection |
| **Laravel** | `.env` exposure, APP_KEY strength, debug mode, route exposure, middleware config, composer package audit, service provider analysis |
| **PrestaShop** | Version detection (1.4ΓÇô8.x), install dir exposure, admin security, module analysis, override inspection, config hardening, upload security, SSL enforcement |
| **Generic PHP** | Composer integrity, `.htaccess` security, `.git` exposure, `php.ini` misconfigurations, backup files, information disclosure |

###  Vulnerability Detection
- **SQL Injection** ΓÇö unsanitized input in database queries (CWE-89)
- **Cross-Site Scripting (XSS)** ΓÇö echoed user input without escaping (CWE-79)
- **Local File Inclusion (LFI)** ΓÇö user-controlled `include()`/`require()` (CWE-98)
- **Server-Side Request Forgery (SSRF)** ΓÇö user-controlled URLs in HTTP clients (CWE-918)
- **Insecure Deserialization** ΓÇö `unserialize()` with user input (CWE-502)
- **Header Injection** ΓÇö user input in HTTP headers (CWE-113)

###  Reporting
- **Console output** ΓÇö colorized terminal report with severity breakdown
- **JSON export** ΓÇö machine-readable structured data for CI/CD integration
- **HTML report** ΓÇö production-grade dashboard with severity badges and statistics
- **Web Dashboard** ΓÇö Tailwind CSS UI with scan form, real-time results, and version management
- **Severity classification** ΓÇö Critical / High / Medium / Low / Info

###  Automated Rule Updates
- **Cron-ready updater** ΓÇö `tools/update-rules.sh` fetches, converts, and merges rules from external sources
- **YARA converter** ΓÇö converts YARA rule files to WebGuardian JSON format
- **Source registry** ΓÇö `tools/config/rules-sources.json` manages external feeds
- **Version checker** ΓÇö Web UI shows rule count and last update; one-click update button
- **Alert notifier** ΓÇö `tools/alert-on-critical.sh` sends email/Slack on critical findings

> The project is currently in active development. The rule engine is **extensible** and allows adding custom detection patterns without modifying the core code.

---

##  Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Platform Detection](#platform-detection)
- [Output Formats](#output-formats)
- [Web Dashboard](#web-dashboard)
- [Automated Rule Updates](#automated-rule-updates)
- [Extending Rules](#extending-rules)
- [Architecture](#architecture)
- [Integration](#integration)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [License](#license)

---

##  Installation

### Requirements

- PHP 8.0 or higher
- `ext-json`
- `ext-mbstring`
- Composer (for dependency management)

### Via Composer

```bash
composer create-project nathanpixodeo/web-guardian my-security-scan
```

### Manual Installation

```bash
git clone https://github.com/nathanpixodeo/web-guardian.git
cd web-guardian
composer install
```

### Quick Install (No Composer)

```bash
git clone https://github.com/nathanpixodeo/web-guardian.git
cd web-guardian
php bin/webguardian scan /path/to/scan
```

---

##  Quick Start

Scan a WordPress site:

```bash
php bin/webguardian scan /var/www/html --type=wordpress
```

Scan a Laravel application with verbose output:

```bash
php bin/webguardian scan /var/www/myapp --type=laravel --verbose
```

Auto-detect CMS type and generate HTML report:

```bash
php bin/webguardian scan /var/www/html --format=html --output=report.html
```

---

##  Usage

### Command Line Interface

```
webguardian scan <path> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--type=<type>` | CMS type: `auto`, `wordpress`, `laravel`, `generic` | `auto` |
| `--format=<format>` | Output format: `console`, `json`, `html` | `console` |
| `--output=<file>` | Write report to file | stdout |
| `--depth=<num>` | Maximum scan depth | `10` |
| `--no-backup` | Skip backup file scanning | false |
| `--no-perm` | Skip permission checks | false |
| `--verbose` | Verbose output showing scan progress | false |
| `--rules=<path>` | Custom rules directory | built-in |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No issues found |
| `1` | Issues found (medium/low/info) |
| `2` | Critical or High severity issues found |

### Examples

#### Basic WordPress Scan

```bash
php bin/webguardian scan /var/www/mysite
```

Expected output:
```
  ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
  WebGuardian Security Scan Report
  ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ

  Scan Path:    /var/www/mysite
  CMS Type:     wordpress
  Scan Time:    2026-06-15T10:30:00+00:00
  Duration:     2340ms
  Files Scanned: 1842

  ΓöîΓöÇ Scan Summary ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
  Γöé
  Γöé   Critical: 0
  Γöé   High:     3  ΓûêΓûêΓûê
  Γöé   Medium:   5  ΓûêΓûêΓûêΓûêΓûê
  Γöé   Low:      2  ΓûêΓûê
  Γöé   Info:     1  Γûê
  Γöé
  Γöé   Total Findings: 11
  ΓööΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
```

#### JSON Output for CI/CD

```bash
php bin/webguardian scan /var/www/html --format=json --output=scan-report.json
```

Then integrate with your CI pipeline:

```yaml
# .github/workflows/security-scan.yml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run WebGuardian Scan
        run: |
          php webguardian scan . --format=json --output=report.json
          if [ $? -eq 2 ]; then exit 1; fi
```

#### Scanning Remote Directories via SSH

```bash
ssh user@server "php /path/to/webguardian scan /var/www --format=json" > remote-scan.json
```

---

##  Platform Detection

WebGuardian auto-detects the CMS type:

| Indicator | Detected Type |
|-----------|---------------|
| `wp-config.php` exists | **WordPress** |
| `artisan` exists + `app/` directory | **Laravel** |
| `config/settings.inc.php` exists, or `modules/` + `themes/` dirs present | **PrestaShop** |
| None of the above | **Generic PHP** |

You can override detection with `--type=<type>`.

---

##  Output Formats

### Console Format
Colorized terminal output with severity-bucketed findings, progress information, and a summary dashboard. Includes ANSI color codes for readability.

### JSON Format
Structured data ideal for CI/CD pipelines and automated processing:

```json
{
  "metadata": {
    "scanned_at": "2026-06-15T10:30:00+00:00",
    "path": "/var/www/html",
    "type": "wordpress",
    "duration_ms": 2340,
    "files_scanned": 1842,
    "scanner_version": "1.0.0"
  },
  "summary": {
    "critical": 0,
    "high": 3,
    "medium": 5,
    "low": 2,
    "info": 1,
    "total": 11
  },
  "findings": [
    {
      "file": "/var/www/html/wp-content/plugins/evil.php",
      "line": 42,
      "pattern": "base64_eval",
      "severity": "critical",
      "type": "malware",
      "message": "eval() wrapping base64_decode() - classic PHP malware deobfuscation pattern",
      "context": "eval(base64_decode($_POST['cmd']));"
    }
  ]
}
```

### HTML Format
A production-grade responsive dashboard featuring:
- Severity-colored status banner
- Statistics grid with severity counts
- Detailed findings table
- Meta information panel
- Export-friendly layout

---

##  Web Dashboard

WebGuardian includes a production-grade web dashboard built with **Tailwind CSS** for visual scan management.

### Starting the Dashboard

```bash
php -S localhost:8080 -t public/
```

Then open `http://localhost:8080` in your browser.

### Dashboard Features

| Feature | Description |
|---------|-------------|
| **Scan Form** | Input path, select CMS type, configure depth and options |
| **Real-time Results** | Severity-colored status banner, stats grid, findings list |
| **Rules Version Card** | Shows built-in + external rule count, last update timestamp |
| **Check Version** | Fetches current rule status from the detection engine |
| **Update Now** | Runs the external rule updater and refreshes display |
| **Responsive Design** | Works on desktop and mobile devices |
| **Keyboard Shortcut** | Ctrl+Enter to submit scan form |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `?api=rules_status` | GET | Returns rule counts, last update, and file list |
| `?api=update_rules` | GET | Triggers `tools/update-rules.sh` and returns updated status |

---

##  Automated Rule Updates

WebGuardian includes a complete automation pipeline for keeping detection rules current.

### Architecture

```
External Sources (YARA repos, community feeds)
        Γöé
        Γû╝
tools/update-rules.sh    <- Cron: 0 3 * * *
        Γöé
        +---> Download raw rule files
        +---> Convert YARA -> JSON (yara-converter.php)
        +---> Merge into rules/external/
                Γöé
                Γû╝
        Scanners load external rules automatically
                Γöé
                Γû╝
        Web UI shows version + Update Now button
```

### One-Command Update

```bash
# Update all enabled sources
./tools/update-rules.sh

# Check current status
./tools/update-rules.sh --status

# Dry run (preview only)
./tools/update-rules.sh --dry-run

# List available sources
./tools/update-rules.sh --list
```

### Source Registry

Edit `tools/config/rules-sources.json` to add or remove external sources:

```json
{
  "sources": [
    {
      "id": "yara_php_malware",
      "name": "YARA PHP Malware Rules",
      "type": "yara",
      "url": "https://raw.githubusercontent.com/.../php_malware.yar",
      "enabled": true,
      "severity_map": {
        "MALWARE": "critical",
        "WEBSHELL": "critical"
      }
    }
  ]
}
```

### Cron Setup

```bash
# Edit crontab
crontab -e

# Update rules daily at 3:00 AM
0 3 * * * /opt/webguardian/tools/update-rules.sh --quiet >> /var/log/webguardian-update.log 2>&1

# Run scan daily at 4:00 AM after update
0 4 * * * /opt/webguardian/bin/webguardian scan /var/www/html --format=json --output=/var/reports/daily-scan.json
```

### Alert on Critical Findings

```bash
# Send email when critical issues are found
./tools/alert-on-critical.sh /var/reports/scan.json admin@example.com

# Send to Slack webhook
./tools/alert-on-critical.sh /var/reports/scan.json "" https://hooks.slack.com/...
```

### Tools Reference

| Tool | Purpose |
|------|---------|
| `tools/update-rules.sh` | Main updater: fetches, converts, merges external rules |
| `tools/yara-converter.php` | Converts YARA `.yar` files to WebGuardian JSON format |
| `tools/alert-on-critical.sh` | Sends email/Slack alerts on critical/high findings |
| `tools/config/rules-sources.json` | Registry of external rule source URLs |
| `tools/config/crontab.example` | Ready-to-use cron job templates |

---

##  Extending Rules

### JSON Rule Files

Place custom rules in a directory and reference with `--rules=<path>`:

```json
{
  "version": "1.0.0",
  "patterns": [
    {
      "id": "my_custom_pattern",
      "pattern": "suspicious_function\\s*\\(",
      "severity": "high",
      "type": "custom",
      "message": "My custom detection rule"
    }
  ]
}
```

### Rule Structure

| Field | Description | Required |
|-------|-------------|----------|
| `id` | Unique identifier for the rule |  |
| `pattern` | Regex pattern to match |  |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |  |
| `type` | Category of the finding |  |
| `message` | Human-readable description |  |
| `multiLine` | If true, scans entire file content |  |
| `negative` | If true, checks for absence of pattern |  |

### Rule Sources

WebGuardian rules come from three tiers:

| Tier | Source | Format | Update Method |
|------|--------|--------|---------------|
| **Built-in** | Bundled with WebGuardian (`rules/*.json`) | WebGuardian JSON | Release cycle |
| **External** | Community feeds, YARA repos, advisory databases | YARA / JSON | `tools/update-rules.sh` (cron) |
| **Custom** | User-defined rules directory | WebGuardian JSON | `--rules=<path>` |

**Built-in rule files and their origins:**

| File | Sources |
|------|---------|
| `rules/malware-patterns.json` | PHP malware signatures, web shell fingerprints, cryptojacking patterns (YARA community, malware analysis) |
| `rules/wordpress-suspicious.json` | WPScan, WordPress plugin vulnerabilities, core integrity checks |
| `rules/laravel-backdoors.json` | Laravel security advisories, common misconfigurations, known exploit patterns |
| `rules/prestashop-suspicious.json` | PrestaShop forums, security blog, Friends-Of-Presta advisories, digital skimmer patterns |
| `rules/prestashop-vulnerabilities.json` | Friends-Of-Presta CVE database, NVD NIST, PrestaShop security advisories (60+ CVEs from 1.4.x to 8.x) |
| `rules/generic-threats.json` | Generic PHP threats, `.env` exposure, `.git` exposure, htaccess misconfigurations |

External sources are configured in `tools/config/rules-sources.json` and fetched by `tools/update-rules.sh`.

### Programmatic Extension

```php
use WebGuardian\Scanner;

$scanner = new Scanner('/path/to/scan', [
    'rules' => '/path/to/custom/rules'
]);
$results = $scanner->run();
```

---

##  Architecture

```
webguardian/
+-- bin/
|   +-- webguardian            # CLI entry point
+-- src/
|   +-- Scanner.php            # Main scanner orchestrator
|   +-- Scanner/
|   |   +-- WordPressScanner.php
|   |   +-- LaravelScanner.php
|   |   +-- PrestaShopScanner.php
|   |   +-- GenericScanner.php
|   +-- Detector/
|   |   +-- MalwareDetector.php   # Signature + external rules
|   |   +-- BackdoorDetector.php  # Heuristic scoring
|   |   +-- VulnerabilityDetector.php
|   +-- Analyzer/
|   |   +-- FileAnalyzer.php
|   |   +-- DatabaseAnalyzer.php
|   +-- Report/
|       +-- ReportGenerator.php
|       +-- Formatters/
|           +-- ConsoleFormatter.php
|           +-- JsonFormatter.php
|           +-- HtmlFormatter.php
+-- rules/
|   +-- malware-patterns.json    # Built-in signatures
|   +-- wordpress-suspicious.json
|   +-- laravel-backdoors.json
|   +-- prestashop-suspicious.json
|   +-- prestashop-vulnerabilities.json
|   +-- generic-threats.json
|   +-- external/                # Auto-updated external rules
|       +-- .gitkeep
+-- tools/
|   +-- update-rules.sh          # Cron-ready external updater
|   +-- yara-converter.php       # YARA -> JSON converter
|   +-- alert-on-critical.sh     # Email/Slack notifier
|   +-- config/
|       +-- rules-sources.json   # External source registry
|       +-- crontab.example      # Cron job templates
+-- public/
|   +-- index.php                # Web dashboard (Tailwind CSS)
+-- tests/
+-- docs/
|   +-- ARCHITECTURE.md
|   +-- USAGE.md
|   +-- RULES.md
|   +-- CONTRIBUTING.md
+-- composer.json
+-- LICENSE
+-- README.md
```

### Data Flow

```
User Input (path + options)
         |
         v
   Scanner (orchestrator)
         |
         +---> CMS Scanner ---> WordPress / Laravel / Generic
         |
         +---> File Walker ---> FilesystemIterator
         |
         +---> MalwareDetector ---> Signature matching + heuristics
         |
         +---> BackdoorDetector ---> Scoring-based detection
         |
         +---> VulnerabilityDetector ---> Pattern matching (SQLi, XSS, LFI, SSRF)
         |
         +---> FileAnalyzer ---> Permissions, sensitive data
         |
         +---> DatabaseAnalyzer ---> Config exposure, SQL dumps
                  |
                  v
         ReportGenerator
                  |
                  v
         Formatter ---> Console / JSON / HTML
```

---

##  Detection Engine Details

### Signature-Based Detection
The scanner maintains a database of known malware signatures, web shell fingerprints, and exploit patterns. These are regex patterns that target specific code patterns commonly found in malicious software.

### Heuristic (Scoring) Detection
The backdoor detector assigns weighted scores to each line of code based on the presence of dangerous functions, obfuscation techniques, and suspicious patterns. Lines exceeding a configurable threshold (default: 70) are flagged.

**Scoring Weights:**

| Feature | Weight |
|---------|--------|
| `eval()` | 50 |
| System command execution | 40 |
| File write with user input | 25 |
| Base64 obfuscation | 10 |
| Network operations | 15 |
| User input in dangerous context | 30 |
| Multiple dangerous functions per line | +15 each |

### Vulnerability Pattern Matching
The vulnerability detector scans for common web application security flaws using regex patterns mapped to CWE identifiers:
- SQL Injection -> CWE-89
- XSS -> CWE-79
- LFI -> CWE-98
- SSRF -> CWE-918
- Header Injection -> CWE-113
- Insecure Deserialization -> CWE-502

### CMS-Specific Analysis
WordPress and Laravel scanners include framework-specific checks that go beyond generic pattern matching, analyzing core file integrity, configuration hardening, and known vulnerability vectors.

---

##  Integration

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
      - name: Install WebGuardian
        run: |
          git clone https://github.com/nathanpixodeo/web-guardian.git
          cd web-guardian && composer install --no-dev
      - name: Run Security Scan
        run: |
          php scanner/bin/webguardian scan . --format=json --output=report.json
          if [ $? -eq 2 ]; then
            echo "::error::Critical or High severity issues found!"
            cat report.json
            exit 1
          fi
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
php /path/to/webguardian scan --staged --format=json > /dev/null
if [ $? -eq 2 ]; then
    echo "ERROR: Security issues detected in staged changes!"
    exit 1
fi
```

### Monitoring Script

```bash
#!/bin/bash
# Scheduled scan with email notification
php /opt/webguardian/bin/webguardian scan /var/www --format=json > /tmp/scan.json
if [ $? -ge 2 ]; then
    mail -s "Security Alert: Issues found on $(hostname)" admin@example.com < /tmp/scan.json
fi
```

---

## FAQ

### How does WebGuardian detect malware?
It uses a combination of signature-based pattern matching (known malware patterns), heuristic scoring (behavioral analysis), and CMS-specific checks.

### Does it scan database contents?
Currently, WebGuardian scans filesystem-level code. Database scanning is planned for a future release.

### Can it be used in production?
Yes. WebGuardian is designed for production use. It performs read-only operations and does not modify any files.

### How often are detection rules updated?
Built-in rules are updated with each release. You can also maintain your own custom rules directory.

### Does it require internet access?
No. All scanning is performed locally. No data is sent to external servers.

### Can it scan non-PHP files?
Yes, WebGuardian scans various file types including JS, HTML, .htaccess, .env, and configuration files for relevant security issues.

---

## Contributing

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

### Development Setup

```bash
git clone https://github.com/nathanpixodeo/web-guardian.git
cd web-guardian
composer install
composer test
```

---

## Changelog

### 2026-06-15 - Async scan with real-time progress + directory filtering

- **New**: Web dashboard now runs scans asynchronously (background process) — no more page blocking during scan
- **New**: Real-time progress bar showing files scanned, findings count, current file, elapsed time
- **New**: `?api=start_scan`, `?api=scan_progress`, `?api=scan_results` API endpoints for async scan management
- **New**: Scanner.php now accepts `progress_file` option and writes JSON progress updates during scanning
- **New**: CLI `--progress=<file>` option for progress output
- **Fixed**: `checkInformationDisclosure()` now uses `RecursiveCallbackFilterIterator` to skip `vendor/`, `node_modules/`, `storage/`, `cache/`, hidden dirs, and files >10MB — prevents timeout on large projects
- **Fixed**: Added `set_time_limit(0)` in `checkInformationDisclosure()` to prevent execution timeout
- **Affected files**: `src/Scanner/GenericScanner.php`, `src/Scanner.php`, `bin/webguardian`, `public/index.php`

### 2026-06-15 - Performance fix: chunked file reading in GenericScanner

- **Fixed**: `Maximum execution time` timeout error in `checkInformationDisclosure()` when scanning large projects
- **Change**: Replaced `file_get_contents()` (loads entire file into memory) with `fopen()` + `fread()` chunked reading (8KB buffers)
- **Benefit**: Eliminates timeout on large files, reduces memory usage, and early-exits as soon as the pattern is found
- **Affected file**: `src/Scanner/GenericScanner.php`

---

## License

This project is licensed under the MIT License -- see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

WebGuardian performs static code analysis and may produce both false positives and false negatives. Always review findings manually before taking action. The authors are not responsible for any damage resulting from the use of this tool.

---

<p align="center">Built with love for the security community</p>
