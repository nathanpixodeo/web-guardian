# WebGuardian Architecture

## Overview

WebGuardian follows a modular, pipeline-based architecture designed for extensibility and maintainability. The scan process is divided into distinct phases, each handled by specialized components.

## Core Design Principles

1. **Separation of Concerns** — Each component has a single, well-defined responsibility
2. **Extensibility** — New scanners, detectors, and formatters can be added without modifying core code
3. **Performance** — Efficient file traversal with configurable depth limits and file filtering
4. **Safety** — Read-only operations; no files are modified during scanning

## Component Architecture

### 1. Entry Point (`bin/webguardian`)

The CLI entry point handles:
- Argument parsing and validation
- CMS type auto-detection
- Scanner instantiation
- Report generation and formatting

### 2. Scanner (`src/Scanner.php`)

The central orchestrator that:
- Coordinates all scanning phases
- Manages file system traversal
- Aggregates findings from all detectors
- Deduplicates and sorts results by severity
- Tracks scan metrics (files scanned, duration)

### 3. CMS Scanners (`src/Scanner/`)

Framework-specific scanners that extend detection capabilities:

- **WordPressScanner** — Checks core integrity, version vulnerabilities, plugin/theme security, upload directories, wp-config hardening, user enumeration
- **LaravelScanner** — Inspects .env security, APP_KEY strength, debug mode, route exposure, middleware configuration, composer dependencies
- **GenericScanner** — Analyzes composer.json integrity, .htaccess security, .git exposure, php.ini settings, backup files, information disclosure

### 4. Detectors (`src/Detector/`)

Detection engines that perform specialized analysis:

- **MalwareDetector** — Signature-based detection using regex pattern matching against known malware signatures, web shells, cryptominers, and spam injections
- **BackdoorDetector** — Heuristic scoring system that assigns weighted scores to code lines based on dangerous function combinations, obfuscation techniques, and suspicious patterns
- **VulnerabilityDetector** — Pattern matching for common web vulnerabilities (SQLi, XSS, LFI, SSRF, deserialization, header injection) mapped to CWE identifiers

### 5. Analyzers (`src/Analyzer/`)

Supporting analysis modules:

- **FileAnalyzer** — Detects sensitive data exposure (API keys, passwords, certificates) and checks file permissions
- **DatabaseAnalyzer** — Identifies exposed database configuration files and SQL dump files

### 6. Report System (`src/Report/`)

Flexible reporting pipeline:

- **ReportGenerator** — Aggregates findings into structured report format with metadata, summary statistics, type/severity groupings, and top affected files
- **Formatters** — Render reports in multiple formats:
  - **ConsoleFormatter** — Colorized terminal output with severity-bucketed findings
  - **JsonFormatter** — Machine-readable structured data
  - **HtmlFormatter** — Production-grade responsive dashboard with Tailwind CSS styling

### 7. Rule Engine (`rules/`)

JSON-based rule definitions organized by category:
- `malware-patterns.json` — Cross-platform malware signatures
- `wordpress-suspicious.json` — WordPress-specific threats
- `laravel-backdoors.json` — Laravel-specific vulnerabilities
- `generic-threats.json` — General web application threats
- `external/` — Auto-updated rules from external sources (YARA, community feeds)

External rules are loaded automatically by `MalwareDetector::loadExternalPatterns()` and merged with built-in patterns.

### 8. Tools (`tools/`)

Automation scripts for rule lifecycle management:

| Tool | Function |
|------|----------|
| `update-rules.sh` | Downloads, converts (YARA→JSON), and merges external rules |
| `yara-converter.php` | Converts YARA rule files to WebGuardian JSON schema |
| `alert-on-critical.sh` | Email/Slack notification on critical findings |
| `config/rules-sources.json` | Registry of external rule source URLs |
| `config/crontab.example` | Ready-to-use cron job templates |

### 9. Web Dashboard (`public/`)

Tailwind CSS web interface providing:
- Scan form with CMS type selection
- Real-time results display with severity breakdown
- Rules version card with check/update buttons
- REST API endpoints for rule status and updates

## Data Flow

```
┌──────────────────────┐     ┌──────────────────┐     ┌───────────────┐
│ External Sources     │     │  Scanner         │────▶│  File Walker  │
│ (YARA, community,   │────▶│  (Orchestrator)  │     └───────┬───────┘
│  commercial feeds)  │     └────────┬─────────┘             │
└──────────┬───────────┘              │                       │
           │                          │                       │
           ▼                          │                       │
┌────────────────────┐                │                       │
│ tools/update-      │                │                       │
│ rules.sh + yara-   │                │                       │
│ converter.php      │                │                       │
│                    │                │                       │
│ (cron: 0 3 * * *)  │                │                       │
└──────────┬─────────┘                │                       │
           │                          │                       │
           ▼                          │                       │
┌────────────────────┐  ┌──────────────┼───────────────────────┘
│ rules/external/    │  │              │
│ (.json files)      │  │              │
└──────────┬─────────┘  │              │
           │             ▼              ▼
           │     ┌────────────┐  ┌──────────────┐
           └────▶│ CMS        │  │ Detectors    │
                 │ Scanner    │  │ & Analyzers  │
                 └────────────┘  └──────┬───────┘
                                        │
                                        ▼
                                ┌───────────────┐
                                │ Report        │
                                │ Generator     │
                                └───────┬───────┘
                                        │
                                        ▼
                                ┌───────────────┐
                                │ Formatter     │
                                │ (Console/     │
                                │  JSON/HTML)   │
                                └───────────────┘
```

## Class Diagram

```
Scanner
├── MalwareDetector
│   └── Pattern[] (from rules/*.json)
├── BackdoorDetector
│   └── HeuristicScorer
├── VulnerabilityDetector
│   └── Pattern[] (SQLi, XSS, LFI, SSRF, etc.)
├── FileAnalyzer
│   └── SensitiveDataDetector
│   └── PermissionChecker
├── DatabaseAnalyzer
│   └── ConfigExposureDetector
├── WordPressScanner
│   ├── CoreIntegrityChecker
│   ├── VersionVulnerabilityChecker
│   ├── PluginThemeAnalyzer
│   └── UploadSecurityChecker
├── LaravelScanner
│   ├── EnvSecurityChecker
│   ├── RouteExposureChecker
│   └── ComposerAuditor
└── GenericScanner
    ├── HtaccessAnalyzer
    ├── GitExposureChecker
    └── PhpConfigAnalyzer
```

## Extension Points

### Adding a New CMS Scanner

1. Create `src/Scanner/YourCmsScanner.php` implementing a `scan(): array` method
2. Add the detection logic in `Scanner.php` `run()` method
3. Add auto-detection rules in `bin/webguardian`

### Adding a New Detector

1. Create `src/Detector/YourDetector.php`
2. Implement analysis methods returning finding arrays
3. Register the detector in `Scanner.php`

### Adding a New Report Format

1. Create `src/Report/Formatters/YourFormatter.php` implementing `format(array $report): string`
2. Add format option in `bin/webguardian` CLI argument parsing

### Adding Detection Rules

Add JSON rule files to the `rules/` directory or use a custom rules path at scan time.

## Performance Considerations

- Files larger than 10MB are skipped
- Binary file extensions (images, archives, fonts) are excluded
- Configurable scan depth (default: 10)
- Vendor and node_modules directories are skipped by default
- Deduplication prevents redundant findings
- Findings are limited in output for large result sets
- Chunked file reading (8KB) used in file content scanning to avoid loading entire files into memory

## Security Considerations

- Read-only operations — no files are modified
- No network requests — all scanning is local
- No data exfiltration — results stay on the scanning machine
- Configurable skip lists to avoid scanning sensitive system files
