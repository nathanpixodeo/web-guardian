# WebGuardian Usage Guide

## Installation

### System Requirements

- **PHP**: Version 8.0 or newer (64-bit recommended)
- **Extensions**: `json`, `mbstring`
- **Disk**: At least 100MB for installation and temporary scan data
- **Memory**: 128MB minimum, 256MB recommended for large codebases

### Composer Installation (Recommended)

```bash
# Install globally
composer global require nathanpixodeo/web-guardian

# Or create a new project
composer create-project nathanpixodeo/web-guardian .

# Or add to existing project
composer require --dev nathanpixodeo/web-guardian
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/nathanpixodeo/web-guardian.git
cd webguardian

# Install dependencies
composer install --no-dev

# Make the CLI executable
chmod +x bin/webguardian
```

### Docker

```bash
# Build the image
docker build -t webguardian .

# Run a scan
docker run --rm -v /path/to/scan:/app/target webguardian scan /app/target
```

## Comprehensive CLI Reference

### Global Options

| Option | Description | Default |
|--------|-------------|---------|
| `--help`, `-h` | Display help information | — |
| `--version` | Display version information | — |

### Scan Command Options

```
webguardian scan <path> [options]
```

#### Path Argument

The `<path>` argument specifies the target directory to scan. It must be a readable directory.

```bash
# Scan current directory
webguardian scan .

# Scan absolute path
webguardian scan /var/www/html

# Scan relative path
webguardian scan ../../projects/myapp
```

#### Type Detection Options

| Option | Description |
|--------|-------------|
| `--type=auto` | Automatically detect CMS type (default) |
| `--type=wordpress` | Force WordPress-specific scanning |
| `--type=laravel` | Force Laravel-specific scanning |
| `--type=generic` | Generic PHP application scanning |

Auto-detection logic:
- **WordPress**: Presence of `wp-config.php` or `wp-config-sample.php`
- **Laravel**: Presence of `artisan` + `app/` directory
- **Generic**: Fallback when no CMS is detected

#### Output Options

| Option | Description |
|--------|-------------|
| `--format=console` | Colorized terminal output (default) |
| `--format=json` | Machine-readable JSON output |
| `--format=html` | HTML dashboard report |
| `--output=<file>` | Write report to file instead of stdout |

#### Scan Control Options

| Option | Description |
|--------|-------------|
| `--depth=<n>` | Maximum directory depth to scan (default: 10) |
| `--no-backup` | Skip scanning for backup files |
| `--no-perm` | Skip file permission checks |
| `--verbose` | Enable verbose progress output |
| `--rules=<path>` | Custom rules directory path |
| `--no-progress` | Disable progress indicator |

## Scan Scenarios

### 1. Quick Security Check

Run a default scan with auto-detection:

```bash
webguardian scan /var/www/myapp
```

### 2. Thorough Audit

Full scan with all checks enabled:

```bash
webguardian scan /var/www/myapp --verbose
```

### 3. CI/CD Integration

Generate JSON output for automated processing:

```bash
webguardian scan . --format=json --output=ci-report.json
```

### 4. Compliance Report

Generate an HTML report for documentation purposes:

```bash
webguardian scan /var/www/production --format=html --output=/var/www/reports/security-scan-$(date +%Y%m%d).html
```

### 5. Targeted Component Scan

Scan only specific directories:

```bash
# Scan plugins directory only
webguardian scan /var/www/html/wp-content/plugins --type=wordpress

# Scan custom theme
webguardian scan /var/www/html/wp-content/themes/my-theme --type=wordpress
```

### 6. Multi-Site Scan with Bash

```bash
#!/bin/bash
SITES=("/var/www/site1" "/var/www/site2" "/var/www/site3")
for site in "${SITES[@]}"; do
    echo "Scanning $site..."
    php /opt/webguardian/bin/webguardian scan "$site" --format=json \
        --output="/var/reports/$(basename $site)-scan.json"
done
```

## Understanding Scan Results

### Severity Levels

| Level | Description | Action Required |
|-------|-------------|-----------------|
| **Critical** | Active malware, backdoor, or remote code execution | Immediate investigation and remediation |
| **High** | Vulnerability that could lead to compromise, exposed credentials | Fix as soon as possible |
| **Medium** | Security misconfiguration, missing hardening | Address in next maintenance cycle |
| **Low** | Best practice violation, minor information disclosure | Consider during regular audits |
| **Info** | Informational observation | Review for context |

### Finding Structure

Each finding contains:

```json
{
    "file": "/var/www/html/wp-content/plugins/evil.php",
    "line": 42,
    "pattern": "base64_eval",
    "severity": "critical",
    "type": "malware",
    "message": "eval() wrapping base64_decode() - classic PHP malware deobfuscation pattern",
    "context": "eval(base64_decode($_POST['cmd']));"
}
```

| Field | Description |
|-------|-------------|
| `file` | Absolute path to the affected file |
| `line` | Line number (0 if file-level) |
| `pattern` | Detection pattern identifier |
| `severity` | Severity classification |
| `type` | Category: `malware`, `backdoor`, `vulnerability`, `sensitive`, `permission`, or CMS-specific |
| `message` | Human-readable description |
| `context` | First 200 characters of the matched code |

## Advanced Usage

### Custom Rules Directory

Create a directory with JSON rule files:

```bash
mkdir -p /etc/webguardian/rules

# Create a custom rule file
cat > /etc/webguardian/rules/custom.json << 'EOF'
{
    "version": "1.0.0",
    "patterns": [
        {
            "id": "my_backdoor",
            "pattern": "my_suspicious_function\\s*\\(",
            "severity": "critical",
            "type": "custom",
            "message": "Custom backdoor detection"
        }
    ]
}
EOF

# Scan with custom rules
webguardian scan /var/www/html --rules=/etc/webguardian/rules
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `WEBGUARDIAN_RULES_PATH` | Default rules directory path |
| `WEBGUARDIAN_NO_COLOR` | Disable colored output (set to 1) |
| `WEBGUARDIAN_THRESHOLD` | Backdoor heuristic threshold (default: 70) |

### Ignoring Specific Directories

The scanner automatically ignores:
- Hidden directories (starting with `.`)
- `vendor/` (Composer dependencies)
- `node_modules/`
- `storage/` (Laravel cache/logs)
- `cache/`

These are built-in exclusions. To add more, modify the `walkDirectory` method in `Scanner.php`.

## Web Dashboard

WebGuardian includes a built-in web dashboard built with Tailwind CSS for visual scan management.

### Starting the Dashboard

```bash
php -S localhost:8080 -t public/
```

Then open `http://localhost:8080` in your browser.

### Dashboard Sections

| Section | Description |
|---------|-------------|
| **Scan Form** | Input path, select CMS type (auto/wordpress/laravel/generic), depth, options |
| **Results Display** | Status banner, statistics grid, findings list with severity badges |
| **Rules Version Card** | Shows built-in + external rule counts and last update timestamp |
| **Check Version** | Calls API to fetch current rule status from the detection engine |
| **Update Now** | Triggers `tools/update-rules.sh`, shows real-time log, auto-refreshes counts |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `?api=rules_status` | GET | Returns JSON with builtin/external rule counts, file list, last update |
| `?api=update_rules` | GET | Runs external rule updater, returns updated status |

## Automated Rule Updates

WebGuardian automates keeping detection rules current via a cron-ready pipeline.

### Available Tools

```bash
tools/
├── update-rules.sh           # Main updater (cron-ready)
├── yara-converter.php        # YARA → WebGuardian JSON converter
├── alert-on-critical.sh      # Email/Slack notifier
└── config/
    ├── rules-sources.json    # External source registry
    └── crontab.example       # Cron templates
```

### Usage

```bash
# Update all enabled sources
./tools/update-rules.sh

# Check status
./tools/update-rules.sh --status

# Preview changes (dry run)
./tools/update-rules.sh --dry-run

# List available sources
./tools/update-rules.sh --list

# Update specific source
./tools/update-rules.sh --source=yara_php_malware
```

### Cron Setup

```bash
# Daily update at 3 AM
0 3 * * * /opt/webguardian/tools/update-rules.sh --quiet >> /var/log/webguardian-update.log 2>&1

# Automatic scan after update
0 4 * * * /opt/webguardian/bin/webguardian scan /var/www --format=json --output=/var/reports/daily.json
```

### Alert Configuration

```bash
# Email alert
./tools/alert-on-critical.sh /var/reports/scan.json admin@example.com

# Slack webhook
./tools/alert-on-critical.sh /var/reports/scan.json "" https://hooks.slack.com/services/...

# Both
./tools/alert-on-critical.sh /var/reports/scan.json admin@example.com https://hooks.slack.com/...
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `PHP Fatal error: Allowed memory size exhausted` | Increase memory_limit in php.ini or add `-d memory_limit=512M` |
| `No findings for known-infected site` | Ensure `--type` is correctly set; update rules |
| `Scan is too slow` | Reduce depth with `--depth=5` or target specific directories |
| `Maximum execution time exceeded` | Scanner uses chunked file reading (8KB buffers) to avoid loading entire files; if timeout persists, increase `max_execution_time` in php.ini or reduce scan scope |
| `JSON output is empty` | Check file permissions and path validity |
| `Permission denied` | Ensure the running user has read access to the target directory |

### Getting Help

```bash
# Display help
webguardian --help

# Check version
webguardian --version

# Verbose mode for debugging
webguardian scan /path --verbose
```

## Best Practices

1. **Scan regularly**: Set up daily or weekly automated scans
2. **Integrate with CI**: Scan every commit for new vulnerabilities
3. **Review findings promptly**: Critical issues should be addressed within hours
4. **Maintain custom rules**: Update your organization-specific patterns regularly
5. **Combine with other tools**: WebGuardian complements but does not replace WAF, IDS, or runtime monitoring
6. **Keep updated**: Regularly pull the latest version for updated detection rules
7. **Secure scan results**: Reports may contain sensitive information about your application
