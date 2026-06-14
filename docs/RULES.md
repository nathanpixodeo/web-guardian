# WebGuardian Rules System

## Overview

WebGuardian uses a JSON-based rules system for malware and vulnerability pattern matching. Rules are organized into categories and can be extended with custom patterns without modifying the scanner core.

## Rule Sources

### Built-in Rules

WebGuardian ships with four pre-built rule sets:

| File | Focus | Patterns |
|------|-------|---------|
| `rules/malware-patterns.json` | Cross-platform malware signatures | 25+ |
| `rules/wordpress-suspicious.json` | WordPress-specific threats | 12 |
| `rules/laravel-backdoors.json` | Laravel-specific vulnerabilities | 11 |
| `rules/generic-threats.json` | General web application threats | 14 |

### Automated External Rule Updates

WebGuardian includes a full automation system for fetching, converting, and installing rules from external sources:

```
tools/
├── update-rules.sh           # Main updater (cron-ready)
├── yara-converter.php        # YARA → WebGuardian JSON converter
├── alert-on-critical.sh      # Alert notifier for scan results
└── config/
    ├── rules-sources.json    # Source registry (YARA, JSON feeds)
    └── crontab.example       # Cron job templates
```

#### One-Command Update

```bash
# Update all enabled sources
./tools/update-rules.sh

# Check current status
./tools/update-rules.sh --status

# Dry run (see what would happen)
./tools/update-rules.sh --dry-run
```

#### Cron Setup

```bash
# Edit crontab
crontab -e

# Add daily update at 3 AM
0 3 * * * /opt/webguardian/tools/update-rules.sh --quiet >> /var/log/webguardian-update.log 2>&1
```

### Third-Party Rule Source Integration

WebGuardian supports loading rules from external sources via the automated updater:

1. **YARA rule repositories** — automatically downloaded and converted
2. **Community JSON feeds** — direct download
3. **Commercial threat intelligence feeds** — custom URL configuration
4. **Local security research** — direct file placement

#### Source Registry

The file `tools/config/rules-sources.json` defines all external sources:

```json
{
    "sources": [
        {
            "id": "yara_php_malware",
            "name": "YARA PHP Malware Rules",
            "type": "yara",
            "url": "https://raw.githubusercontent.com/YARAHQ/yara-forks/main/php_malware.yar",
            "enabled": true,
            "severity_map": {
                "MALWARE": "critical",
                "WEBSHELL": "critical",
                "SUSPICIOUS": "high"
            }
        }
    ]
}
```

| Field | Description |
|-------|-------------|
| `id` | Unique source identifier |
| `type` | `yara` (converts YARA) or `webguardian_json` (native format) |
| `url` | HTTPS URL of the rule file |
| `enabled` | `true` to include in updates |
| `convert` | `true` to run converter (YARA only) |
| `severity_map` | Maps YARA tags to WebGuardian severity levels |

#### Manual YARA Conversion

```bash
curl -sL https://example.com/malware.yar \
  | php tools/yara-converter.php my_source '{"MALWARE":"critical"}' \
  > rules/external/my-rules.json
```

### Community & Commercial Sources

| Source | Type | Integration |
|--------|------|-------------|
| YARA Forks (PHP Malware) | YARA | Auto via updater |
| Neo23x0 Signature Base | YARA | Auto via updater |
| OWASP Core Rules | Manual | Adapt to JSON format |
| Commercial Threat Feeds | JSON | Add URL to `rules-sources.json` |
| Local Security Research | JSON | Place in `rules/external/` |

### How External Rules Load

When `Scanner` initializes `MalwareDetector`:
1. Built-in patterns load first
2. `loadExternalPatterns()` scans `rules/external/*.json`
3. All patterns are merged into a single active set
4. Scanning proceeds as normal

The `rules/external/` directory can contain:
- Files downloaded by `update-rules.sh`
- Manually placed JSON rule files
- Community rule sets
- Commercial threat feed exports

Any `.json` file in this directory is automatically loaded on the next scan.

## Rule Format

### JSON Schema

```json
{
    "version": "1.0.0",
    "description": "Description of this rule set",
    "updated_at": "2026-06-15",
    "source": "https://example.com/threat-feed",
    "patterns": [
        {
            "id": "unique_pattern_id",
            "pattern": "regex_pattern",
            "severity": "critical",
            "type": "category",
            "message": "Human-readable description"
        }
    ]
}
```

### Field Reference

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `version` | Yes | String | Semantic version of the rule set |
| `patterns` | Yes | Array | Array of pattern objects |
| `patterns[].id` | Yes | String | Unique identifier for the pattern |
| `patterns[].pattern` | Yes | String | PCRE-compatible regex pattern |
| `patterns[].severity` | Yes | String | `critical`, `high`, `medium`, `low`, or `info` |
| `patterns[].type` | Yes | String | Category identifier (e.g., `malware`, `obfuscation`, `webshell`) |
| `patterns[].message` | Yes | String | Human-readable finding description |
| `description` | No | String | Description of the rule file |
| `updated_at` | No | String | Last update timestamp |
| `source` | No | String | Source URL for the rule set |
| `patterns[].multiLine` | No | Boolean | Match against multi-line content (default: single line) |
| `patterns[].negative` | No | Boolean | Alert when pattern is NOT found (default: false) |
| `patterns[].context` | No | String | Restrict to specific directory context |

### Regex Guidelines

Patterns must be:
- **PCRE-compatible** (PHP preg_match format)
- **Delimiter-free** (delimiters are added automatically)
- **Efficient** (avoid catastrophic backtracking)
- **Escaped properly** (use `\\` for literal backslashes in JSON)

## Example Rules

### Malware Detection

```json
{
    "id": "base64_eval",
    "pattern": "eval\\s*\\(\\s*base64_decode\\s*\\(",
    "severity": "critical",
    "type": "obfuscation",
    "message": "eval() wrapping base64_decode() - classic PHP malware deobfuscation pattern"
}
```

### Web Shell Detection

```json
{
    "id": "webshell_identifier",
    "pattern": "(?:c99shell|r57shell|phpshell|b374k)",
    "severity": "critical",
    "type": "webshell",
    "message": "Known web shell identifier detected in source code"
}
```

### Vulnerability Detection

```json
{
    "id": "sql_injection_user_input",
    "pattern": "query\\s*\\([^)]*\\$_",
    "severity": "critical",
    "type": "vulnerability",
    "message": "User input in database query - SQL injection vulnerability"
}
```

### Configuration Check

```json
{
    "id": "debug_mode_production",
    "pattern": "APP_DEBUG\\s*=\\s*true",
    "severity": "high",
    "type": "misconfiguration",
    "message": "Debug mode enabled in production environment"
}
```

## Rule Management

### Creating Custom Rules

1. Create a JSON file in your rules directory
2. Define patterns following the schema above
3. Test patterns with a small scan
4. Iterate based on results

```json
{
    "version": "1.0.0",
    "patterns": [
        {
            "id": "my_custom_threat",
            "pattern": "suspicious\\s*=\\s*['\"][^'\"]*malicious['\"]",
            "severity": "high",
            "type": "custom",
            "message": "Custom threat pattern detected"
        }
    ]
}
```

### Testing Rules

```bash
# Test your rule against a specific file
php bin/webguardian scan test-file.php --rules=/path/to/custom-rules --verbose

# Full directory scan
php bin/webguardian scan /var/www/html --rules=/path/to/custom-rules
```

### Rule Lifecycle

1. **Development** — Write and test new patterns
2. **Staging** — Run against test environments to tune thresholds
3. **Production** — Deploy to scanning pipeline
4. **Maintenance** — Update patterns as new threats emerge

## Performance Tips

- Keep patterns specific to avoid false positives
- Use anchored patterns (`^`, `$`) when possible
- Avoid overly broad character classes
- Test regex efficiency before deployment
- Split large rule files into smaller, focused files
- Use `context` field to scope rules to specific directories

## False Positive Management

### Common Causes

1. **Overly broad patterns** — Refine regex to match more specifically
2. **Legitimate obfuscation** — Minifiers, packers, and build tools
3. **Test/staging configuration** — Files with intentional debug settings
4. **Third-party libraries** — Bundled dependencies with known patterns

### Mitigation Strategies

1. **Add context restrictions** — Use `context` field to limit scan scope
2. **Create exclusion lists** — Maintain a list of known-safe files
3. **Adjust severity** — Lower severity for patterns with higher false positive rates
4. **Use negative patterns** — Alert on absence of expected security measures

## Extending the Rule Engine

For programmatic rule creation, you can extend the `MalwareDetector` class:

```php
use WebGuardian\Detector\MalwareDetector;

$detector = new MalwareDetector([
    'rules' => '/path/to/custom/rules'
]);
$findings = $detector->analyze($filePath, $content);
```

The detector loads all `.json` files from the specified rules directory (or uses built-in rules by default). Each file is validated and merged into the active pattern set.
