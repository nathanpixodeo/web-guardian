#!/usr/bin/env php
<?php
/**
 * WebGuardian - YARA to JSON Rule Converter
 *
 * Converts YARA rule files to WebGuardian-compatible JSON format.
 * Supports basic YARA syntax: strings, conditions, metadata.
 *
 * Usage:
 *   cat rules.yar | php yara-converter.php <source_id> '<severity_map_json>'
 *
 * Example:
 *   curl -sL https://example.com/malware.yar | \
 *     php yara-converter.php yara_php_malware '{"MALWARE":"critical"}'
 *
 * Output:
 *   WebGuardian JSON rule file written to stdout
 */

// ---- Parse Arguments ----
$sourceId = $argv[1] ?? 'unknown';
$severityMapJson = $argv[2] ?? '{}';
$severityMap = json_decode($severityMapJson, true) ?: [];

// ---- Read YARA Content from STDIN ----
$yarContent = stream_get_contents(STDIN);
if (empty($yarContent)) {
    fwrite(STDERR, "Error: No YARA content provided on STDIN\n");
    exit(1);
}

// ---- Parse YARA Rules ----
$rules = parseYaraRules($yarContent);
$patterns = [];

foreach ($rules as $rule) {
    $webguardianRule = convertRule($rule, $sourceId, $severityMap);
    if ($webguardianRule !== null) {
        $patterns[] = $webguardianRule;
    }
}

// ---- Build Output ----
$output = [
    'version'     => '1.0.0',
    'description' => "Converted YARA rules from source: $sourceId",
    'updated_at'  => date('c'),
    'source'      => $sourceId,
    'converted_at' => date('c'),
    'patterns'    => $patterns,
];

echo json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

// ---- YARA Parser ----

function parseYaraRules(string $content): array
{
    $rules = [];
    $lines = explode("\n", $content);
    $currentRule = null;
    $inStrings = false;
    $inCondition = false;
    $braceDepth = 0;

    foreach ($lines as $lineNum => $rawLine) {
        $line = trim($rawLine);

        // Skip comments and empty lines
        if (empty($line) || str_starts_with($line, '//') || str_starts_with($line, '#')) {
            continue;
        }

        // Rule start: rule rule_name [tags]
        if (preg_match('/^rule\s+(\w+)/i', $line, $m)) {
            if ($currentRule !== null) {
                $rules[] = $currentRule;
            }
            $currentRule = [
                'name'       => $m[1],
                'meta'       => [],
                'strings'    => [],
                'condition'  => '',
                'line_start' => $lineNum + 1,
            ];

            // Extract tags
            if (preg_match('/:\s*(.+)/', $line, $tagMatch)) {
                $currentRule['tags'] = preg_split('/\s+/', trim($tagMatch[1]));
            } else {
                $currentRule['tags'] = [];
            }

            $inStrings = false;
            $inCondition = false;
            $braceDepth = 0;
            continue;
        }

        if ($currentRule === null) continue;

        // Section markers
        if (preg_match('/^\s*meta\s*:/i', $line)) {
            $inStrings = false;
            $inCondition = false;
            continue;
        }
        if (preg_match('/^\s*strings\s*:/i', $line)) {
            $inStrings = true;
            $inCondition = false;
            continue;
        }
        if (preg_match('/^\s*condition\s*:/i', $line)) {
            $inStrings = false;
            $inCondition = true;
            continue;
        }

        // Meta data
        if (isset($currentRule['meta']) && preg_match('/^\s*(\w+)\s*=\s*"([^"]*)"/', $line, $m)) {
            $currentRule['meta'][$m[1]] = $m[2];
            continue;
        }
        if (isset($currentRule['meta']) && preg_match('/^\s*(\w+)\s*=\s*(\d+)/', $line, $m)) {
            $currentRule['meta'][$m[1]] = (int)$m[2];
            continue;
        }

        // String definitions: $name = "pattern"
        if ($inStrings && preg_match('/^\$(\w+)\s*=\s*"([^"]*)"/', $line, $m)) {
            $currentRule['strings'][] = [
                'id'      => '$' . $m[1],
                'value'   => $m[2],
                'type'    => 'text',
                'modifier'=> '',
            ];
            continue;
        }

        // String definitions with modifiers: $name = "pattern" nocase
        if ($inStrings && preg_match('/^\$(\w+)\s*=\s*"([^"]*)"\s*(\w+)/', $line, $m)) {
            $currentRule['strings'][] = [
                'id'      => '$' . $m[1],
                'value'   => $m[2],
                'type'    => 'text',
                'modifier'=> strtolower($m[3]),
            ];
            continue;
        }

        // Hex string: $name = { 6A 40 68 00 30 00 00 6A 14 }
        if ($inStrings && preg_match('/^\$(\w+)\s*=\s*\{([^}]+)\}/', $line, $m)) {
            $hexStr = preg_replace('/\s+/', '', $m[2]);
            $currentRule['strings'][] = [
                'id'      => '$' . $m[1],
                'value'   => $hexStr,
                'type'    => 'hex',
            ];
            continue;
        }

        // Regex string: $name = /pattern/
        if ($inStrings && preg_match('/^\$(\w+)\s*=\s*\/([^\/]+)\//', $line, $m)) {
            $currentRule['strings'][] = [
                'id'      => '$' . $m[1],
                'value'   => $m[2],
                'type'    => 'regex',
            ];
            continue;
        }

        // Condition (accumulate until closing brace)
        if ($inCondition) {
            $braceDepth += substr_count($line, '{');
            $braceDepth -= substr_count($line, '}');
            $currentRule['condition'] .= $line . ' ';

            // End of rule (closing brace at depth 0)
            if ($braceDepth <= 0) {
                $currentRule['condition'] = trim($currentRule['condition']);
                // Remove trailing closing brace
                $currentRule['condition'] = preg_replace('/\s*\}\s*$/', '', $currentRule['condition']);
                $rules[] = $currentRule;
                $currentRule = null;
                $inCondition = false;
                $braceDepth = 0;
            }
        }
    }

    // Flush last rule
    if ($currentRule !== null) {
        $rules[] = $currentRule;
    }

    return $rules;
}

function convertRule(array $rule, string $sourceId, array $severityMap): ?array
{
    if (empty($rule['strings']) || empty($rule['condition'])) {
        return null;
    }

    // Determine severity from tags or meta
    $severity = determineSeverity($rule, $severityMap);

    // Determine type/category
    $type = determineType($rule);

    // Build message
    $message = buildMessage($rule);

    // Generate regex pattern from YARA strings
    $pattern = convertStringsToPattern($rule['strings'], $rule['condition']);

    if ($pattern === null) {
        return null;
    }

    // Check if this is a multi-line pattern
    $multiLine = isMultiLineCondition($rule['condition']);

    return [
        'id'        => sanitizeId($sourceId . '_' . $rule['name']),
        'pattern'   => $pattern,
        'severity'  => $severity,
        'type'      => $type,
        'source'    => $sourceId,
        'multiLine' => $multiLine,
        'message'   => $message,
        'yara_rule' => $rule['name'],
    ];
}

function determineSeverity(array $rule, array $severityMap): string
{
    // Check tags first
    foreach ($rule['tags'] as $tag) {
        $upperTag = strtoupper($tag);
        if (isset($severityMap[$upperTag])) {
            return $severityMap[$upperTag];
        }
    }

    // Check meta fields
    foreach (['severity', 'level', 'risk', 'score'] as $field) {
        if (isset($rule['meta'][$field])) {
            $val = strtolower((string)$rule['meta'][$field]);
            if (in_array($val, ['critical', 'high', 'medium', 'low', 'info'])) {
                return $val;
            }
            if (is_numeric($val)) {
                return (int)$val >= 80 ? 'critical' : ((int)$val >= 50 ? 'high' : 'medium');
            }
        }
    }

    // Check name for hints
    $name = strtoupper($rule['name']);
    if (preg_match('/MALWARE|WEBSHELL|BACKDOOR|SHELL|RCE|EXEC/', $name)) return 'critical';
    if (preg_match('/SUSPICIOUS|OBFUSCATED|CRYPTO|MINER|SPAM/', $name)) return 'high';
    if (preg_match('/INFO|NOTIFY|WARNING/', $name)) return 'info';

    return 'high';
}

function determineType(array $rule): string
{
    $name = strtoupper($rule['name']);
    $tags = array_map('strtoupper', $rule['tags']);

    $all = array_merge($tags, [$name]);

    foreach ($all as $item) {
        if (preg_match('/WEBSHELL|SHELL/', $item)) return 'webshell';
        if (preg_match('/BACKDOOR/', $item)) return 'backdoor';
        if (preg_match('/MALWARE/', $item)) return 'malware';
        if (preg_match('/OBFUSCATED|OBFUSCATION/', $item)) return 'obfuscation';
        if (preg_match('/CRYPTO|MINER|COIN/', $item)) return 'cryptominer';
        if (preg_match('/SPAM|SEO/', $item)) return 'spam';
        if (preg_match('/EXPLOIT|RCE|INJECTION/', $item)) return 'exploit';
        if (preg_match('/INFO/', $item)) return 'info';
    }

    return 'malware';
}

function buildMessage(array $rule): string
{
    // Use description from meta if available
    if (!empty($rule['meta']['description'])) {
        return $rule['meta']['description'];
    }

    // Build from name
    $name = $rule['name'];
    $name = preg_replace('/([a-z])([A-Z])/', '$1 $2', $name);
    $name = preg_replace('/[_-]+/', ' ', $name);
    $name = ucfirst(strtolower($name));

    $type = determineType($rule);
    $typeLabel = ucfirst($type);

    return "[YARA] $name - $typeLabel pattern detected";
}

function convertStringsToPattern(array $strings, string $condition): ?string
{
    // Simple case: single string match
    if (count($strings) === 1) {
        return textToRegexPattern($strings[0]);
    }

    // Multiple strings with condition like "$a or $b"
    if (preg_match('/\$(\w+)/', $condition)) {
        // Build alternation group
        $patterns = [];
        foreach ($strings as $str) {
            $p = textToRegexPattern($str);
            if ($p !== null) {
                $patterns[] = $p;
            }
        }
        if (empty($patterns)) return null;
        if (count($patterns) === 1) return $patterns[0];
        return '(' . implode('|', $patterns) . ')';
    }

    // Fallback: combine all strings
    $patterns = [];
    foreach ($strings as $str) {
        $p = textToRegexPattern($str);
        if ($p !== null) {
            $patterns[] = $p;
        }
    }
    if (empty($patterns)) return null;
    return implode('|', $patterns);
}

function textToRegexPattern(array $str): ?string
{
    $value = $str['value'] ?? '';
    $type = $str['type'] ?? 'text';
    $modifier = $str['modifier'] ?? '';

    if (empty($value)) return null;

    switch ($type) {
        case 'hex':
            // Convert hex like "6A4068003000006A14" to regex
            $bytes = str_split($value, 2);
            $pattern = '';
            foreach ($bytes as $byte) {
                if ($byte === '??') {
                    $pattern .= '.';
                } else {
                    $pattern .= '\\x' . $byte;
                }
            }
            return $pattern;

        case 'regex':
            // Use YARA regex directly (with some adjustments)
            return $value;

        case 'text':
        default:
            // Escape PCRE special characters
            $escaped = preg_quote($value, '/');
            // Handle nocase
            if (str_contains($modifier, 'nocase') || str_contains($modifier, 'wide') || str_contains($modifier, 'ascii')) {
                // Case-insensitive matching - we'll handle this in the detector
            }
            // Build regex that matches if string appears anywhere in line
            return $escaped;
    }
}

function isMultiLineCondition(string $condition): bool
{
    // Conditions involving "at", "in", "for all" typically need multi-line
    return str_contains($condition, ' of ') ||
           str_contains($condition, ' for ') ||
           str_contains($condition, ' at ') ||
           str_contains($condition, ' in ');
}

function sanitizeId(string $id): string
{
    // Replace non-alphanumeric characters
    $id = preg_replace('/[^a-zA-Z0-9_]/', '_', $id);
    $id = preg_replace('/_+/', '_', $id);
    $id = trim($id, '_');
    return strtolower($id);
}
