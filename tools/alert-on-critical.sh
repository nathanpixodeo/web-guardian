#!/usr/bin/env bash
#
# WebGuardian - Critical Alert Notifier
#
# Parses a WebGuardian JSON report and sends notification if
# critical/high severity issues are found.
#
# Usage:
#   ./tools/alert-on-critical.sh <report.json> [email] [webhook_url]
#
# Examples:
#   ./tools/alert-on-critical.sh /var/reports/scan.json admin@example.com
#   ./tools/alert-on-critical.sh /var/reports/scan.json "" https://hooks.slack.com/...
#   ./tools/alert-on-critical.sh /var/reports/scan.json admin@example.com https://hooks.slack.com/...
#

set -euo pipefail

REPORT_FILE="${1:-}"
EMAIL="${2:-}"
WEBHOOK="${3:-}"

if [ -z "$REPORT_FILE" ] || [ ! -f "$REPORT_FILE" ]; then
    echo "Usage: $0 <report.json> [email] [webhook_url]"
    exit 1
fi

# Parse report
if ! command -v jq &>/dev/null; then
    echo "Error: jq is required. Install with: apt install jq"
    exit 1
fi

CRITICAL=$(jq '.summary.critical // 0' "$REPORT_FILE")
HIGH=$(jq '.summary.high // 0' "$REPORT_FILE")
TOTAL=$(jq '.summary.total // 0' "$REPORT_FILE")
PATH_SCANNED=$(jq -r '.metadata.path // "unknown"' "$REPORT_FILE")
DURATION=$(jq -r '.metadata.duration_ms // 0' "$REPORT_FILE")
TIMESTAMP=$(jq -r '.metadata.scanned_at // "unknown"' "$REPORT_FILE")

# No critical issues
if [ "$CRITICAL" -eq 0 ] && [ "$HIGH" -eq 0 ]; then
    exit 0
fi

# Build subject/message
HOST=$(hostname)
SUBJECT="[WebGuardian] ALERT: ${CRITICAL} critical, ${HIGH} high issues on ${HOST}"

MESSAGE=$(cat <<EOF
WebGuardian Security Alert
━━━━━━━━━━━━━━━━━━━━━━━━━
Host:         ${HOST}
Path:         ${PATH_SCANNED}
Timestamp:    ${TIMESTAMP}
Duration:     ${DURATION}ms

Summary:
  Critical:   ${CRITICAL}
  High:       ${HIGH}
  Medium:     $(jq '.summary.medium // 0' "$REPORT_FILE")
  Low:        $(jq '.summary.low // 0' "$REPORT_FILE")
  Total:      ${TOTAL}

Top findings:
EOF
)

# Add top 5 critical findings
jq -r '.findings[] | select(.severity == "critical" or .severity == "high") | "  [\(.severity | ascii_upcase)] \(.message[:80])... \(.file)"' "$REPORT_FILE" | head -5 >> /dev/null
while IFS= read -r line; do
    MESSAGE+="\n${line}"
done < <(jq -r '.findings[] | select(.severity == "critical" or .severity == "high") | "  [\(.severity | ascii_upcase)] \(.message[:80] | gsub("\n"; ""))... \(.file)"' "$REPORT_FILE" | head -5)

MESSAGE+="\n\nFull report: ${REPORT_FILE}"

# Email notification
if [ -n "$EMAIL" ]; then
    if command -v mail &>/dev/null; then
        echo -e "$MESSAGE" | mail -s "$SUBJECT" "$EMAIL"
        echo "[✓] Email alert sent to $EMAIL"
    elif command -v sendmail &>/dev/null; then
        (echo "Subject: $SUBJECT"; echo ""; echo -e "$MESSAGE") | sendmail "$EMAIL"
        echo "[✓] Email alert sent via sendmail to $EMAIL"
    else
        echo "[!] Cannot send email: no mail command found"
    fi
fi

# Webhook notification (Slack, Discord, etc.)
if [ -n "$WEBHOOK" ]; then
    PAYLOAD=$(cat <<EOF
{
    "text": "*WebGuardian Security Alert*",
    "attachments": [{
        "color": "$([ "$CRITICAL" -gt 0 ] && echo "danger" || echo "warning")",
        "title": "${SUBJECT}",
        "text": "Path: ${PATH_SCANNED}\\nCritical: ${CRITICAL} | High: ${HIGH} | Total: ${TOTAL}\\nDuration: ${DURATION}ms",
        "footer": "WebGuardian v1.0.0",
        "ts": $(date +%s)
    }]
}
EOF
    )
    curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "$WEBHOOK" > /dev/null
    echo "[✓] Webhook alert sent"
fi
