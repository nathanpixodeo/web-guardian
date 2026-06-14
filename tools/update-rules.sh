#!/usr/bin/env bash
#
# WebGuardian - External Rules Updater
#
# Fetches, converts, and installs security rules from external sources.
# Designed to be run as a cronjob for automatic updates.
#
# Usage:
#   ./tools/update-rules.sh                    # Update all enabled sources
#   ./tools/update-rules.sh --dry-run          # Show what would be done
#   ./tools/update-rules.sh --source=yara_php_malware  # Update specific source
#   ./tools/update-rules.sh --status           # Show current rule status
#   ./tools/update-rules.sh --list             # List available sources
#
# Cron setup (run daily at 3am):
#   0 3 * * * /path/to/webguardian/tools/update-rules.sh --quiet >> /var/log/webguardian-update.log 2>&1
#

set -euo pipefail

# ---- Configuration ----
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RULES_DIR="$PROJECT_DIR/rules"
EXTERNAL_DIR="$RULES_DIR/external"
TOOLS_DIR="$PROJECT_DIR/tools"
CONFIG_FILE="$TOOLS_DIR/config/rules-sources.json"
LOG_FILE="/tmp/webguardian-update.log"
QUIET=false
DRY_RUN=false
SPECIFIC_SOURCE=""
STATUS_MODE=false
LIST_MODE=false

# ---- Parse Arguments ----
for arg in "$@"; do
    case "$arg" in
        --quiet|--silent) QUIET=true ;;
        --dry-run) DRY_RUN=true ;;
        --status|--stats) STATUS_MODE=true ;;
        --list|--sources) LIST_MODE=true ;;
        --source=*) SPECIFIC_SOURCE="${arg#*=}" ;;
        --help|-h)
            echo "WebGuardian Rules Updater v1.0.0"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --quiet              Suppress output"
            echo "  --dry-run            Show actions without executing"
            echo "  --status             Show current rule statistics"
            echo "  --list               List available rule sources"
            echo "  --source=<id>        Update only a specific source"
            echo "  --help               Show this help"
            echo ""
            echo "Cron example:"
            echo "  0 3 * * * $0 --quiet >> $LOG_FILE 2>&1"
            exit 0
            ;;
    esac
done

# ---- Colors (skip if quiet or piped) ----
if [ -t 1 ] && [ "$QUIET" = false ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

log()  { [ "$QUIET" = false ] && echo -e "${GREEN}[✓]${RESET} $1"; }
warn() { [ "$QUIET" = false ] && echo -e "${YELLOW}[!]${RESET} $1" >&2; }
err()  { echo -e "${RED}[✗]${RESET} $1" >&2; }
info() { [ "$QUIET" = false ] && echo -e "${CYAN}[i]${RESET} $1"; }
cmd()  { [ "$DRY_RUN" = true ] && echo -e "${YELLOW}[DRY-RUN]${RESET} $1" || eval "$1"; }

# ---- Prerequisites Check ----
check_prereqs() {
    local missing=false
    for cmd in curl php jq; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Missing required command: $cmd"
            missing=true
        fi
    done
    if [ ! -f "$CONFIG_FILE" ]; then
        err "Config file not found: $CONFIG_FILE"
        missing=true
    fi
    if [ "$missing" = true ]; then
        echo "Install missing dependencies and try again."
        echo "  Ubuntu/Debian: apt install curl jq"
        echo "  CentOS/RHEL:   yum install curl jq"
        exit 1
    fi
}

# ---- Status Display ----
show_status() {
    echo -e "${BOLD}WebGuardian Rules Status${RESET}"
    echo "────────────────────────────────────────"
    echo ""

    # Built-in rules
    echo -e "${BOLD}[ Built-in Rules ]${RESET}"
    for f in "$RULES_DIR"/*.json; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        count=$(jq '.patterns | length' "$f" 2>/dev/null || echo "?")
        version=$(jq -r '.version // "?"' "$f" 2>/dev/null)
        updated=$(jq -r '.updated_at // "?"' "$f" 2>/dev/null)
        printf "  %-40s %3s patterns  (v%s, %s)\n" "$name" "$count" "$version" "$updated"
    done

    # External rules
    if [ -d "$EXTERNAL_DIR" ]; then
        echo ""
        echo -e "${BOLD}[ External Rules ]${RESET}"
        for f in "$EXTERNAL_DIR"/*.json; do
            [ -f "$f" ] || continue
            name=$(basename "$f")
            count=$(jq '.patterns | length' "$f" 2>/dev/null || echo "?")
            src=$(jq -r '.source // "unknown"' "$f" 2>/dev/null)
            updated=$(jq -r '.updated_at // "?"' "$f" 2>/dev/null)
            printf "  %-40s %3s patterns  (from %s, %s)\n" "$name" "$count" "$src" "$updated"
        done
    fi

    # Totals
    echo ""
    total_builtin=0
    for f in "$RULES_DIR"/*.json; do
        [ -f "$f" ] || continue
        c=$(jq '.patterns | length' "$f" 2>/dev/null || echo 0)
        total_builtin=$((total_builtin + c))
    done
    total_external=0
    if [ -d "$EXTERNAL_DIR" ]; then
        for f in "$EXTERNAL_DIR"/*.json; do
            [ -f "$f" ] || continue
            c=$(jq '.patterns | length' "$f" 2>/dev/null || echo 0)
            total_external=$((total_external + c))
        done
    fi
    echo -e "${BOLD}Total:${RESET} $total_builtin built-in + $total_external external = $((total_builtin + total_external)) patterns"
}

# ---- List Available Sources ----
list_sources() {
    echo -e "${BOLD}Available Rule Sources${RESET}"
    echo "────────────────────────────────────────"
    echo ""

    sources=$(jq -c '.sources[]' "$CONFIG_FILE")
    echo "$sources" | while read -r src; do
        id=$(echo "$src" | jq -r '.id')
        name=$(echo "$src" | jq -r '.name')
        type=$(echo "$src" | jq -r '.type')
        url=$(echo "$src" | jq -r '.url')
        enabled=$(echo "$src" | jq -r '.enabled')
        status="${GREEN}enabled${RESET}"
        [ "$enabled" = "false" ] && status="${YELLOW}disabled${RESET}"

        printf "  ${BOLD}%-25s${RESET} %-10s %-20s %s\n" "$id" "[$type]" "$status" "$name"
    done
}

# ---- YARA to WebGuardian JSON Converter ----
yara_to_webguardian() {
    local yar_content="$1"
    local source_id="$2"
    local severity_map="$3"

    php "$TOOLS_DIR/yara-converter.php" "$source_id" "$severity_map" <<< "$yar_content"
}

# ---- Download and Convert YARA Rule ----
process_yara_source() {
    local src="$1"
    local id=$(echo "$src" | jq -r '.id')
    local url=$(echo "$src" | jq -r '.url')
    local name=$(echo "$src" | jq -r '.name')
    local severity_map=$(echo "$src" | jq -r '.severity_map')

    info "Downloading YARA rules: $name"

    local tmp_file=$(mktemp)
    local http_code=$(curl -sL -w "%{http_code}" -o "$tmp_file" "$url" 2>/dev/null || echo "000")

    if [ "$http_code" != "200" ]; then
        err "HTTP $http_code from $url"
        rm -f "$tmp_file"
        return 1
    fi

    local yar_content
    yar_content=$(cat "$tmp_file")
    rm -f "$tmp_file"

    if [ -z "$yar_content" ]; then
        err "Empty response from $url"
        return 1
    fi

    # Convert YARA to WebGuardian JSON
    local output_file="$EXTERNAL_DIR/${id}.json"
    local json_output

    if [ "$DRY_RUN" = true ]; then
        log "[DRY-RUN] Would convert YARA → $output_file ($(echo "$yar_content" | wc -l) lines)"
        return 0
    fi

    json_output=$(yara_to_webguardian "$yar_content" "$id" "$severity_map")

    echo "$json_output" > "$output_file"

    local count=$(echo "$json_output" | jq '.patterns | length' 2>/dev/null || echo "0")
    log "Converted to $count WebGuardian patterns → $output_file"
}

# ---- Download Direct JSON Rule ----
process_json_source() {
    local src="$1"
    local id=$(echo "$src" | jq -r '.id')
    local url=$(echo "$src" | jq -r '.url')
    local name=$(echo "$src" | jq -r '.name')

    info "Downloading WebGuardian rules: $name"

    local tmp_file=$(mktemp)
    local http_code=$(curl -sL -w "%{http_code}" -o "$tmp_file" "$url" 2>/dev/null || echo "000")

    if [ "$http_code" != "200" ]; then
        err "HTTP $http_code from $url"
        rm -f "$tmp_file"
        return 1
    fi

    # Validate JSON
    if ! jq empty "$tmp_file" 2>/dev/null; then
        err "Invalid JSON from $url"
        rm -f "$tmp_file"
        return 1
    fi

    local output_file="$EXTERNAL_DIR/${id}.json"
    if [ "$DRY_RUN" = true ]; then
        local size=$(wc -c < "$tmp_file")
        log "[DRY-RUN] Would copy $size bytes → $output_file"
        rm -f "$tmp_file"
        return 0
    fi

    mv "$tmp_file" "$output_file"

    local count=$(jq '.patterns | length' "$output_file" 2>/dev/null || echo "0")
    log "Installed $count patterns → $output_file"
}

# ---- Merge External Rules into Main Rule File ----
merge_rules() {
    info "Merging external rules into active rule set..."

    local merged_file="$EXTERNAL_DIR/.merged.json"
    local patterns="[]"

    for f in "$EXTERNAL_DIR"/*.json; do
        [ -f "$f" ] && [ "$(basename "$f")" != ".merged.json" ] || continue
        file_patterns=$(jq '.patterns // []' "$f" 2>/dev/null)
        patterns=$(echo "$patterns" "$file_patterns" | jq -s 'add')
    done

    local count=$(echo "$patterns" | jq 'length')
    local merged=$(jq -n --argjson p "$patterns" '{
        version: "1.0.0",
        description: "Merged external rules from community sources",
        updated_at: now | strftime("%Y-%m-%dT%H:%M:%SZ"),
        patterns: $p
    }')

    echo "$merged" > "$merged_file"
    log "Merged $count external patterns → $merged_file"
}

# ---- Main Update Logic ----
main() {
    check_prereqs

    if [ "$STATUS_MODE" = true ]; then
        show_status
        exit 0
    fi

    if [ "$LIST_MODE" = true ]; then
        list_sources
        exit 0
    fi

    # Create external rules directory
    cmd "mkdir -p \"$EXTERNAL_DIR\""

    # Load sources
    local sources
    if [ -n "$SPECIFIC_SOURCE" ]; then
        sources=$(jq -c ".sources[] | select(.id == \"$SPECIFIC_SOURCE\")" "$CONFIG_FILE")
        if [ -z "$sources" ]; then
            err "Source '$SPECIFIC_SOURCE' not found in config. Use --list to see available sources."
            exit 1
        fi
        sources=$(echo "$sources" | jq -c '.')
    else
        sources=$(jq -c '.sources[] | select(.enabled == true)' "$CONFIG_FILE")
    fi

    if [ -z "$sources" ]; then
        warn "No enabled sources found in config."
        exit 0
    fi

    # Process each source
    local success_count=0
    local fail_count=0

    while IFS= read -r src; do
        [ -z "$src" ] && continue
        local type=$(echo "$src" | jq -r '.type')
        local id=$(echo "$src" | jq -r '.id')

        echo ""
        info "Processing source: $id ($type)..."

        case "$type" in
            yara)
                if process_yara_source "$src"; then
                    ((success_count++))
                else
                    ((fail_count++))
                fi
                ;;
            webguardian_json)
                if process_json_source "$src"; then
                    ((success_count++))
                else
                    ((fail_count++))
                fi
                ;;
            *)
                warn "Unknown source type: $type"
                ((fail_count++))
                ;;
        esac
    done <<< "$sources"

    # Merge external rules
    if [ "$fail_count" = 0 ]; then
        merge_rules
    fi

    # Summary
    echo ""
    echo "─"───────────────────────────────────────"
    if [ "$DRY_RUN" = true ]; then
        log "Dry-run complete. $((success_count + fail_count)) sources processed."
    else
        log "Update complete. ${success_count} success, ${fail_count} failed."
        if [ "$fail_count" -gt 0 ]; then
            warn "Some sources failed. Check network connectivity and URLs."
        fi
    fi

    return $fail_count
}

main "$@"
