#!/bin/bash
#
# Detection Engineering Pipeline
# Combines VirusTotal, yarGen, and YARA rule expertise
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VT_SKILL="${HOME}/.openclaw/skills/virustotal-api"
YARGEN_SKILL="${HOME}/.openclaw/skills/yargen"
TEMP_DIR="/tmp/detection-engineer-$$"

# Default values
AUTHOR="Detection Engineering Team"
OUTPUT=""
REFERENCE=""
VERBOSE=false
SAVE_SAMPLE=""
NO_VT_CONTEXT=false
SKIP_POST_PROCESS=false

# Functions
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[E]${NC} $1" >&2
}

usage() {
    cat << EOF
Detection Engineering Pipeline

Usage: detection-engineer.sh <command> [options]

Commands:
    generate-from-hash <hash>    Full pipeline: hash → YARA rule
    download <hash>              Download sample from VT
    generate <sample-path>       Generate YARA from sample
    review <rule-file>           Review existing rule

Options:
    -a, --author <name>          Rule author (default: Detection Engineering Team)
    -o, --output <file>          Output file (default: stdout)
    -r, --reference <ref>        Reference URL/report
    --no-vt-context              Skip VT metadata enrichment
    --skip-post-process          Skip YARA expert review
    --save-sample <path>         Keep downloaded sample
    -v, --verbose                Show detailed progress
    -h, --help                   Show this help

Examples:
    # Full pipeline
    detection-engineer.sh generate-from-hash d41d8cd98f00b204e9800998ecf8427e -a "Florian Roth"
    
    # Download only
    detection-engineer.sh download d41d8cd98f00b204e9800998ecf8427e --save-sample /tmp/sample.bin
    
    # Generate from existing sample
    detection-engineer.sh generate /tmp/malware.bin -o rule.yar

EOF
}

# Check prerequisites
check_prerequisites() {
    local missing=()
    
    if [ ! -d "$VT_SKILL" ]; then
        missing+=("virustotal-api skill")
    fi
    
    if [ ! -d "$YARGEN_SKILL" ]; then
        missing+=("yargen skill")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing prerequisites: ${missing[*]}"
        log_error "Install to ~/.openclaw/skills/"
        exit 1
    fi
    
    # Check VT API key
    if [ -z "$VT_API_KEY" ] && [ ! -f ~/.virustotal/apikey ]; then
        log_error "VirusTotal API key not configured"
        exit 1
    fi
}

# Download sample from VirusTotal
download_from_vt() {
    local hash="$1"
    local output="$2"
    
    log_info "Looking up hash in VirusTotal: $hash"
    
    # Get file metadata
    local vt_response
    vt_response=$("$VT_SKILL/scripts/vt-file-lookup.sh" "$hash" 2>/dev/null) || {
        log_error "Hash not found in VirusTotal"
        return 1
    }
    
    if [ "$VERBOSE" = true ]; then
        echo "$vt_response" | head -20
    fi
    
    # Extract detection stats
    local detections
    detections=$(echo "$vt_response" | grep -o '"malicious":[0-9]*' | head -1 | cut -d: -f2)
    
    log_info "VT Detections: ${detections:-unknown}"
    
    # Download file
    log_info "Downloading sample..."
    if ! "$VT_SKILL/scripts/vt-file-download.sh" "$hash" "$output" 2>/dev/null; then
        log_error "Failed to download sample (may require premium API)"
        return 1
    fi
    
    log_success "Downloaded to: $output"
    
    # Save VT context for later
    echo "$vt_response" > "${TEMP_DIR}/vt_context.json"
    
    return 0
}

# Generate YARA rule from sample
generate_rule() {
    local sample="$1"
    local output="$2"
    
    log_info "Generating YARA rule from sample..."
    
    # Check if yarGen server is running
    if ! curl -s http://127.0.0.1:8080/api/health >/dev/null 2>&1; then
        log_warn "yarGen server not running, attempting to start..."
        local yargen_dir="${HOME}/clawd/projects/yarGen-Go/repo"
        if [ -f "$yargen_dir/yargen" ]; then
            # Start server from the correct directory so it finds the databases
            (cd "$yargen_dir" && nohup ./yargen serve > /tmp/yargen-auto.log 2>&1 &)
            log_info "Starting yarGen server..."
            # Wait for server to be ready
            local attempts=0
            while [ $attempts -lt 90 ]; do
                if curl -s http://127.0.0.1:8080/api/health >/dev/null 2>&1; then
                    log_success "yarGen server is ready!"
                    break
                fi
                sleep 2
                attempts=$((attempts + 1))
            done
            if [ $attempts -eq 90 ]; then
                log_error "yarGen server failed to start within 3 minutes"
                log_info "Start manually: cd ~/clawd/projects/yarGen-Go/repo && ./yargen serve"
                return 1
            fi
        else
            log_error "yarGen binary not found at $yargen_dir/yargen"
            return 1
        fi
    fi
    
    # Submit sample using yargen-util
    local yargen_dir="${HOME}/clawd/projects/yarGen-Go/repo"
    
    local extra_opts=""
    [ -n "$REFERENCE" ] && extra_opts="$extra_opts -r \"$REFERENCE\""
    [ "$VERBOSE" = true ] && extra_opts="$extra_opts -v"
    
    if [ -n "$output" ]; then
        "$yargen_dir/yargen-util" submit -a "$AUTHOR" $extra_opts -o "$output" "$sample"
    else
        "$yargen_dir/yargen-util" submit -a "$AUTHOR" $extra_opts "$sample"
    fi
    
    log_success "YARA rule generated"
}

# Review rule with YARA expert
review_rule() {
    local rule_file="$1"
    local improved_rule="${rule_file%.yar}_improved.yar"
    
    if [ "$SKIP_POST_PROCESS" = true ]; then
        log_info "Skipping YARA expert review (--skip-post-process)"
        return 0
    fi
    
    log_info "Reviewing rule with YARA expert..."
    
    # Extract rule components for analysis
    local rule_name
    rule_name=$(grep -oP 'rule\s+\K\w+' "$rule_file" | head -1)
    
    local filesize_line
    filesize_line=$(grep -oP 'filesize\s*<\s*\K[0-9]+[KMGT]?B?' "$rule_file" | head -1)
    
    local sample_size=""
    if [ -f "${TEMP_DIR}/sample.bin" ]; then
        sample_size=$(stat -f%z "${TEMP_DIR}/sample.bin" 2>/dev/null || stat -c%s "${TEMP_DIR}/sample.bin" 2>/dev/null)
    fi
    
    # Initialize issues array
    local issues=()
    local suggestions=()
    
    # Check 1: Rule naming convention
    if [[ ! "$rule_name" =~ ^(MAL|SUSP|HKTL|APT|EXPL|FEEL|INFO)_ ]]; then
        issues+=("Rule name '$rule_name' doesn't follow naming convention")
        suggestions+=("Use prefix: MAL_ (malware), SUSP_ (suspicious), HKTL_ (hacktool), APT_ (apt), EXPL_ (exploit)")
    fi
    
    # Check 2: Filesize mismatch (critical!)
    if [ -n "$filesize_line" ] && [ -n "$sample_size" ]; then
        local filesize_bytes
        filesize_bytes=$(echo "$filesize_line" | sed 's/KB/*1024/g; s/MB/*1048576/g; s/GB/*1073741824/g' | bc 2>/dev/null || echo "0")
        if [ "$filesize_bytes" -lt "$sample_size" ] 2>/dev/null; then
            issues+=("CRITICAL: filesize $filesize_line is smaller than actual file ($sample_size bytes)")
            suggestions+=("Update filesize condition or remove it")
        fi
    fi
    
    # Check 3: Missing metadata fields
    if ! grep -q "description" "$rule_file"; then
        issues+=("Missing 'description' in metadata")
        suggestions+=("Add description explaining what this rule detects")
    fi
    
    if ! grep -q "hash1" "$rule_file"; then
        issues+=("Missing 'hash1' in metadata")
        suggestions+=("Add sample hash for reference")
    fi
    
    # Check 4: String naming convention
    local x_count s_count a_count fp_count
    x_count=$(grep -oP '\$x\d+' "$rule_file" | wc -l)
    s_count=$(grep -oP '\$s\d+' "$rule_file" | wc -l)
    a_count=$(grep -oP '\$a\d+' "$rule_file" | wc -l)
    fp_count=$(grep -oP '\$fp\d+' "$rule_file" | wc -l)
    
    if [ "$x_count" -gt 5 ] && [ "$s_count" -eq 0 ]; then
        issues+=("Many strings marked as \$x* (highly specific) - some should be \$s* (grouped)")
        suggestions+=("Use \$s* for strings that need multiple matches, \$x* for unique signatures")
    fi
    
    if [ "$fp_count" -eq 0 ]; then
        suggestions+=("Consider adding \$fp* strings for false positive filtering")
    fi
    
    # Check 5: Condition logic
    if grep -q "all of (\$op\*)" "$rule_file" && [ "$(grep -oP '\$op\d+' "$rule_file" | wc -l)" -lt 2 ]; then
        issues+=("Condition uses 'all of (\$op*)' but only has one opcode pattern")
        suggestions+=("Use 'any of (\$op*)' or add more opcode patterns")
    fi
    
    # Check 6: Score distribution
    local high_score_count
    high_score_count=$(grep -oP '/\* score: \K[0-9]+' "$rule_file" | awk '$1 >= 30 {count++} END {print count+0}')
    if [ "$high_score_count" -lt 2 ]; then
        suggestions+=("Rule may benefit from more high-scoring (specific) strings")
    fi
    
    # Display findings
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║           YARA RULE EXPERT REVIEW                                ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    
    if [ ${#issues[@]} -eq 0 ] && [ ${#suggestions[@]} -eq 0 ]; then
        echo "✅ No issues found! Rule looks good."
    else
        if [ ${#issues[@]} -gt 0 ]; then
            echo "❌ ISSUES FOUND (${#issues[@]}):"
            echo ""
            for i in "${!issues[@]}"; do
                echo "  [$((i+1))] ${issues[$i]}"
                echo "      → ${suggestions[$i]}"
                echo ""
            done
        fi
        
        if [ ${#suggestions[@]} -gt ${#issues[@]} ]; then
            echo "💡 SUGGESTIONS:"
            echo ""
            local start_idx=${#issues[@]}
            for i in $(seq $start_idx $((${#suggestions[@]}-1))); do
                echo "  • ${suggestions[$i]}"
            done
            echo ""
        fi
    fi
    
    # Show VT context enrichment suggestion
    if [ -f "${TEMP_DIR}/vt_context.json" ]; then
        local vt_detections vt_tags
        vt_detections=$(grep -oP '"malicious":\s*\K[0-9]+' "${TEMP_DIR}/vt_context.json" | head -1)
        vt_tags=$(grep -oP '"tags":\s*\[\s*"\K[^"]+' "${TEMP_DIR}/vt_context.json" | head -3 | tr '\n' ',' | sed 's/,$//')
        
        if [ -n "$vt_detections" ]; then
            echo "📊 VirusTotal Context:"
            echo "   Detections: $vt_detections"
            [ -n "$vt_tags" ] && echo "   Tags: $vt_tags"
            echo ""
            echo "   💡 Suggestion: Add to metadata:"
            echo "      vt_detection = \"$vt_detections/72\""
            [ -n "$vt_tags" ] && echo "      vt_tags = \"$vt_tags\""
            echo ""
        fi
    fi
    
    # Show improved rule template
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║           FINAL IMPROVED YARA RULE                               ║"
    echo "║           (Production-Ready)                                     ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Generate improved rule
    generate_improved_rule "$rule_file" "${TEMP_DIR}/vt_context.json" > "$improved_rule"
    cat "$improved_rule"
    
    echo ""
    echo "════════════════════════════════════════════════════════════════════"
    echo ""
    
    # COMPILE CHECK: Verify the rule compiles
    log_info "Validating rule compilation..."
    local compile_script="$SKILL_DIR/scripts/yara-compile-loop.py"
    
    if [ -f "$compile_script" ] && command -v python3 >/dev/null 2>&1; then
        if python3 "$compile_script" "$improved_rule" 1 2>/dev/null; then
            log_success "Rule compiles successfully!"
        else
            log_warn "Rule has compilation issues"
            echo ""
            echo "💡 Run the fix loop:"
            echo "   python3 $compile_script $improved_rule"
            echo ""
            echo "   Or use bash version:"
            echo "   $SKILL_DIR/scripts/yara-compile-loop.sh $improved_rule"
        fi
    elif command -v yara >/dev/null 2>&1; then
        # Fallback to simple yara check
        if yara -c "$improved_rule" /dev/null 2>/dev/null; then
            log_success "Rule compiles successfully!"
        else
            log_error "Rule compilation FAILED!"
            echo ""
            echo "⚠️  ERRORS:"
            yara -c "$improved_rule" /dev/null 2>&1 | head -10
            echo ""
            echo "💡 Install Python 3 for automatic fix features"
        fi
    else
        log_warn "yara binary not found - skipping compile check"
        log_info "Install yara to enable automatic validation"
    fi
    
    # Replace original with improved if user wants
    if [ -f "$improved_rule" ]; then
        # Always show the improved rule path
        log_success "IMPROVED RULE saved to: $improved_rule"
        
        # If output was specified, use improved version
        if [ -n "$OUTPUT" ]; then
            cp "$improved_rule" "$OUTPUT"
            # Also save original for comparison
            cp "$rule_file" "${OUTPUT%.yar}_original.yar"
            log_success "Final rule (reviewed) saved to: $OUTPUT"
            log_info "Original yarGen output saved to: ${OUTPUT%.yar}_original.yar"
        fi
        
        # ALWAYS display the rule at the end
        echo ""
        echo ">>> RULE GENERATION COMPLETE <<<"
        echo ""
        
        # Display the final rule
        echo ""
        echo "════════════════════════════════════════════════════════════════════"
        echo "                    FINAL YARA RULE"
        echo "════════════════════════════════════════════════════════════════════"
        echo ""
        if [ -n "$OUTPUT" ] && [ -f "$OUTPUT" ]; then
            cat "$OUTPUT"
        elif [ -f "$improved_rule" ]; then
            cat "$improved_rule"
        elif [ -f "$rule_file" ]; then
            cat "$rule_file"
        fi
        echo ""
        echo "════════════════════════════════════════════════════════════════════"
        echo ""
        echo "Rule also saved to:"
        if [ -n "$OUTPUT" ]; then
            echo "  $OUTPUT"
        else
            echo "  $improved_rule"
        fi
    fi
}

# Generate improved rule based on expert review
generate_improved_rule() {
    local input_file="$1"
    local vt_context="$2"
    
    # Extract original components
    local rule_name author reference date hash score
    rule_name=$(grep -oP 'rule\s+\K\w+' "$input_file" | head -1)
    author=$(grep -oP 'author\s*=\s*"\K[^"]+' "$input_file" | head -1)
    reference=$(grep -oP 'reference\s*=\s*"\K[^"]+' "$input_file" | head -1)
    date=$(grep -oP 'date\s*=\s*"\K[^"]+' "$input_file" | head -1)
    hash=$(grep -oP 'hash1\s*=\s*"\K[^"]+' "$input_file" | head -1)
    score=$(grep -oP 'score\s*=\s*\K[0-9]+' "$input_file" | head -1)
    
    # Get sample size for filesize fix
    local sample_size=""
    if [ -f "${TEMP_DIR}/sample.bin" ]; then
        sample_size=$(stat -f%z "${TEMP_DIR}/sample.bin" 2>/dev/null || stat -c%s "${TEMP_DIR}/sample.bin" 2>/dev/null)
    fi
    
    # Get VT context
    local vt_detections=""
    local vt_tags=""
    if [ -f "$vt_context" ]; then
        vt_detections=$(grep -oP '"malicious":\s*\K[0-9]+' "$vt_context" | head -1)
        vt_tags=$(grep -oP '"tags":\s*\[\s*"\K[^"]+' "$vt_context" | head -3 | paste -sd ',' -)
    fi
    
    # Determine rule type based on VT detections
    local rule_prefix="SUSP"
    local description=""
    if [ -n "$vt_detections" ] && [ "$vt_detections" -gt 10 ]; then
        rule_prefix="MAL"
        description="Malware sample"
    elif [ -n "$vt_tags" ] && [[ "$vt_tags" =~ hacktool|pentest ]]; then
        rule_prefix="HKTL"
        description="Hacktool/Pentest tool"
    fi
    
    # Generate improved rule name
    local improved_name="${rule_prefix}_Unknown_Sample"
    if [ -n "$date" ]; then
        local date_short=$(echo "$date" | sed 's/20\([0-9]\{2\}\)-\([0-9]\{2\}\)-[0-9]\{2\}/\1\2/')
        improved_name="${rule_prefix}_Unknown_Sample_${date_short}"
    fi
    
    # Output improved rule header
    cat << EOF
/*
   YARA Rule Set
   Author: ${author:-yarGen}
   Date: ${date:-$(date +%Y-%m-%d)}
   Identifier: ${hash:0:32}
   Reference: ${reference}
*/

/* Rule Set ----------------------------------------------------------------- */

rule ${improved_name} {
   meta:
      description = "${description:-Suspicious executable - requires analysis}"
      author = "${author:-yarGen}"
      date = "${date:-$(date +%Y-%m-%d)}"
      hash1 = "${hash}"
      score = ${score:-75}
EOF
    
    # Add VT context if available
    if [ -n "$vt_detections" ]; then
        echo "      vt_detection = \"${vt_detections}/72\""
    fi
    if [ -n "$vt_tags" ]; then
        echo "      vt_tags = \"${vt_tags}\""
    fi
    
    # Extract strings from original rule
    echo "   strings:"
    
    # Parse strings and collect them with their goodware counts for scoring
    # Format: "goodware_count|string_content"
    declare -a scored_strings
    local has_opcodes=false
    local opcode_line=""
    
    # Patterns for low-quality strings to exclude
    # - Build artifacts: GCC, MSVC, stack frame patterns
    # - Random code: short garbage strings, non-word characters
    # - Compiler noise
    local skip_pattern='(GCC:|Built by MSYS|clang version|Microsoft Visual|stack frame|\[\^_\]|\^[A-Z]\|\\[A-Z]\^)'
    
    while IFS= read -r line; do
        # Check for opcode patterns - keep max 1-2
        if echo "$line" | grep -qE '^\s*\$op[0-9]+\s*='; then
            has_opcodes=true
            # Only keep first opcode (most significant)
            if [ -z "$opcode_line" ]; then
                opcode_line="$line"
            fi
            continue
        fi
        
        # Check if this is a string definition line ($x, $s, etc.)
        if echo "$line" | grep -qE '^\s*\$[xsafp][0-9]+\s*='; then
            # Extract the string value for analysis
            local str_value
            str_value=$(echo "$line" | grep -oP '=\s*"\K[^"]+' | head -1)
            
            # Skip build artifacts and garbage strings
            if [ -z "$str_value" ] || [ "$str_value" = " " ]; then
                continue  # Empty string
            fi
            # Compiler/build strings
            case "$str_value" in
                *"GCC:"*|*"Built by MSYS"*|*"Microsoft"*|*"Visual Studio"*|*"clang version"*)
                    continue
                    ;;
            esac
            # Stack frame artifacts: strings with mostly ^ [ ] \ _ and capital letters
            # These are machine code that happens to be in ASCII range
            local special_chars alpha_chars
            special_chars=$(echo "$str_value" | tr -cd '[]^_\\' | wc -c)
            alpha_chars=$(echo "$str_value" | tr -cd '[:alpha:]' | wc -c)
            if [ "$special_chars" -ge 3 ] && [ "$special_chars" -ge "$alpha_chars" ]; then
                continue  # Too many brackets/special chars relative to letters
            fi
            # Random-looking short strings (likely machine code in ASCII range)
            # Meaningful strings have: words, format specifiers, paths, identifiers
            local str_len=${#str_value}
            if [ "$str_len" -ge 6 ] && [ "$str_len" -le 20 ]; then
                # Skip if string looks like garbage (no structure)
                # Meaningful patterns: spaces (words), underscores (identifiers), 
                # format specs (%s, %d), paths (\, /), extensions (.exe)
                if ! echo "$str_value" | grep -qE '[ _]|%[sdxpufcl]|\\\\|/|\.[a-zA-Z]{2,4}$|^[A-Z][a-z]+'; then
                    # No meaningful structure - check character distribution
                    # Garbage often has: mixed case without pattern, digits mixed with letters, punctuation
                    local lower upper digit
                    lower=$(echo "$str_value" | tr -cd '[:lower:]' | wc -c)
                    upper=$(echo "$str_value" | tr -cd '[:upper:]' | wc -c)
                    digit=$(echo "$str_value" | tr -cd '[:digit:]' | wc -c)
                    # Random code often has roughly equal mix of cases
                    # Or starts with digit/has digits scattered throughout
                    if [ "$digit" -ge 1 ] && [ "$upper" -ge 2 ] && [ "$lower" -ge 2 ]; then
                        continue  # Looks like random mixed code: "8MZuEHcP<H"
                    fi
                fi
            fi
            
            # Extract goodware count (default to 0 if not found)
            local gw_count=0
            if echo "$line" | grep -qE '/\* goodware:\s*[0-9]+\s*\*/'; then
                gw_count=$(echo "$line" | grep -oP '/\* goodware:\s*\K[0-9]+' | head -1)
            fi
            # Store as "goodware_count|full_line" for sorting
            scored_strings+=("${gw_count}|${line}")
        fi
    done < <(sed -n '/strings:/,/condition:/p' "$input_file" | tail -n +2 | head -n -1)
    
    # Sort by goodware count (lowest first = highest scoring)
    # Use process substitution with sort
    local sorted_strings
    sorted_strings=$(printf '%s\n' "${scored_strings[@]}" | sort -t'|' -k1 -n)
    
    # Limit to maximum 10 strings total (optimal 3-7)
    # Keep 1 opcode (if present) + up to 9 strings, but aim for 3-7 total
    local max_strings=7  # Aim for optimal range
    if [ ${#scored_strings[@]} -gt 10 ]; then
        max_strings=9  # Allow up to 9 if we have many, plus 1 opcode = 10 total
    fi
    
    local string_count=0
    local x_count=0 s_count=0
    
    # Output sorted strings (best ones first)
    while IFS='|' read -r gw_count line; do
        [ -z "$line" ] && continue
        
        string_count=$((string_count + 1))
        if [ $string_count -gt $max_strings ]; then
            break
        fi
        
        # Extract just the value part and the string value
        local value_part str_value
        value_part=$(echo "$line" | sed -E 's/^\s*\$[xsafp][0-9]+\s*=\s*/= /')
        str_value=$(echo "$line" | grep -oP '=\s*"\K[^"]+' | head -1)
        
        # Categorize: Highly specific strings get $x*, most others get $s*
        # $x* criteria: unique filename, specific identifier (not generic), unique string
        # $s* criteria: generic service names, format strings, common text
        local is_highly_specific=false
        
        # Check if highly specific (unique identifier or filename)
        if echo "$str_value" | grep -qE '\.exe$|\.dll$|\.bin$'; then
            # Executable filenames are somewhat specific
            if ! echo "$str_value" | grep -qiE 'svchost\.exe|explorer\.exe|cmd\.exe|powershell\.exe'; then
                is_highly_specific=true
            fi
        elif echo "$str_value" | grep -qE '^[a-z]+_[a-z]+$'; then
            # Identifier with underscore like "svchost_upd" - somewhat specific
            is_highly_specific=true
        fi
        
        # Most strings should be $s* (grouped, need multiple)
        if [ "$is_highly_specific" = true ]; then
            x_count=$((x_count + 1))
            echo "      \$x${x_count} ${value_part}"
        else
            s_count=$((s_count + 1))
            echo "      \$s${s_count} ${value_part}"
        fi
    done <<< "$sorted_strings"
    
    # Output opcode if we have one
    if [ -n "$opcode_line" ]; then
        echo "      ${opcode_line#* }"  # Remove leading whitespace
    fi
    
    # Extract condition
    echo ""
    echo "   condition:"
    
    # Get condition lines (between condition: and closing brace)
    local condition_content
    condition_content=$(sed -n '/condition:/,/^[[:space:]]*}/p' "$input_file" | tail -n +2 | head -n -1)
    
    # Fix condition based on string types present
    if [ "$has_opcodes" = false ]; then
        # Remove opcode conditions if no opcodes present
        condition_content=$(echo "$condition_content" | sed -E 's/and[[:space:]]+(any|all) of \(\$op\*\)//g')
    else
        # Fix 'all of ($op*)' to 'any of ($op*)' when only one opcode
        condition_content=$(echo "$condition_content" | sed 's/all of (\$op\*)/any of ($op*)/g')
    fi
    
    # Fix filesize condition if it's clearly wrong (less than 100KB is often a yarGen bug)
    # Remove overly restrictive filesize conditions - let analyst decide
    if echo "$condition_content" | grep -qE 'filesize\s*<\s*[0-9]+KB'; then
        local fs_value
        fs_value=$(echo "$condition_content" | grep -oP 'filesize\s*<\s*\K[0-9]+' | head -1)
        if [ -n "$fs_value" ] && [ "$fs_value" -lt 100 ]; then
            # Replace with more reasonable default (500KB for PE files)
            condition_content=$(echo "$condition_content" | sed -E 's/filesize\s*<\s*[0-9]+KB/filesize < 500KB/g')
        fi
    fi
    
    # Update condition based on string types
    # Most strings are now $s* (grouped), few are $x* (highly specific)
    # Require multiple $s* matches for detection
    
    if [ "$s_count" -gt 0 ]; then
        # Replace original condition with grouped string logic
        # Use 3 of ($s*) as default, or fewer if we don't have enough
        local s_threshold=3
        if [ "$s_count" -lt 3 ]; then
            s_threshold=$s_count
        fi
        
        if [ "$x_count" -gt 0 ]; then
            # We have both $x and $s strings: 1 of ($x*) or 3 of ($s*)
            condition_content=$(echo "$condition_content" | sed "s/1 of (\\\$x\*)/1 of (\$x*) or ${s_threshold} of (\$s*)/g")
        else
            # Only $s strings: just require 3 of ($s*)
            condition_content=$(echo "$condition_content" | sed "s/1 of (\\\$x\*)/${s_threshold} of (\$s*)/g")
        fi
    fi
    
    # Output condition with proper indentation
    echo "$condition_content" | sed 's/^/      /'
    
    echo "}"
}

# Full pipeline: hash -> rule
cmd_generate_from_hash() {
    local hash="$1"
    
    if [ -z "$hash" ]; then
        log_error "Hash required"
        usage
        exit 1
    fi
    
    mkdir -p "$TEMP_DIR"
    local sample_path="${TEMP_DIR}/sample_${hash:0:16}.bin"
    local rule_path="${TEMP_DIR}/rule.yar"
    
    # Step 1: Download from VT
    if ! download_from_vt "$hash" "$sample_path"; then
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    
    # Step 2: Generate YARA rule
    if ! generate_rule "$sample_path" "$rule_path"; then
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    
    # Step 3: Review rule
    local improved_rule="${rule_path%.yar}_improved.yar"
    if [ -f "$rule_path" ]; then
        review_rule "$rule_path"
    fi
    
    # Output result - use improved version if available, otherwise original
    if [ -n "$OUTPUT" ]; then
        if [ -f "$improved_rule" ]; then
            cp "$improved_rule" "$OUTPUT"
            # Also save original for comparison
            cp "$rule_path" "${OUTPUT%.yar}_original.yar"
            log_success "Rule saved to: $OUTPUT"
            log_info "Original yarGen output saved to: ${OUTPUT%.yar}_original.yar"
        elif [ -f "$rule_path" ]; then
            cp "$rule_path" "$OUTPUT"
            log_success "Rule saved to: $OUTPUT"
        fi
    fi
    
    # Cleanup or save sample
    if [ -n "$SAVE_SAMPLE" ]; then
        cp "$sample_path" "$SAVE_SAMPLE"
        log_success "Sample saved to: $SAVE_SAMPLE"
    fi
    
    rm -rf "$TEMP_DIR"
    log_success "Pipeline complete!"
}

# Parse arguments
COMMAND=""
HASH=""
SAMPLE_PATH=""
RULE_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        generate-from-hash|download|generate|review)
            COMMAND="$1"
            shift
            ;;
        -a|--author)
            AUTHOR="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -r|--reference)
            REFERENCE="$2"
            shift 2
            ;;
        --no-vt-context)
            NO_VT_CONTEXT=true
            shift
            ;;
        --skip-post-process)
            SKIP_POST_PROCESS=true
            shift
            ;;
        --save-sample)
            SAVE_SAMPLE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [ -z "$HASH" ] && [ -z "$SAMPLE_PATH" ] && [ -z "$RULE_FILE" ]; then
                # First positional arg
                case "$COMMAND" in
                    generate-from-hash|download)
                        HASH="$1"
                        ;;
                    generate)
                        SAMPLE_PATH="$1"
                        ;;
                    review)
                        RULE_FILE="$1"
                        ;;
                esac
            fi
            shift
            ;;
    esac
done

# Main
check_prerequisites

case "$COMMAND" in
    generate-from-hash)
        cmd_generate_from_hash "$HASH"
        ;;
    download)
        mkdir -p "$TEMP_DIR"
        download_from_vt "$HASH" "${SAVE_SAMPLE:-${TEMP_DIR}/sample.bin}"
        rm -rf "$TEMP_DIR"
        ;;
    generate)
        if [ -z "$SAMPLE_PATH" ]; then
            log_error "Sample path required"
            exit 1
        fi
        generate_rule "$SAMPLE_PATH" "$OUTPUT"
        ;;
    review)
        if [ -z "$RULE_FILE" ]; then
            log_error "Rule file required"
            exit 1
        fi
        review_rule "$RULE_FILE"
        ;;
    *)
        usage
        exit 1
        ;;
esac
