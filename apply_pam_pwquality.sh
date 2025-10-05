#!/bin/bash
# Apply PAM Password Quality Configuration
# Safely configures PAM password quality settings per Annexure requirements

set -euo pipefail

# Configuration
ROLLBACK_DIR="/var/log/hardening-tool"
ROLLBACK_FILE="$ROLLBACK_DIR/pam_pwquality_rollback_$(date +%Y%m%d_%H%M%S).json"

# PAM configuration files (distribution-specific)
PAM_FILES=(
    "/etc/pam.d/common-password"  # Debian/Ubuntu
    "/etc/pam.d/system-auth"      # RHEL/CentOS/Fedora
    "/etc/pam.d/password-auth"    # RHEL/CentOS/Fedora
)

PWQUALITY_CONF="/etc/security/pwquality.conf"

# Required settings per Annexure
declare -A PWQUALITY_SETTINGS=(
    ["minlen"]="14"
    ["dcredit"]="-1"
    ["ucredit"]="-1"
    ["lcredit"]="-1"
    ["ocredit"]="-1"
    ["retry"]="3"
    ["dictcheck"]="1"
    ["maxrepeat"]="3"
    ["maxclasschg"]="4"
    ["minclass"]="4"
    ["difok"]="5"
    ["gecoscheck"]="1"
    ["enforce_for_root"]="1"
)

# Function to show usage
usage() {
    echo "Usage: $0 [--audit|--apply] [--help]"
    echo "  --audit    Check current PAM password quality configuration"
    echo "  --apply    Apply secure PAM password quality configuration"
    echo "  --help     Show this help message"
    exit 1
}

# Function to find active PAM password file
find_pam_file() {
    for pam_file in "${PAM_FILES[@]}"; do
        if [[ -f "$pam_file" ]]; then
            echo "$pam_file"
            return 0
        fi
    done
    return 1
}

# Function to backup files
backup_files() {
    local pam_file="$1"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    mkdir -p "$ROLLBACK_DIR"
    
    # Backup PAM file
    if [[ -f "$pam_file" ]]; then
        cp "$pam_file" "$ROLLBACK_DIR/$(basename "$pam_file")_backup_$timestamp"
        echo "Backed up $pam_file"
    fi
    
    # Backup pwquality.conf
    if [[ -f "$PWQUALITY_CONF" ]]; then
        cp "$PWQUALITY_CONF" "$ROLLBACK_DIR/pwquality.conf_backup_$timestamp"
        echo "Backed up $PWQUALITY_CONF"
    fi
}

# Function to check if PAM module is enabled
check_pam_module() {
    local pam_file="$1"
    local module="$2"
    
    grep -q "^[^#]*$module" "$pam_file" 2>/dev/null
}

# Function to get current pwquality setting
get_pwquality_setting() {
    local setting="$1"
    local value=""
    
    # Check pwquality.conf first
    if [[ -f "$PWQUALITY_CONF" ]]; then
        value=$(grep "^[[:space:]]*$setting[[:space:]]*=" "$PWQUALITY_CONF" 2>/dev/null | tail -1 | cut -d'=' -f2 | xargs)
    fi
    
    # Check PAM file for override (PAM settings take precedence)
    local pam_file
    if pam_file=$(find_pam_file); then
        local pam_setting
        pam_setting=$(grep "pam_pwquality" "$pam_file" 2>/dev/null | grep -o "$setting=[^[:space:]]*" | tail -1 | cut -d'=' -f2)
        if [[ -n "$pam_setting" ]]; then
            value="$pam_setting"
        fi
    fi
    
    echo "$value"
}

# Function to audit PAM modules
audit_pam_modules() {
    local pam_file
    if ! pam_file=$(find_pam_file); then
        echo "    {"
        echo "      \"error\": \"No PAM password configuration file found\","
        echo "      \"pam_pwquality\": false,"
        echo "      \"pam_pwhistory\": false,"
        echo "      \"pam_faillock\": false"
        echo "    }"
        return
    fi
    
    local pwquality_enabled=false
    local pwhistory_enabled=false
    local faillock_enabled=false
    
    if check_pam_module "$pam_file" "pam_pwquality"; then
        pwquality_enabled=true
    fi
    
    if check_pam_module "$pam_file" "pam_pwhistory"; then
        pwhistory_enabled=true
    fi
    
    if check_pam_module "$pam_file" "pam_faillock"; then
        faillock_enabled=true
    fi
    
    echo "    {"
    echo "      \"pam_file\": \"$pam_file\","
    echo "      \"pam_pwquality\": $pwquality_enabled,"
    echo "      \"pam_pwhistory\": $pwhistory_enabled,"
    echo "      \"pam_faillock\": $faillock_enabled"
    echo "    }"
}

# Function to audit pwquality settings
audit_pwquality_settings() {
    echo "    ["
    
    local first=true
    for setting in "${!PWQUALITY_SETTINGS[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        
        local current
        current=$(get_pwquality_setting "$setting")
        local required="${PWQUALITY_SETTINGS[$setting]}"
        local compliant=false
        local action="set_to_$required"
        
        if [[ "$current" == "$required" ]]; then
            compliant=true
            action="compliant"
        elif [[ -n "$current" ]]; then
            action="change_from_${current}_to_${required}"
        fi
        
        echo "      {"
        echo "        \"setting\": \"$setting\","
        echo "        \"current\": \"$current\","
        echo "        \"required\": \"$required\","
        echo "        \"compliant\": $compliant,"
        echo "        \"action\": \"$action\""
        echo -n "      }"
    done
    
    echo ""
    echo "    ]"
}

# Function to perform audit
perform_audit() {
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"audit\","
    echo "  \"pam_modules\":"
    audit_pam_modules
    echo ","
    echo "  \"pwquality_settings\":"
    audit_pwquality_settings
    echo ","
    
    # Calculate compliance
    local pam_file
    local modules_compliant=true
    local settings_compliant=true
    
    if pam_file=$(find_pam_file); then
        if ! check_pam_module "$pam_file" "pam_pwquality" || \
           ! check_pam_module "$pam_file" "pam_pwhistory" || \
           ! check_pam_module "$pam_file" "pam_faillock"; then
            modules_compliant=false
        fi
    else
        modules_compliant=false
    fi
    
    for setting in "${!PWQUALITY_SETTINGS[@]}"; do
        local current
        current=$(get_pwquality_setting "$setting")
        if [[ "$current" != "${PWQUALITY_SETTINGS[$setting]}" ]]; then
            settings_compliant=false
            break
        fi
    done
    
    local overall_compliant=false
    if [[ "$modules_compliant" == true && "$settings_compliant" == true ]]; then
        overall_compliant=true
    fi
    
    echo "  \"compliance\": {"
    echo "    \"pam_modules_compliant\": $modules_compliant,"
    echo "    \"settings_compliant\": $settings_compliant,"
    echo "    \"overall_compliant\": $overall_compliant"
    echo "  }"
    echo "}"
}

# Function to configure pwquality.conf
configure_pwquality_conf() {
    local changes=()
    
    # Create pwquality.conf if it doesn't exist
    if [[ ! -f "$PWQUALITY_CONF" ]]; then
        mkdir -p "$(dirname "$PWQUALITY_CONF")"
        cat > "$PWQUALITY_CONF" << EOF
# Password quality configuration - Generated by hardening script
# $(date)

EOF
        changes+=("Created $PWQUALITY_CONF")
    fi
    
    # Create temporary file for safe editing
    local temp_file
    temp_file=$(mktemp)
    
    # Copy existing content, filtering out settings we'll manage
    if [[ -f "$PWQUALITY_CONF" ]]; then
        while IFS= read -r line; do
            local skip=false
            for setting in "${!PWQUALITY_SETTINGS[@]}"; do
                if [[ "$line" =~ ^[[:space:]]*${setting}[[:space:]]*= ]]; then
                    skip=true
                    break
                fi
            done
            if [[ "$skip" == false ]]; then
                echo "$line" >> "$temp_file"
            fi
        done < "$PWQUALITY_CONF"
    fi
    
    # Add our settings
    echo "" >> "$temp_file"
    echo "# Password quality settings - Applied by hardening script" >> "$temp_file"
    echo "# $(date)" >> "$temp_file"
    
    for setting in "${!PWQUALITY_SETTINGS[@]}"; do
        local value="${PWQUALITY_SETTINGS[$setting]}"
        echo "$setting = $value" >> "$temp_file"
        changes+=("Set $setting = $value in pwquality.conf")
    done
    
    # Replace original file
    mv "$temp_file" "$PWQUALITY_CONF"
    chmod 644 "$PWQUALITY_CONF"
    
    echo "${changes[@]}"
}

# Function to configure PAM modules
configure_pam_modules() {
    local pam_file
    if ! pam_file=$(find_pam_file); then
        echo "Error: No PAM password configuration file found"
        return 1
    fi
    
    local changes=()
    local temp_file
    temp_file=$(mktemp)
    
    # Track which modules we need to add
    local need_pwquality=true
    local need_pwhistory=true
    local need_faillock=true
    
    # Process existing file
    while IFS= read -r line; do
        # Check if line contains our modules
        if echo "$line" | grep -q "pam_pwquality"; then
            need_pwquality=false
            # Update existing pwquality line to ensure proper configuration
            if echo "$line" | grep -q "^[[:space:]]*password"; then
                echo "password requisite pam_pwquality.so retry=3" >> "$temp_file"
                changes+=("Updated pam_pwquality configuration")
            else
                echo "$line" >> "$temp_file"
            fi
        elif echo "$line" | grep -q "pam_pwhistory"; then
            need_pwhistory=false
            echo "$line" >> "$temp_file"
        elif echo "$line" | grep -q "pam_faillock"; then
            need_faillock=false
            echo "$line" >> "$temp_file"
        else
            echo "$line" >> "$temp_file"
        fi
    done < "$pam_file"
    
    # Add missing modules
    if [[ "$need_pwquality" == true ]]; then
        echo "password requisite pam_pwquality.so retry=3" >> "$temp_file"
        changes+=("Added pam_pwquality module")
    fi
    
    if [[ "$need_pwhistory" == true ]]; then
        echo "password required pam_pwhistory.so remember=5 use_authtok" >> "$temp_file"
        changes+=("Added pam_pwhistory module")
    fi
    
    if [[ "$need_faillock" == true ]]; then
        # Add faillock to auth section (this is a simplified approach)
        # In practice, faillock configuration is more complex and may need auth section modification
        echo "# Note: pam_faillock should also be configured in auth section" >> "$temp_file"
        changes+=("Added pam_faillock note (manual auth section configuration may be needed)")
    fi
    
    # Replace original file
    mv "$temp_file" "$pam_file"
    chmod 644 "$pam_file"
    
    echo "${changes[@]}"
}

# Function to create rollback manifest
create_rollback_manifest() {
    local changes=("$@")
    
    mkdir -p "$ROLLBACK_DIR"
    
    local pam_file
    pam_file=$(find_pam_file) || pam_file="unknown"
    
    cat << EOF > "$ROLLBACK_FILE"
{
    "timestamp": "$(date -Iseconds)",
    "operation": "pam_pwquality_apply",
    "pam_file": "$pam_file",
    "pwquality_conf": "$PWQUALITY_CONF",
    "backup_files": [
EOF

    # List backup files
    local backup_files=()
    for file in "$ROLLBACK_DIR"/*backup_$(date +%Y%m%d)*; do
        if [[ -f "$file" ]]; then
            backup_files+=("\"$file\"")
        fi
    done
    
    local first=true
    for backup_file in "${backup_files[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo "," >> "$ROLLBACK_FILE"
        fi
        echo "        $backup_file" >> "$ROLLBACK_FILE"
    done

    cat << EOF >> "$ROLLBACK_FILE"
    ],
    "changes": [
EOF

    first=true
    for change in "${changes[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo "," >> "$ROLLBACK_FILE"
        fi
        echo "        \"$change\"" >> "$ROLLBACK_FILE"
    done

    cat << EOF >> "$ROLLBACK_FILE"
    ],
    "rollback_instructions": "Restore configuration files from backup and restart relevant services"
}
EOF

    echo "Rollback manifest created: $ROLLBACK_FILE" >&2
}

# Function to apply configuration
perform_apply() {
    local all_changes=()
    
    # Find PAM file
    local pam_file
    if ! pam_file=$(find_pam_file); then
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"operation\": \"apply\","
        echo "  \"success\": false,"
        echo "  \"error\": \"No PAM password configuration file found\""
        echo "}"
        return 1
    fi
    
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"apply\","
    echo "  \"pam_file\": \"$pam_file\","
    
    # Backup files
    backup_files "$pam_file"
    
    # Configure pwquality.conf
    echo "  \"pwquality_changes\": ["
    local pwquality_changes
    IFS=$'\n' read -rd '' -a pwquality_changes <<< "$(configure_pwquality_conf)" || true
    
    local first=true
    for change in "${pwquality_changes[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"$change\""
        all_changes+=("$change")
    done
    echo "  ],"
    
    # Configure PAM modules
    echo "  \"pam_changes\": ["
    local pam_changes
    IFS=$'\n' read -rd '' -a pam_changes <<< "$(configure_pam_modules)" || true
    
    first=true
    for change in "${pam_changes[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"$change\""
        all_changes+=("$change")
    done
    echo "  ],"
    
    echo "  \"success\": true,"
    echo "  \"changes_count\": ${#all_changes[@]}"
    echo "}"
    
    # Create rollback manifest
    if [[ ${#all_changes[@]} -gt 0 ]]; then
        create_rollback_manifest "${all_changes[@]}"
    fi
}

# Main execution
main() {
    local mode=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --audit)
                mode="audit"
                shift
                ;;
            --apply)
                mode="apply"
                shift
                ;;
            --help)
                usage
                ;;
            *)
                echo "Error: Unknown option $1" >&2
                usage
                ;;
        esac
    done
    
    # Validate arguments
    if [[ -z "$mode" ]]; then
        echo "Error: Must specify --audit or --apply" >&2
        usage
    fi
    
    # Check permissions for apply operations
    if [[ "$mode" == "apply" && $EUID -ne 0 ]]; then
        echo "Error: Must run as root to apply changes" >&2
        exit 1
    fi
    
    # Execute requested operation
    case "$mode" in
        "audit")
            perform_audit
            ;;
        "apply")
            perform_apply
            ;;
    esac
}

# Run main function with all arguments
main "$@"