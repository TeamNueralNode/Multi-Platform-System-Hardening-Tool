#!/bin/bash
# Shadow File Hardening Script
# Ensures secure password aging and shadow file permissions per security requirements

set -euo pipefail

# Default configuration values
DEFAULT_PASS_MAX_DAYS=90
DEFAULT_PASS_MIN_DAYS=1
DEFAULT_PASS_WARN_AGE=7

# Configuration files
LOGIN_DEFS="/etc/login.defs"
SHADOW_FILE="/etc/shadow"
ROLLBACK_DIR="/var/log/hardening-tool"
ROLLBACK_FILE="$ROLLBACK_DIR/shadow_hardening_rollback_$(date +%Y%m%d_%H%M%S).json"

# Function to show usage
usage() {
    echo "Usage: $0 [--audit|--apply] [--max-days N] [--min-days N] [--warn-age N] [--rollback FILE] [--help]"
    echo "  --audit              Check current shadow file security configuration"
    echo "  --apply              Apply secure shadow file configuration"
    echo "  --max-days N         Set maximum password age in days (default: $DEFAULT_PASS_MAX_DAYS)"
    echo "  --min-days N         Set minimum password age in days (default: $DEFAULT_PASS_MIN_DAYS)"
    echo "  --warn-age N         Set password warning age in days (default: $DEFAULT_PASS_WARN_AGE)"
    echo "  --rollback FILE      Restore configuration from rollback file"
    echo "  --help               Show this help message"
    exit 1
}

# Function to get current setting from login.defs
get_login_defs_setting() {
    local setting="$1"
    local default="$2"
    
    if [[ -f "$LOGIN_DEFS" ]]; then
        grep "^[[:space:]]*$setting[[:space:]]" "$LOGIN_DEFS" 2>/dev/null | \
            tail -1 | awk '{print $2}' || echo "$default"
    else
        echo "$default"
    fi
}

# Function to check shadow file permissions
check_shadow_permissions() {
    local result="{}"
    
    if [[ ! -f "$SHADOW_FILE" ]]; then
        echo "{"
        echo "  \"file\": \"$SHADOW_FILE\","
        echo "  \"exists\": false,"
        echo "  \"error\": \"Shadow file does not exist\""
        echo "}"
        return
    fi
    
    # Get file permissions and ownership
    local perms
    perms=$(stat -c "%a" "$SHADOW_FILE" 2>/dev/null || echo "unknown")
    local owner
    owner=$(stat -c "%U:%G" "$SHADOW_FILE" 2>/dev/null || echo "unknown")
    
    local perms_compliant=false
    local owner_compliant=false
    
    if [[ "$perms" == "600" ]]; then
        perms_compliant=true
    fi
    
    if [[ "$owner" == "root:root" ]] || [[ "$owner" == "root:shadow" ]]; then
        owner_compliant=true
    fi
    
    local overall_compliant=false
    if [[ "$perms_compliant" == true && "$owner_compliant" == true ]]; then
        overall_compliant=true
    fi
    
    echo "{"
    echo "  \"file\": \"$SHADOW_FILE\","
    echo "  \"exists\": true,"
    echo "  \"permissions\": \"$perms\","
    echo "  \"owner\": \"$owner\","
    echo "  \"permissions_compliant\": $perms_compliant,"
    echo "  \"owner_compliant\": $owner_compliant,"
    echo "  \"overall_compliant\": $overall_compliant,"
    echo "  \"required_permissions\": \"600\","
    echo "  \"required_owner\": \"root:root\""
    echo "}"
}

# Function to check UID 0 accounts
check_uid_zero_accounts() {
    local uid_zero_accounts=()
    local compliant=true
    
    # Find all accounts with UID 0
    while IFS=: read -r username _ uid _; do
        if [[ "$uid" == "0" ]]; then
            uid_zero_accounts+=("$username")
            if [[ "$username" != "root" ]]; then
                compliant=false
            fi
        fi
    done < /etc/passwd
    
    echo "{"
    echo "  \"uid_zero_accounts\": ["
    
    local first=true
    for account in "${uid_zero_accounts[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"$account\""
    done
    
    echo "  ],"
    echo "  \"compliant\": $compliant,"
    echo "  \"violations\": ["
    
    first=true
    for account in "${uid_zero_accounts[@]}"; do
        if [[ "$account" != "root" ]]; then
            if [[ "$first" == true ]]; then
                first=false
            else
                echo ","
            fi
            echo "    \"$account\""
        fi
    done
    
    echo "  ]"
    echo "}"
}

# Function to check password aging settings
check_password_aging() {
    local max_days="$1"
    local min_days="$2" 
    local warn_age="$3"
    
    local current_max
    current_max=$(get_login_defs_setting "PASS_MAX_DAYS" "99999")
    local current_min
    current_min=$(get_login_defs_setting "PASS_MIN_DAYS" "0")
    local current_warn
    current_warn=$(get_login_defs_setting "PASS_WARN_AGE" "7")
    
    local max_compliant=false
    local min_compliant=false
    local warn_compliant=false
    
    if [[ "$current_max" == "$max_days" ]]; then
        max_compliant=true
    fi
    
    if [[ "$current_min" == "$min_days" ]]; then
        min_compliant=true
    fi
    
    if [[ "$current_warn" == "$warn_age" ]]; then
        warn_compliant=true
    fi
    
    local overall_compliant=false
    if [[ "$max_compliant" == true && "$min_compliant" == true && "$warn_compliant" == true ]]; then
        overall_compliant=true
    fi
    
    echo "{"
    echo "  \"PASS_MAX_DAYS\": {"
    echo "    \"current\": \"$current_max\","
    echo "    \"required\": \"$max_days\","
    echo "    \"compliant\": $max_compliant"
    echo "  },"
    echo "  \"PASS_MIN_DAYS\": {"
    echo "    \"current\": \"$current_min\","
    echo "    \"required\": \"$min_days\","
    echo "    \"compliant\": $min_compliant"
    echo "  },"
    echo "  \"PASS_WARN_AGE\": {"
    echo "    \"current\": \"$current_warn\","
    echo "    \"required\": \"$warn_age\","
    echo "    \"compliant\": $warn_compliant"
    echo "  },"
    echo "  \"overall_compliant\": $overall_compliant"
    echo "}"
}

# Function to backup files
backup_files() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    mkdir -p "$ROLLBACK_DIR"
    
    local backup_files=()
    
    # Backup login.defs
    if [[ -f "$LOGIN_DEFS" ]]; then
        local backup_login="$ROLLBACK_DIR/login.defs_backup_$timestamp"
        cp "$LOGIN_DEFS" "$backup_login"
        backup_files+=("$backup_login")
        echo "Backed up $LOGIN_DEFS to $backup_login" >&2
    fi
    
    # Backup shadow file permissions (just record current state)
    if [[ -f "$SHADOW_FILE" ]]; then
        local shadow_perms
        shadow_perms=$(stat -c "%a %U:%G" "$SHADOW_FILE" 2>/dev/null)
        echo "$shadow_perms" > "$ROLLBACK_DIR/shadow_perms_backup_$timestamp"
        backup_files+=("$ROLLBACK_DIR/shadow_perms_backup_$timestamp")
        echo "Recorded shadow permissions: $shadow_perms" >&2
    fi
    
    echo "${backup_files[@]}"
}

# Function to set login.defs setting
set_login_defs_setting() {
    local setting="$1"
    local value="$2"
    
    # Create login.defs if it doesn't exist
    if [[ ! -f "$LOGIN_DEFS" ]]; then
        mkdir -p "$(dirname "$LOGIN_DEFS")"
        cat > "$LOGIN_DEFS" << EOF
# Login configuration - Generated by hardening script
# $(date)

EOF
    fi
    
    # Create temporary file for safe editing
    local temp_file
    temp_file=$(mktemp)
    
    local setting_updated=false
    
    # Process existing file
    while IFS= read -r line; do
        # Check if this line contains our setting
        if echo "$line" | grep -q "^[[:space:]]*$setting[[:space:]]"; then
            if [[ "$setting_updated" == false ]]; then
                # Replace the first occurrence
                echo "$setting $value" >> "$temp_file"
                setting_updated=true
            fi
            # Skip other occurrences
        else
            echo "$line" >> "$temp_file"
        fi
    done < "$LOGIN_DEFS"
    
    # If setting wasn't found, add it
    if [[ "$setting_updated" == false ]]; then
        echo "" >> "$temp_file"
        echo "# Added by hardening script - $(date)" >> "$temp_file"
        echo "$setting $value" >> "$temp_file"
    fi
    
    # Replace original file
    mv "$temp_file" "$LOGIN_DEFS"
    chmod 644 "$LOGIN_DEFS"
}

# Function to fix shadow file permissions
fix_shadow_permissions() {
    local changes=()
    
    if [[ ! -f "$SHADOW_FILE" ]]; then
        return 1
    fi
    
    # Get current permissions and ownership
    local current_perms
    current_perms=$(stat -c "%a" "$SHADOW_FILE")
    local current_owner
    current_owner=$(stat -c "%U:%G" "$SHADOW_FILE")
    
    # Fix permissions if needed
    if [[ "$current_perms" != "600" ]]; then
        chmod 600 "$SHADOW_FILE"
        changes+=("Changed permissions from $current_perms to 600")
    fi
    
    # Fix ownership if needed
    if [[ "$current_owner" != "root:root" ]] && [[ "$current_owner" != "root:shadow" ]]; then
        chown root:root "$SHADOW_FILE"
        changes+=("Changed owner from $current_owner to root:root")
    fi
    
    echo "${changes[@]}"
}

# Function to create rollback manifest
create_rollback_manifest() {
    local backup_files=("$@")
    
    mkdir -p "$ROLLBACK_DIR"
    
    cat << EOF > "$ROLLBACK_FILE"
{
    "timestamp": "$(date -Iseconds)",
    "operation": "shadow_hardening_apply",
    "backup_files": [
EOF

    local first=true
    for backup_file in "${backup_files[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo "," >> "$ROLLBACK_FILE"
        fi
        echo "        \"$backup_file\"" >> "$ROLLBACK_FILE"
    done

    cat << EOF >> "$ROLLBACK_FILE"
    ],
    "rollback_instructions": "Restore files from backup and reset shadow permissions as needed"
}
EOF

    echo "Rollback manifest created: $ROLLBACK_FILE" >&2
}

# Function to perform audit
perform_audit() {
    local max_days="$1"
    local min_days="$2"
    local warn_age="$3"
    
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"audit\","
    echo "  \"password_aging\":"
    check_password_aging "$max_days" "$min_days" "$warn_age"
    echo ","
    echo "  \"shadow_permissions\":"
    check_shadow_permissions
    echo ","
    echo "  \"uid_zero_check\":"
    check_uid_zero_accounts
    echo ","
    
    # Overall compliance check
    local aging_compliant
    aging_compliant=$(check_password_aging "$max_days" "$min_days" "$warn_age" | jq -r '.overall_compliant' 2>/dev/null || echo "false")
    local perms_compliant
    perms_compliant=$(check_shadow_permissions | jq -r '.overall_compliant' 2>/dev/null || echo "false")
    local uid_compliant
    uid_compliant=$(check_uid_zero_accounts | jq -r '.compliant' 2>/dev/null || echo "false")
    
    local overall_compliant=false
    if [[ "$aging_compliant" == "true" && "$perms_compliant" == "true" && "$uid_compliant" == "true" ]]; then
        overall_compliant=true
    fi
    
    echo "  \"compliance\": {"
    echo "    \"password_aging_compliant\": $aging_compliant,"
    echo "    \"shadow_permissions_compliant\": $perms_compliant,"
    echo "    \"uid_zero_compliant\": $uid_compliant,"
    echo "    \"overall_compliant\": $overall_compliant"
    echo "  }"
    echo "}"
    
    # Exit with error if UID 0 violations found
    if [[ "$uid_compliant" == "false" ]]; then
        echo "CRITICAL: Non-root accounts with UID 0 detected!" >&2
        exit 2
    fi
}

# Function to apply configuration
perform_apply() {
    local max_days="$1"
    local min_days="$2"
    local warn_age="$3"
    
    # Check for UID 0 violations first - this is a critical security issue
    local uid_check
    uid_check=$(check_uid_zero_accounts)
    local uid_compliant
    uid_compliant=$(echo "$uid_check" | jq -r '.compliant' 2>/dev/null || echo "false")
    
    if [[ "$uid_compliant" == "false" ]]; then
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"operation\": \"apply\","
        echo "  \"success\": false,"
        echo "  \"error\": \"Critical security violation: Non-root accounts with UID 0 detected\","
        echo "  \"uid_zero_check\": $uid_check"
        echo "}"
        exit 2
    fi
    
    local all_changes=()
    
    # Backup files
    local backup_files_result
    backup_files_result=$(backup_files)
    IFS=' ' read -ra backup_files <<< "$backup_files_result"
    
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"apply\","
    echo "  \"backup_files\": ["
    
    local first=true
    for backup_file in "${backup_files[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"$backup_file\""
    done
    echo "  ],"
    
    # Apply password aging settings
    echo "  \"password_aging_changes\": ["
    
    # Check current settings and apply if needed
    local current_max
    current_max=$(get_login_defs_setting "PASS_MAX_DAYS" "99999")
    local current_min
    current_min=$(get_login_defs_setting "PASS_MIN_DAYS" "0")
    local current_warn
    current_warn=$(get_login_defs_setting "PASS_WARN_AGE" "7")
    
    first=true
    
    if [[ "$current_max" != "$max_days" ]]; then
        set_login_defs_setting "PASS_MAX_DAYS" "$max_days"
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"Set PASS_MAX_DAYS from $current_max to $max_days\""
        all_changes+=("Set PASS_MAX_DAYS from $current_max to $max_days")
    fi
    
    if [[ "$current_min" != "$min_days" ]]; then
        set_login_defs_setting "PASS_MIN_DAYS" "$min_days"
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"Set PASS_MIN_DAYS from $current_min to $min_days\""
        all_changes+=("Set PASS_MIN_DAYS from $current_min to $min_days")
    fi
    
    if [[ "$current_warn" != "$warn_age" ]]; then
        set_login_defs_setting "PASS_WARN_AGE" "$warn_age"
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"Set PASS_WARN_AGE from $current_warn to $warn_age\""
        all_changes+=("Set PASS_WARN_AGE from $current_warn to $warn_age")
    fi
    
    echo "  ],"
    
    # Fix shadow file permissions
    echo "  \"shadow_permission_changes\": ["
    
    local shadow_changes
    shadow_changes=$(fix_shadow_permissions)
    IFS=$'\n' read -rd '' -a shadow_changes_array <<< "$shadow_changes" || true
    
    first=true
    for change in "${shadow_changes_array[@]}"; do
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
    if [[ ${#backup_files[@]} -gt 0 ]]; then
        create_rollback_manifest "${backup_files[@]}"
    fi
}

# Function to perform rollback
perform_rollback() {
    local rollback_file="$1"
    
    if [[ ! -f "$rollback_file" ]]; then
        echo "Error: Rollback file not found: $rollback_file" >&2
        exit 1
    fi
    
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"rollback\","
    echo "  \"rollback_file\": \"$rollback_file\","
    
    # Extract backup files from rollback manifest
    local backup_files
    backup_files=$(jq -r '.backup_files[]' "$rollback_file" 2>/dev/null || echo "")
    
    local restored_files=()
    local errors=()
    
    while IFS= read -r backup_file; do
        if [[ -n "$backup_file" && -f "$backup_file" ]]; then
            if [[ "$backup_file" == *"login.defs_backup_"* ]]; then
                cp "$backup_file" "$LOGIN_DEFS"
                restored_files+=("$LOGIN_DEFS")
            elif [[ "$backup_file" == *"shadow_perms_backup_"* ]]; then
                # Restore shadow permissions
                local perms_owner
                perms_owner=$(cat "$backup_file" 2>/dev/null || echo "")
                if [[ -n "$perms_owner" ]]; then
                    local perms owner
                    read -r perms owner <<< "$perms_owner"
                    if [[ -n "$perms" && -n "$owner" ]]; then
                        chmod "$perms" "$SHADOW_FILE" 2>/dev/null || true
                        chown "$owner" "$SHADOW_FILE" 2>/dev/null || true
                        restored_files+=("$SHADOW_FILE permissions")
                    fi
                fi
            fi
        else
            errors+=("Backup file not found: $backup_file")
        fi
    done <<< "$backup_files"
    
    echo "  \"restored_files\": ["
    local first=true
    for file in "${restored_files[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"$file\""
    done
    echo "  ],"
    
    echo "  \"errors\": ["
    first=true
    for error in "${errors[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"$error\""
    done
    echo "  ],"
    
    local success=true
    if [[ ${#errors[@]} -gt 0 ]]; then
        success=false
    fi
    
    echo "  \"success\": $success"
    echo "}"
    
    if [[ "$success" != true ]]; then
        exit 1
    fi
}

# Main execution
main() {
    local mode=""
    local max_days="$DEFAULT_PASS_MAX_DAYS"
    local min_days="$DEFAULT_PASS_MIN_DAYS"
    local warn_age="$DEFAULT_PASS_WARN_AGE"
    local rollback_file=""
    
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
            --rollback)
                mode="rollback"
                rollback_file="$2"
                shift 2
                ;;
            --max-days)
                max_days="$2"
                shift 2
                ;;
            --min-days)
                min_days="$2"
                shift 2
                ;;
            --warn-age)
                warn_age="$2"
                shift 2
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
        echo "Error: Must specify --audit, --apply, or --rollback" >&2
        usage
    fi
    
    # Validate numeric arguments
    if ! [[ "$max_days" =~ ^[0-9]+$ ]] || ! [[ "$min_days" =~ ^[0-9]+$ ]] || ! [[ "$warn_age" =~ ^[0-9]+$ ]]; then
        echo "Error: Days arguments must be positive integers" >&2
        exit 1
    fi
    
    # Check permissions for apply/rollback operations
    if [[ "$mode" == "apply" || "$mode" == "rollback" ]] && [[ $EUID -ne 0 ]]; then
        echo "Error: Must run as root to apply changes or rollback" >&2
        exit 1
    fi
    
    # Execute requested operation
    case "$mode" in
        "audit")
            perform_audit "$max_days" "$min_days" "$warn_age"
            ;;
        "apply")
            perform_apply "$max_days" "$min_days" "$warn_age"
            ;;
        "rollback")
            if [[ -z "$rollback_file" ]]; then
                echo "Error: Must specify rollback file with --rollback" >&2
                exit 1
            fi
            perform_rollback "$rollback_file"
            ;;
    esac
}

# Run main function with all arguments
main "$@"