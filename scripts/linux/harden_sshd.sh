#!/bin/bash
# SSH Daemon Hardening Script - Annexure-B Compliance
# Audits and enforces secure SSH configuration

set -euo pipefail

# Configuration
SSHD_CONFIG="/etc/ssh/sshd_config"
ROLLBACK_DIR="/var/log/hardening-tool"
ROLLBACK_FILE="$ROLLBACK_DIR/sshd_rollback_$(date +%Y%m%d_%H%M%S).json"
BACKUP_CONFIG="$ROLLBACK_DIR/sshd_config_backup_$(date +%Y%m%d_%H%M%S)"

# SSH Security Configuration per Annexure-B
declare -A SSH_SETTINGS=(
    ["PermitRootLogin"]="no"
    ["PermitEmptyPasswords"]="no"
    ["UsePAM"]="yes"
    ["DisableForwarding"]="yes"
    ["GSSAPIAuthentication"]="no"
    ["X11Forwarding"]="no"
    ["AllowTcpForwarding"]="no"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="2"
    ["LoginGraceTime"]="60"
    ["MaxAuthTries"]="3"
    ["MaxSessions"]="4"
    ["MaxStartups"]="10:30:100"
    ["Protocol"]="2"
    ["LogLevel"]="INFO"
    ["IgnoreRhosts"]="yes"
    ["HostbasedAuthentication"]="no"
    ["PasswordAuthentication"]="yes"
    ["ChallengeResponseAuthentication"]="no"
    ["KerberosAuthentication"]="no"
    ["PubkeyAuthentication"]="yes"
    ["AuthorizedKeysFile"]=".ssh/authorized_keys"
    ["PermitUserEnvironment"]="no"
    ["Compression"]="delayed"
    ["TCPKeepAlive"]="yes"
    ["UseDNS"]="no"
    ["AllowUsers"]=""
    ["DenyUsers"]=""
    ["AllowGroups"]=""
    ["DenyGroups"]=""
)

# Secure algorithms and ciphers
declare -A SSH_ALGORITHMS=(
    ["MACs"]="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    ["Ciphers"]="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    ["KexAlgorithms"]="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"
    ["HostKeyAlgorithms"]="rsa-sha2-512,rsa-sha2-256,ssh-ed25519"
    ["PubkeyAcceptedKeyTypes"]="rsa-sha2-512,rsa-sha2-256,ssh-ed25519"
)

# Function to show usage
usage() {
    echo "Usage: $0 [--audit|--apply|--rollback] [--rollback-file FILE] [--help]"
    echo "  --audit              Check current SSH configuration"
    echo "  --apply              Apply secure SSH configuration"
    echo "  --rollback           Restore SSH configuration from backup"
    echo "  --rollback-file FILE Specify rollback file (default: latest)"
    echo "  --help               Show this help message"
    exit 1
}

# Function to get current SSH setting value
get_ssh_setting() {
    local setting="$1"
    local config_file="${2:-$SSHD_CONFIG}"
    
    # Handle case-insensitive matching and get the last occurrence
    grep -i "^[[:space:]]*${setting}[[:space:]]" "$config_file" 2>/dev/null | \
        tail -1 | \
        sed -E "s/^[[:space:]]*${setting}[[:space:]]+(.*)$/\1/i" | \
        xargs echo || echo ""
}

# Function to check if setting exists in config
setting_exists() {
    local setting="$1"
    local config_file="${2:-$SSHD_CONFIG}"
    
    grep -qi "^[[:space:]]*${setting}[[:space:]]" "$config_file" 2>/dev/null
}

# Function to validate SSH configuration
validate_sshd_config() {
    local config_file="${1:-$SSHD_CONFIG}"
    
    if sshd -t -f "$config_file" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to backup SSH config
backup_sshd_config() {
    mkdir -p "$ROLLBACK_DIR"
    cp "$SSHD_CONFIG" "$BACKUP_CONFIG"
    echo "Backed up SSH config to: $BACKUP_CONFIG" >&2
}

# Function to audit single SSH setting
audit_ssh_setting() {
    local setting="$1"
    local expected="$2"
    local current
    current=$(get_ssh_setting "$setting")
    
    local compliant=false
    local action="set to $expected"
    
    if [[ -n "$current" ]]; then
        # Handle special cases for boolean-like settings
        case "$expected" in
            "yes"|"no")
                if [[ "${current,,}" == "${expected,,}" ]]; then
                    compliant=true
                    action="already compliant"
                fi
                ;;
            *)
                if [[ "$current" == "$expected" ]]; then
                    compliant=true
                    action="already compliant"
                elif [[ -z "$expected" ]]; then
                    # For settings that should be empty/unset
                    compliant=true
                    action="already compliant"
                fi
                ;;
        esac
    else
        # Setting not found
        if [[ -z "$expected" ]]; then
            compliant=true
            action="not set (compliant)"
        else
            action="add $setting $expected"
        fi
    fi
    
    cat << EOF
    {
        "setting": "$setting",
        "expected": "$expected",
        "current": "$current",
        "compliant": $compliant,
        "action": "$action"
    }
EOF
}

# Function to perform SSH audit
perform_audit() {
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"audit\","
    echo "  \"config_file\": \"$SSHD_CONFIG\","
    echo "  \"config_exists\": $(if [[ -f "$SSHD_CONFIG" ]]; then echo "true"; else echo "false"; fi),"
    echo "  \"sshd_running\": $(if systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1; then echo "true"; else echo "false"; fi),"
    echo "  \"settings\": ["
    
    local first=true
    
    # Audit basic settings
    for setting in "${!SSH_SETTINGS[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        audit_ssh_setting "$setting" "${SSH_SETTINGS[$setting]}"
    done
    
    # Audit algorithm settings
    for setting in "${!SSH_ALGORITHMS[@]}"; do
        echo ","
        audit_ssh_setting "$setting" "${SSH_ALGORITHMS[$setting]}"
    done
    
    echo ""
    echo "  ],"
    
    # Overall compliance check
    local config_valid=false
    if [[ -f "$SSHD_CONFIG" ]] && validate_sshd_config; then
        config_valid=true
    fi
    
    echo "  \"config_valid\": $config_valid"
    echo "}"
}

# Function to set SSH configuration value
set_ssh_config() {
    local setting="$1"
    local value="$2"
    local config_file="${3:-$SSHD_CONFIG}"
    
    # Create a temporary file for safe editing
    local temp_config
    temp_config=$(mktemp)
    
    local setting_updated=false
    
    # Process existing config
    while IFS= read -r line; do
        # Check if this line contains our setting (case-insensitive)
        if echo "$line" | grep -qi "^[[:space:]]*${setting}[[:space:]]"; then
            if [[ "$setting_updated" == false ]]; then
                # Replace the first occurrence
                echo "$setting $value" >> "$temp_config"
                setting_updated=true
            fi
            # Skip other occurrences (comments them out)
        else
            echo "$line" >> "$temp_config"
        fi
    done < "$config_file"
    
    # If setting wasn't found, add it
    if [[ "$setting_updated" == false ]]; then
        echo "" >> "$temp_config"
        echo "# Added by hardening script - $(date)" >> "$temp_config"
        echo "$setting $value" >> "$temp_config"
    fi
    
    # Validate the new config
    if validate_sshd_config "$temp_config"; then
        mv "$temp_config" "$config_file"
        return 0
    else
        rm "$temp_config"
        echo "Error: Invalid SSH configuration for $setting = $value" >&2
        return 1
    fi
}

# Function to apply SSH hardening
perform_apply() {
    local changes=()
    local settings_applied=0
    local settings_failed=0
    
    # Backup current config
    backup_sshd_config
    
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"apply\","
    echo "  \"backup_file\": \"$BACKUP_CONFIG\","
    echo "  \"settings\": ["
    
    local first=true
    
    # Apply basic settings
    for setting in "${!SSH_SETTINGS[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        
        local expected="${SSH_SETTINGS[$setting]}"
        local current
        current=$(get_ssh_setting "$setting")
        
        local needs_update=false
        local action="no change needed"
        
        # Determine if update is needed
        if [[ -z "$expected" ]]; then
            # Setting should be unset/empty
            if [[ -n "$current" ]]; then
                needs_update=true
                action="remove setting"
            fi
        else
            # Setting should have specific value
            case "$expected" in
                "yes"|"no")
                    if [[ "${current,,}" != "${expected,,}" ]]; then
                        needs_update=true
                        action="set to $expected"
                    fi
                    ;;
                *)
                    if [[ "$current" != "$expected" ]]; then
                        needs_update=true
                        action="set to $expected"
                    fi
                    ;;
            esac
        fi
        
        # Apply change if needed
        local success=true
        if [[ "$needs_update" == true ]]; then
            if [[ -n "$expected" ]]; then
                if set_ssh_config "$setting" "$expected"; then
                    changes+=("Set $setting = $expected")
                    settings_applied=$((settings_applied + 1))
                else
                    success=false
                    settings_failed=$((settings_failed + 1))
                    action="failed to apply"
                fi
            fi
        fi
        
        echo "    {"
        echo "      \"setting\": \"$setting\","
        echo "      \"expected\": \"$expected\","
        echo "      \"applied\": $needs_update,"
        echo "      \"success\": $success,"
        echo "      \"action\": \"$action\""
        echo -n "    }"
    done
    
    # Apply algorithm settings
    for setting in "${!SSH_ALGORITHMS[@]}"; do
        echo ","
        
        local expected="${SSH_ALGORITHMS[$setting]}"
        local current
        current=$(get_ssh_setting "$setting")
        
        local needs_update=false
        local action="no change needed"
        
        if [[ "$current" != "$expected" ]]; then
            needs_update=true
            action="set secure algorithms"
        fi
        
        local success=true
        if [[ "$needs_update" == true ]]; then
            if set_ssh_config "$setting" "$expected"; then
                changes+=("Set $setting = $expected")
                settings_applied=$((settings_applied + 1))
            else
                success=false
                settings_failed=$((settings_failed + 1))
                action="failed to apply"
            fi
        fi
        
        echo "    {"
        echo "      \"setting\": \"$setting\","
        echo "      \"expected\": \"$expected\","
        echo "      \"applied\": $needs_update,"
        echo "      \"success\": $success,"
        echo "      \"action\": \"$action\""
        echo -n "    }"
    done
    
    echo ""
    echo "  ],"
    
    # Final validation and service restart
    local config_valid=false
    local service_restarted=false
    
    if validate_sshd_config; then
        config_valid=true
        
        # Restart SSH service
        if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
            service_restarted=true
            echo "SSH service restarted successfully" >&2
        else
            echo "Warning: Failed to restart SSH service" >&2
        fi
    else
        echo "Error: Final SSH configuration is invalid, restoring backup" >&2
        cp "$BACKUP_CONFIG" "$SSHD_CONFIG"
    fi
    
    echo "  \"summary\": {"
    echo "    \"settings_applied\": $settings_applied,"
    echo "    \"settings_failed\": $settings_failed,"
    echo "    \"config_valid\": $config_valid,"
    echo "    \"service_restarted\": $service_restarted"
    echo "  }"
    echo "}"
    
    # Create rollback manifest
    if [[ ${#changes[@]} -gt 0 ]]; then
        create_rollback_manifest "${changes[@]}"
    fi
}

# Function to create rollback manifest
create_rollback_manifest() {
    local changes=("$@")
    
    mkdir -p "$ROLLBACK_DIR"
    
    cat << EOF > "$ROLLBACK_FILE"
{
    "timestamp": "$(date -Iseconds)",
    "operation": "sshd_hardening_apply",
    "backup_file": "$BACKUP_CONFIG",
    "original_config": "$SSHD_CONFIG",
    "changes": [
EOF

    local first=true
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
    "rollback_instructions": "Restore $SSHD_CONFIG from $BACKUP_CONFIG and restart SSH service"
}
EOF

    echo "Rollback manifest created: $ROLLBACK_FILE" >&2
}

# Function to perform rollback
perform_rollback() {
    local rollback_file="$1"
    
    if [[ ! -f "$rollback_file" ]]; then
        echo "Error: Rollback file not found: $rollback_file" >&2
        exit 1
    fi
    
    # Extract backup file path from rollback manifest
    local backup_file
    backup_file=$(grep '"backup_file"' "$rollback_file" | sed 's/.*"backup_file": "\([^"]*\)".*/\1/')
    
    if [[ ! -f "$backup_file" ]]; then
        echo "Error: Backup file not found: $backup_file" >&2
        exit 1
    fi
    
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"rollback\","
    echo "  \"rollback_file\": \"$rollback_file\","
    echo "  \"backup_file\": \"$backup_file\","
    
    # Restore config file
    cp "$backup_file" "$SSHD_CONFIG"
    local restore_success=true
    
    # Validate restored config
    local config_valid=false
    if validate_sshd_config; then
        config_valid=true
        
        # Restart SSH service
        if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
            echo "  \"service_restarted\": true,"
        else
            echo "  \"service_restarted\": false,"
        fi
    else
        echo "  \"service_restarted\": false,"
        restore_success=false
    fi
    
    echo "  \"success\": $restore_success,"
    echo "  \"config_valid\": $config_valid"
    echo "}"
    
    if [[ "$restore_success" == true ]]; then
        echo "SSH configuration successfully rolled back" >&2
    else
        echo "Error: Rollback failed - configuration is invalid" >&2
        exit 1
    fi
}

# Function to find latest rollback file
find_latest_rollback() {
    find "$ROLLBACK_DIR" -name "sshd_rollback_*.json" -type f 2>/dev/null | sort | tail -1
}

# Main execution
main() {
    local mode=""
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
                shift
                ;;
            --rollback-file)
                rollback_file="$2"
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
    
    # Check if SSH config exists
    if [[ ! -f "$SSHD_CONFIG" ]]; then
        echo "Error: SSH configuration file not found: $SSHD_CONFIG" >&2
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
            perform_audit
            ;;
        "apply")
            perform_apply
            ;;
        "rollback")
            if [[ -z "$rollback_file" ]]; then
                rollback_file=$(find_latest_rollback)
                if [[ -z "$rollback_file" ]]; then
                    echo "Error: No rollback files found in $ROLLBACK_DIR" >&2
                    exit 1
                fi
            fi
            perform_rollback "$rollback_file"
            ;;
    esac
}

# Run main function with all arguments
main "$@"