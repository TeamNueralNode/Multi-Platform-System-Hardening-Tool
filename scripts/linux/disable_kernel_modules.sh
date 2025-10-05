#!/bin/bash
# Kernel Module Hardening Script
# Disables unnecessary filesystem and storage modules per security requirements

set -euo pipefail

# Configuration
MODPROBE_CONF="/etc/modprobe.d/hardening.conf"
ROLLBACK_DIR="/var/log/hardening-tool"
ROLLBACK_FILE="$ROLLBACK_DIR/kernel_modules_rollback_$(date +%Y%m%d_%H%M%S).json"

# Modules to audit and potentially blacklist
MODULES_TO_CHECK=(
    "cramfs"
    "freevxfs" 
    "hfs"
    "hfsplus"
    "jffs2"
    "overlayfs"
    "squashfs"
    "udf"
    "usb-storage"
    "fat"
    "vfat"
    "ntfs"
    "isofs"
    "nfs"
    "nfsv3"
    "nfsv4"
    "cifs"
    "reiserfs"
    "xfs"
)

# Function to show usage
usage() {
    echo "Usage: $0 [--audit|--apply] [--help]"
    echo "  --audit    Check module status without making changes"
    echo "  --apply    Apply blacklist rules for unused modules"
    echo "  --help     Show this help message"
    exit 1
}

# Function to check if module is loaded
is_module_loaded() {
    local module="$1"
    grep -q "^$module " /proc/modules 2>/dev/null
}

# Function to check if module is blacklisted
is_module_blacklisted() {
    local module="$1"
    if [[ -f "$MODPROBE_CONF" ]]; then
        grep -q "^blacklist $module" "$MODPROBE_CONF" 2>/dev/null
    else
        return 1
    fi
}

# Function to check if module is available
is_module_available() {
    local module="$1"
    modprobe -n -v "$module" &>/dev/null || modinfo "$module" &>/dev/null
}

# Function to check if module is in use
is_module_in_use() {
    local module="$1"
    
    # Check if any filesystem is using this module
    case "$module" in
        "cramfs"|"freevxfs"|"hfs"|"hfsplus"|"jffs2"|"squashfs"|"udf"|"fat"|"vfat"|"ntfs"|"isofs"|"reiserfs"|"xfs")
            mount | grep -q "type $module" 2>/dev/null && return 0
            ;;
        "overlayfs")
            mount | grep -q "type overlay" 2>/dev/null && return 0
            ;;
        "usb-storage")
            lsusb | grep -q "Mass Storage" 2>/dev/null && return 0
            ;;
        "nfs"|"nfsv3"|"nfsv4")
            mount | grep -q "type nfs" 2>/dev/null && return 0
            ;;
        "cifs")
            mount | grep -q "type cifs" 2>/dev/null && return 0
            ;;
    esac
    
    return 1
}

# Function to audit single module
audit_module() {
    local module="$1"
    local loaded=false
    local blacklisted=false
    local available=false
    local in_use=false
    local action="none"
    
    # Check if module is loaded
    if is_module_loaded "$module"; then
        loaded=true
    fi
    
    # Check if module is blacklisted
    if is_module_blacklisted "$module"; then
        blacklisted=true
    fi
    
    # Check if module is available
    if is_module_available "$module"; then
        available=true
    fi
    
    # Check if module is in use
    if is_module_in_use "$module"; then
        in_use=true
    fi
    
    # Determine recommended action
    if [[ "$available" == true && "$blacklisted" == false && "$in_use" == false ]]; then
        action="blacklist recommended"
    elif [[ "$blacklisted" == true ]]; then
        action="already blacklisted"
    elif [[ "$available" == false ]]; then
        action="module not available"
    elif [[ "$in_use" == true ]]; then
        action="module in use - skip"
    fi
    
    # Output JSON for this module
    cat << EOF
    {
        "module": "$module",
        "loaded": $loaded,
        "blacklisted": $blacklisted,
        "available": $available,
        "in_use": $in_use,
        "action": "$action"
    }
EOF
}

# Function to blacklist module
blacklist_module() {
    local module="$1"
    
    # Create modprobe config directory if it doesn't exist
    mkdir -p "$(dirname "$MODPROBE_CONF")"
    
    # Create config file if it doesn't exist
    if [[ ! -f "$MODPROBE_CONF" ]]; then
        echo "# Hardening Tool - Kernel Module Blacklist" > "$MODPROBE_CONF"
        echo "# Generated on $(date)" >> "$MODPROBE_CONF"
        echo "" >> "$MODPROBE_CONF"
    fi
    
    # Add blacklist entry if not already present
    if ! is_module_blacklisted "$module"; then
        echo "blacklist $module" >> "$MODPROBE_CONF"
        echo "install $module /bin/true" >> "$MODPROBE_CONF"
        return 0
    else
        return 1
    fi
}

# Function to create rollback manifest
create_rollback_manifest() {
    local changes=("$@")
    
    mkdir -p "$ROLLBACK_DIR"
    
    cat << EOF > "$ROLLBACK_FILE"
{
    "timestamp": "$(date -Iseconds)",
    "operation": "kernel_module_blacklist",
    "config_file": "$MODPROBE_CONF",
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
    "rollback_instructions": "Remove the blacklist lines from $MODPROBE_CONF and run 'depmod -a' to restore modules"
}
EOF

    echo "Rollback manifest created: $ROLLBACK_FILE"
}

# Function to perform audit
perform_audit() {
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"audit\","
    echo "  \"modules\": ["
    
    local first=true
    for module in "${MODULES_TO_CHECK[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        audit_module "$module"
    done
    
    echo "  ],"
    echo "  \"config_file\": \"$MODPROBE_CONF\","
    echo "  \"config_exists\": $(if [[ -f "$MODPROBE_CONF" ]]; then echo "true"; else echo "false"; fi)"
    echo "}"
}

# Function to apply blacklist rules
perform_apply() {
    local changes=()
    local modules_processed=0
    local modules_blacklisted=0
    
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"apply\","
    echo "  \"modules\": ["
    
    local first=true
    for module in "${MODULES_TO_CHECK[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        
        modules_processed=$((modules_processed + 1))
        
        # Check if we should blacklist this module
        local should_blacklist=false
        if is_module_available "$module" && ! is_module_blacklisted "$module" && ! is_module_in_use "$module"; then
            should_blacklist=true
        fi
        
        if [[ "$should_blacklist" == true ]]; then
            if blacklist_module "$module"; then
                changes+=("blacklist $module")
                modules_blacklisted=$((modules_blacklisted + 1))
                
                # Try to remove module if loaded
                if is_module_loaded "$module"; then
                    modprobe -r "$module" 2>/dev/null || true
                fi
                
                cat << EOF
        {
            "module": "$module",
            "loaded": $(is_module_loaded "$module" && echo "true" || echo "false"),
            "blacklisted": true,
            "available": true,
            "action": "blacklist applied"
        }
EOF
            else
                audit_module "$module"
            fi
        else
            audit_module "$module"
        fi
    done
    
    echo "  ],"
    echo "  \"summary\": {"
    echo "    \"modules_processed\": $modules_processed,"
    echo "    \"modules_blacklisted\": $modules_blacklisted,"
    echo "    \"config_file\": \"$MODPROBE_CONF\""
    echo "  }"
    echo "}"
    
    # Update module dependencies if changes were made
    if [[ ${#changes[@]} -gt 0 ]]; then
        echo "Updating module dependencies..." >&2
        depmod -a
        
        # Create rollback manifest
        create_rollback_manifest "${changes[@]}"
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
    
    # Check if running as root for apply operations
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