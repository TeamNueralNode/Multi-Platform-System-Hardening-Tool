#!/bin/bash
# Apply Mount Options Script
# Applies secure mount options to specified filesystem paths

set -euo pipefail

# Configuration
FSTAB_FILE="/etc/fstab"
ROLLBACK_DIR="/var/log/hardening-tool"
ROLLBACK_FILE="$ROLLBACK_DIR/mount_options_rollback_$(date +%Y%m%d_%H%M%S).json"
BACKUP_FSTAB="$ROLLBACK_DIR/fstab_backup_$(date +%Y%m%d_%H%M%S)"

# Default paths to secure
DEFAULT_PATHS=(
    "/tmp"
    "/dev/shm" 
    "/home"
    "/var"
    "/var/tmp"
    "/var/log"
    "/var/log/audit"
)

# Function to show usage
usage() {
    echo "Usage: $0 [--audit|--apply] [--paths path1,path2,...] [--help]"
    echo "  --audit              Check current mount options without changes"
    echo "  --apply              Apply secure mount options to fstab and remount"
    echo "  --paths path1,path2  Comma-separated list of paths (default: /tmp,/dev/shm,/home,/var,/var/tmp,/var/log,/var/log/audit)"
    echo "  --help               Show this help message"
    exit 1
}

# Function to get desired options for a path
get_desired_options() {
    local path="$1"
    local options=""
    
    case "$path" in
        "/tmp"|"/dev/shm"|"/var/tmp"|"/var/log"*)
            options="nodev,nosuid,noexec"
            ;;
        "/home")
            options="nodev"
            ;;
        "/var")
            options="nodev"
            ;;
        *)
            options="nodev,nosuid"
            ;;
    esac
    
    echo "$options"
}

# Function to check if path is a separate partition
is_separate_partition() {
    local path="$1"
    
    # Check if exact mountpoint exists
    if findmnt --target "$path" --noheadings >/dev/null 2>&1; then
        local mount_target
        mount_target=$(findmnt --target "$path" --noheadings --output TARGET | head -1)
        if [[ "$mount_target" == "$path" ]]; then
            return 0
        fi
    fi
    
    return 1
}

# Function to get current device for path
get_device_for_path() {
    local path="$1"
    findmnt --target "$path" --noheadings --output SOURCE | head -1
}

# Function to get current options for path
get_current_options() {
    local path="$1"
    findmnt --target "$path" --noheadings --output OPTIONS | head -1
}

# Function to backup fstab
backup_fstab() {
    mkdir -p "$ROLLBACK_DIR"
    cp "$FSTAB_FILE" "$BACKUP_FSTAB"
    echo "Backed up $FSTAB_FILE to $BACKUP_FSTAB"
}

# Function to check if options are already present
has_required_options() {
    local current_options="$1"
    local required_options="$2"
    
    IFS=',' read -ra REQUIRED <<< "$required_options"
    for option in "${REQUIRED[@]}"; do
        if [[ ",$current_options," != *",$option,"* ]]; then
            return 1
        fi
    done
    return 0
}

# Function to add options to existing options string
merge_options() {
    local current="$1"
    local new="$2"
    local merged="$current"
    
    IFS=',' read -ra NEW_OPTS <<< "$new"
    for option in "${NEW_OPTS[@]}"; do
        if [[ ",$current," != *",$option,"* ]]; then
            if [[ -n "$merged" ]]; then
                merged="$merged,$option"
            else
                merged="$option"
            fi
        fi
    done
    
    echo "$merged"
}

# Function to update fstab entry
update_fstab_entry() {
    local device="$1"
    local mountpoint="$2" 
    local desired_options="$3"
    local changes_made=false
    
    # Create temporary file
    local temp_fstab
    temp_fstab=$(mktemp)
    
    # Track if we found and updated the entry
    local entry_found=false
    
    while IFS= read -r line; do
        # Skip empty lines and comments
        if [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]]; then
            echo "$line" >> "$temp_fstab"
            continue
        fi
        
        # Parse fstab line
        read -r fs_spec fs_file fs_vfstype fs_mntops fs_freq fs_passno <<< "$line"
        
        # Check if this line matches our target
        if [[ "$fs_file" == "$mountpoint" ]] || [[ "$fs_spec" == "$device" && "$fs_file" == "$mountpoint" ]]; then
            entry_found=true
            
            # Check if options need updating
            local current_options="$fs_mntops"
            if ! has_required_options "$current_options" "$desired_options"; then
                # Merge options
                local new_options
                new_options=$(merge_options "$current_options" "$desired_options")
                
                # Write updated line
                echo "$fs_spec $fs_file $fs_vfstype $new_options ${fs_freq:-0} ${fs_passno:-0}" >> "$temp_fstab"
                changes_made=true
                echo "Updated fstab entry for $mountpoint: added options $desired_options"
            else
                # No changes needed
                echo "$line" >> "$temp_fstab"
            fi
        else
            # Copy line unchanged
            echo "$line" >> "$temp_fstab"
        fi
    done < "$FSTAB_FILE"
    
    # If entry wasn't found and it's a separate partition, add new entry
    if [[ "$entry_found" == false ]]; then
        echo "# Added by hardening script - $(date)" >> "$temp_fstab"
        echo "$device $mountpoint auto $desired_options 0 0" >> "$temp_fstab"
        changes_made=true
        echo "Added new fstab entry for $mountpoint"
    fi
    
    # Replace fstab if changes were made
    if [[ "$changes_made" == true ]]; then
        mv "$temp_fstab" "$FSTAB_FILE"
        return 0
    else
        rm "$temp_fstab"
        return 1
    fi
}

# Function to remount filesystem with new options
remount_filesystem() {
    local mountpoint="$1"
    local desired_options="$2"
    
    echo "Remounting $mountpoint with options: $desired_options"
    
    # Try to remount with new options
    if mount -o "remount,$desired_options" "$mountpoint" 2>/dev/null; then
        echo "Successfully remounted $mountpoint"
        return 0
    else
        echo "Warning: Could not remount $mountpoint. Reboot may be required."
        return 1
    fi
}

# Function to audit mount options
perform_audit() {
    local paths=("$@")
    
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"audit\","
    echo "  \"paths\": ["
    
    local first=true
    for path in "${paths[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        
        echo -n "    {"
        echo -n "\"path\": \"$path\", "
        
        if [[ ! -d "$path" ]]; then
            echo "\"exists\": false, \"action\": \"path does not exist\"}"
            continue
        fi
        
        echo -n "\"exists\": true, "
        
        if is_separate_partition "$path"; then
            local device
            device=$(get_device_for_path "$path")
            local current_options
            current_options=$(get_current_options "$path")
            local desired_options
            desired_options=$(get_desired_options "$path")
            
            echo -n "\"is_separate_partition\": true, "
            echo -n "\"device\": \"$device\", "
            echo -n "\"current_options\": \"$current_options\", "
            echo -n "\"desired_options\": \"$desired_options\", "
            
            if has_required_options "$current_options" "$desired_options"; then
                echo -n "\"compliant\": true, \"action\": \"compliant\"}"
            else
                echo -n "\"compliant\": false, \"action\": \"add options: $desired_options\"}"
            fi
        else
            echo -n "\"is_separate_partition\": false, \"action\": \"not a separate partition\"}"
        fi
    done
    
    echo ""
    echo "  ]"
    echo "}"
}

# Function to apply mount options
perform_apply() {
    local paths=("$@")
    local changes=()
    local remount_needed=()
    
    # Backup fstab first
    backup_fstab
    
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"operation\": \"apply\","
    echo "  \"backup_fstab\": \"$BACKUP_FSTAB\","
    echo "  \"paths\": ["
    
    local first=true
    for path in "${paths[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo ","
        fi
        
        echo -n "    {"
        echo -n "\"path\": \"$path\", "
        
        if [[ ! -d "$path" ]]; then
            echo "\"exists\": false, \"action\": \"skipped - path does not exist\"}"
            continue
        fi
        
        echo -n "\"exists\": true, "
        
        if is_separate_partition "$path"; then
            local device
            device=$(get_device_for_path "$path")
            local current_options
            current_options=$(get_current_options "$path")
            local desired_options
            desired_options=$(get_desired_options "$path")
            
            echo -n "\"is_separate_partition\": true, "
            echo -n "\"device\": \"$device\", "
            
            if ! has_required_options "$current_options" "$desired_options"; then
                # Update fstab
                if update_fstab_entry "$device" "$path" "$desired_options"; then
                    changes+=("Updated fstab entry for $path")
                    remount_needed+=("$path:$desired_options")
                    echo -n "\"fstab_updated\": true, "
                else
                    echo -n "\"fstab_updated\": false, "
                fi
                
                echo -n "\"action\": \"applied options: $desired_options\"}"
            else
                echo -n "\"action\": \"already compliant\"}"
            fi
        else
            echo -n "\"is_separate_partition\": false, \"action\": \"skipped - not separate partition\"}"
        fi
    done
    
    echo ""
    echo "  ],"
    echo "  \"summary\": {"
    echo "    \"changes_made\": ${#changes[@]},"
    echo "    \"remounts_needed\": ${#remount_needed[@]}"
    echo "  }"
    echo "}"
    
    # Attempt remounts
    for entry in "${remount_needed[@]}"; do
        IFS=':' read -r mount_path mount_options <<< "$entry"
        remount_filesystem "$mount_path" "$mount_options"
    done
    
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
    "operation": "mount_options_apply",
    "fstab_backup": "$BACKUP_FSTAB",
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
    "rollback_instructions": "Restore $FSTAB_FILE from $BACKUP_FSTAB and remount affected filesystems"
}
EOF

    echo "Rollback manifest created: $ROLLBACK_FILE" >&2
}

# Main execution
main() {
    local mode=""
    local paths_input=""
    
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
            --paths)
                paths_input="$2"
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
        echo "Error: Must specify --audit or --apply" >&2
        usage
    fi
    
    # Parse paths
    local paths
    if [[ -n "$paths_input" ]]; then
        IFS=',' read -ra paths <<< "$paths_input"
    else
        paths=("${DEFAULT_PATHS[@]}")
    fi
    
    # Check if running as root for apply operations
    if [[ "$mode" == "apply" && $EUID -ne 0 ]]; then
        echo "Error: Must run as root to apply changes" >&2
        exit 1
    fi
    
    # Execute requested operation
    case "$mode" in
        "audit")
            perform_audit "${paths[@]}"
            ;;
        "apply")
            perform_apply "${paths[@]}"
            ;;
    esac
}

# Run main function with all arguments
main "$@"