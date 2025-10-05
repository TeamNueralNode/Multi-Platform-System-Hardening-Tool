#!/bin/bash
# Demonstration script showing different privilege modes for the Desktop GUI

echo "🛡️ Multi-Platform System Hardening Tool - Privilege Demo"
echo "========================================================"

# Function to check current privileges
check_privileges() {
    if [ "$EUID" -eq 0 ]; then
        echo "✅ Current Status: Running as Administrator (root)"
        echo "   Full functionality available including:"
        echo "   • System audit and rule application" 
        echo "   • Real hardening with rollback capability"
        echo "   • All system configuration modifications"
    else
        echo "ℹ️  Current Status: Running as Standard User"
        echo "   Available functionality:"
        echo "   • Security audits (full functionality)"
        echo "   • Dry-run mode (safe preview of changes)"
        echo "   • Report generation and rule browsing"
        echo "   • System information and logging"
    fi
    echo ""
}

# Show current status
check_privileges

# Menu options
echo "Demo Options:"
echo "1. Launch GUI as Standard User (current mode)"
echo "2. Launch GUI with Administrative Privileges (sudo)"
echo "3. Show privilege comparison"
echo "4. Exit"
echo ""

read -p "Select option [1-4]: " choice

case $choice in
    1)
        echo "🚀 Launching Desktop GUI as Standard User..."
        echo "   Note: You'll see helpful privilege guidance in the interface"
        python3 desktop_gui.py
        ;;
    2)
        echo "🔐 Launching Desktop GUI with Administrative Privileges..."
        echo "   Note: You'll have full access to system modification features"
        sudo python3 desktop_gui.py
        ;;
    3)
        echo ""
        echo "📊 Privilege Comparison:"
        echo "======================"
        echo ""
        echo "Standard User Mode:"
        echo "✅ Security Audits - Complete system security assessment"
        echo "✅ Rule Browsing - View and search all hardening rules"
        echo "✅ Dry-Run Mode - Safe preview of changes without applying"
        echo "✅ Report Generation - PDF, HTML, JSON compliance reports"
        echo "✅ System Information - OS detection and tool status"
        echo "✅ Log Management - View, export, and manage operation logs"
        echo "❌ Apply Changes - Cannot modify actual system configurations"
        echo "❌ Rollback Operations - Cannot create or restore rollback points"
        echo ""
        echo "Administrator Mode:"
        echo "✅ All Standard User Features (above)"
        echo "✅ Apply Hardening Rules - Modify system configurations"
        echo "✅ Create Rollback Points - Automatic backup before changes"
        echo "✅ Restore from Rollbacks - Safe recovery from previous state"
        echo "✅ Service Management - Start/stop/configure system services"
        echo "✅ File Permissions - Modify critical system file permissions"
        echo "✅ Network Configuration - Firewall and network security settings"
        echo ""
        echo "Security Note: Administrative privileges are required for system"
        echo "modifications to prevent unauthorized security changes."
        ;;
    4)
        echo "👋 Goodbye!"
        exit 0
        ;;
    *)
        echo "❌ Invalid option. Please run the script again."
        exit 1
        ;;
esac