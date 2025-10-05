#!/bin/bash
# Launch script for Multi-Platform System Hardening Tool Desktop GUI

echo "🛡️ Multi-Platform System Hardening Tool - Desktop GUI"
echo "======================================================"

# Check if we're in the right directory
if [ ! -f "desktop_gui.py" ]; then
    echo "❌ Error: Please run this script from the project root directory"
    echo "   Expected file: desktop_gui.py"
    exit 1
fi

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed or not in PATH"
    exit 1
fi

# Check if tkinter is available
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "❌ Error: tkinter is not available"
    echo "   Install with: sudo apt-get install python3-tk (Ubuntu/Debian)"
    echo "   Or: sudo yum install tkinter (CentOS/RHEL)"
    exit 1
fi

# Set display for GUI (if needed)
if [ -z "$DISPLAY" ]; then
    export DISPLAY=:0
fi

echo "✅ Python 3: $(python3 --version)"
echo "✅ Tkinter: Available"
echo "🚀 Starting Desktop GUI..."
echo ""

# Launch the GUI
python3 desktop_gui.py

echo ""
echo "Desktop GUI closed."