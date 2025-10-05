#!/bin/bash
# Quick setup script for Multi-Platform System Hardening Tool

echo "🚀 Setting up Multi-Platform System Hardening Tool Development Environment"
echo "=========================================================================="

# Check Python version
if ! python3 --version | grep -E "3\.(11|12|13)" > /dev/null; then
    echo "❌ Python 3.11+ required. Current version:"
    python3 --version
    exit 1
fi

echo "✅ Python version check passed"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -e ".[dev]"

# Validate installation
echo "🧪 Validating installation..."
if python setup_and_test.py > /dev/null 2>&1; then
    echo "✅ Setup validation passed"
else
    echo "⚠️ Setup validation had issues - running detailed check:"
    python setup_and_test.py
fi

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "💡 To activate the environment in the future:"
echo "   source venv/bin/activate"
echo ""
echo "🔍 To run tests:"
echo "   ./test_comprehensive.sh"
echo ""
echo "🛠️ To start developing:"
echo "   hardening-tool --help"
echo "   hardening-tool audit"