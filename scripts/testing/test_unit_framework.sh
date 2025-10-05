#!/bin/bash
# Quick validation of pytest framework setup

echo "🧪 Testing Multi-Platform System Hardening Tool - Unit Test Framework"
echo "====================================================================="

source venv/bin/activate

echo "✅ Testing Core Models..."
python -m pytest tests/test_models.py -q --tb=no
MODELS_EXIT=$?

echo "✅ Testing Database Operations..."
python -m pytest tests/test_database.py::TestDatabaseManager::test_database_initialization -q --tb=no
python -m pytest tests/test_database.py::TestDatabaseManager::test_save_and_retrieve_run -q --tb=no
python -m pytest tests/test_database.py::TestDatabaseManager::test_json_serialization_with_datetime -q --tb=no
DB_EXIT=$?

echo "✅ Testing Platform Factory..."
python -m pytest tests/test_platforms.py::TestPlatformFactory -q --tb=no
PLATFORM_EXIT=$?

echo ""
if [ $MODELS_EXIT -eq 0 ] && [ $DB_EXIT -eq 0 ] && [ $PLATFORM_EXIT -eq 0 ]; then
    echo "🎉 Unit Test Framework Setup: SUCCESSFUL"
    echo "✅ Core data models: Working"
    echo "✅ Database operations: Working"  
    echo "✅ Platform factory: Working"
    echo ""
    echo "📊 Test Coverage:"
    python -m pytest tests/test_models.py --cov=hardening_tool --cov-report=term-missing --tb=no -q | grep "TOTAL\|hardening_tool/core/models"
else
    echo "❌ Some tests failed - check individual test output above"
    exit 1
fi

echo ""
echo "🚀 Ready for full test development!"
echo "   Run: python -m pytest tests/ -v --cov=hardening_tool"