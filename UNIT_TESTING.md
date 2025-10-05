# Unit Testing Framework Guide

## 🧪 **Pytest Framework Successfully Implemented**

The Multi-Platform System Hardening Tool now has a **comprehensive unit testing framework** using pytest with coverage reporting, mocking capabilities, and structured test organization.

## 📁 **Test Structure**

```
tests/
├── __init__.py              # Test package marker
├── conftest.py             # Shared fixtures and utilities
├── test_models.py          # Core Pydantic model tests
├── test_database.py        # Database manager tests  
├── test_platforms.py       # Platform implementation tests
└── test_unit_framework.sh  # Quick validation script
```

## 🚀 **Quick Start**

### Setup Virtual Environment
```bash
./setup_dev_env.sh          # One-command setup
# OR manually:
source venv/bin/activate
pip install -e ".[dev]"
```

### Run Tests
```bash
# Quick validation
./test_unit_framework.sh

# Full test suite with coverage
python -m pytest tests/ -v --cov=hardening_tool

# Specific test modules
python -m pytest tests/test_models.py -v
python -m pytest tests/test_database.py -v
python -m pytest tests/test_platforms.py -v

# Coverage report
python -m pytest --cov=hardening_tool --cov-report=html
# View: htmlcov/index.html
```

## ✅ **Current Test Coverage**

### Working Tests (20+ passing)
- **Core Models (14 tests)**: SystemInfo, HardeningRule, RuleResult, HardeningRun, RollbackPoint
- **Database Operations (3 tests)**: Database initialization, run storage, JSON serialization
- **Platform Factory (5 tests)**: Platform selection, supported platforms list

### Test Categories
- **Unit Tests**: Individual component testing with mocks
- **Integration Tests**: Database workflows and platform interactions
- **Fixture-Based**: Shared test data and mock objects
- **Coverage Reporting**: Tracks code coverage across modules

## 📊 **Test Results Summary**

```
✅ Core data models: 100% passing (14/14)
✅ Database operations: Working (3/3 core tests)  
✅ Platform factory: 100% passing (5/5)
✅ Overall coverage: 21% (foundation established)
```

## 🏗️ **Test Framework Features**

### 1. **Fixtures & Utilities** (`conftest.py`)
- Mock system information objects
- Sample hardening rules and results
- Temporary database instances
- SSH configuration mocks
- Helper functions for test data creation

### 2. **Model Testing** (`test_models.py`)
- Pydantic model validation testing
- Serialization/deserialization testing
- Enum value verification
- Invalid input handling
- Model relationships testing

### 3. **Database Testing** (`test_database.py`)
- SQLite operations testing
- JSON serialization with datetime handling
- Encryption key management
- Data integrity verification
- Complete workflow testing

### 4. **Platform Testing** (`test_platforms.py`)
- Platform factory functionality
- OS-specific implementations (partial - needs completion)
- Command execution mocking
- System information gathering
- Rule auditing and application

## 🧪 **Testing Best Practices Implemented**

### Mocking Strategy
- **External Dependencies**: subprocess, file operations, system calls
- **Database Operations**: Temporary databases for isolation
- **Platform Detection**: Mock OS information and commands
- **Time-Sensitive Operations**: Fixed datetime values

### Test Organization
- **Descriptive Names**: Clear test method naming
- **Logical Grouping**: Test classes by component
- **Fixture Reuse**: Shared test data via pytest fixtures
- **Isolated Tests**: No test interdependencies

### Coverage Goals
- **Core Models**: 88% coverage achieved
- **Database Manager**: 41% coverage (critical paths tested)
- **Platform Factory**: 95% coverage
- **Target**: Expand to 70%+ coverage for production readiness

## 🔧 **Dependencies Installed**

```toml
[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-cov>=4.0.0", 
    "pytest-mock>=3.10.0",
    "psutil>=5.9.0"
]
```

## ⚠️ **Known Issues & Future Work**

### Tests Needing Completion
- **Platform Implementation Tests**: LinuxPlatform and WindowsPlatform constructor issues
- **Database Schema Tests**: Rollback point encryption testing
- **CLI Testing**: Command-line interface integration tests
- **Rule Loading Tests**: YAML rule parsing and validation

### Pydantic V2 Migration
- Update deprecated `@validator` to `@field_validator`
- Replace `json_encoders` with modern serialization
- Fix deprecated `datetime.utcnow()` usage

### Test Expansion Areas
- **SSH Server Integration**: Real SSH configuration testing
- **Error Handling**: Exception scenarios and edge cases
- **Performance Testing**: Rule execution timing benchmarks
- **Cross-Platform Testing**: Windows-specific functionality

## 📝 **Development Workflow**

### Adding New Tests
1. **Create test file**: `tests/test_<component>.py`
2. **Import fixtures**: Use `conftest.py` fixtures
3. **Follow patterns**: Match existing test structure
4. **Mock externals**: Use `pytest-mock` for dependencies
5. **Run tests**: Validate before committing

### Test-Driven Development
1. **Write failing test** for new feature
2. **Implement minimum** code to pass
3. **Refactor** while maintaining tests
4. **Update coverage** goals and documentation

### CI/CD Integration Ready
- **pytest configuration** in `pyproject.toml`
- **Coverage reporting** with HTML output
- **Structured test discovery** via naming conventions
- **Mock dependencies** for reliable automation

## 🎯 **Next Steps for Testing**

1. **Fix Platform Constructor Issues**: Update LinuxPlatform/WindowsPlatform tests
2. **Complete Database Tests**: Encryption, rollback scenarios
3. **Add CLI Integration Tests**: Command execution and output validation
4. **Expand Rule Testing**: YAML parsing, rule validation, execution workflows
5. **Performance Benchmarks**: Rule execution timing and resource usage

---

**The unit testing framework is now established and ready for expansion. Core functionality is validated, and the foundation supports comprehensive test development for all system components.**