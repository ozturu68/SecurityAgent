import pytest
import logging
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent. parent
sys.path.insert(0, str(project_root))

# Configure logging for tests
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

@pytest.fixture(scope='session')
def project_root_dir():
    """Return project root directory"""
    return project_root

@pytest.fixture
def mock_logger():
    """Provide mock logger for tests"""
    return logging.getLogger('test')

# Mark for integration tests
def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )