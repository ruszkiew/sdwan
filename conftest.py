import pytest

def pytest_addoption(parser):
    parser.addoption("--deviceId", action="store")

@pytest.fixture(scope='session')
def deviceId(request):
    deviceId_value = request.config.option.deviceId
    if deviceId_value is None:
        pytest.skip()
    return deviceId_value
