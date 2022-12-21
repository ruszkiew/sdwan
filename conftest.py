def pytest_addoption(parser):
    parser.addoption("--deviceId", action="store", default="100.127.3.1")
