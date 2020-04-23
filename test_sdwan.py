#! /usr/bin/env python3

###############################################################################

#  SDWAN CLI Tool - Pytest

#  Version 1.0 - Last Updated: Ed Ruszkiewicz

###############################################################################

"""

NOTES

This is a CLI tool.  All tests will likely evaluate to STDOUT.

TODO

Get a basic test working
Make list of tests
Write 2 tests per day

"""

###############################################################################

# IMPORTS

import sdwan
import pytest

###############################################################################

def test_env(capfd):
    with pytest.raises(SystemExit):
        sdwan.env()
    stdout, err = capfd.readouterr()
    assert 'SDWAN_USERNAME' in stdout
