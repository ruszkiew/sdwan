#! /usr/bin/env python3

###############################################################################

#  SDWAN CLI Tool - Pytest

#  Version 1.0 - Last Updated: Ed Ruszkiewicz

###############################################################################

"""

NOTES

This is a CLI tool.  All tests will likely evaluate to STDOUT.
Do I want to match Environment specific values?  or Headers and Formatting ?

TODO
Write 2 tests per day

"""

###############################################################################

# IMPORTS

import pytest
from click.testing import CliRunner

# module functions for testing
from sdwan import certificate
from sdwan import device
    # attach, bfd, config, control, detach, download, set_var, csv, staging, template, invalid, valid, variable
from sdwan import env
from sdwan import policy_list
    # ltype, config, delete, download, update, upload
from sdwan import policy_central
    # config, download, upload, definition, tree
from sdwan import policy_definition
    # config, download, upload
from sdwan import policy_local
    # config, download, upload, definition, tree
from sdwan import rest
    # object
from sdwan import tasks
    # clear
from sdwan import template_device
    # attached, config, csv, download, upload, tree, variable
from sdwan import template_feature
    # attached, config, download, upload

###############################################################################

runner = CliRunner()

###############################################################################

def test_env():
    response = runner.invoke(env,[])
    assert response.exit_code == 0
    assert "SDWAN_USERNAME" in response.output

###############################################################################

def test_rest():
    response = runner.invoke(rest, ['--object', 'device'])
    assert response.exit_code == 0
    assert "data" in response.output

###############################################################################