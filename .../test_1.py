#! /usr/bin/env python3

###################################################################################

#  Version 1.0 - Last Updated: Ed Ruszkiewicz

###################################################################################

"""

Automated Remote Site Test Script - Site Type 11 - Layer 3

USAGE: pytest --disable-warnings -v test_1.py --deviceId 100.113.1.1

"""

###################################################################################

# IMPORTS

import pytest
import re
from click.testing import CliRunner
from sdwan import device

###################################################################################

runner = CliRunner()

###################################################################################

def test_vmanage_control(deviceId):
    response = runner.invoke(device, ['--control', deviceId])
    assert response.exit_code == 0
    assert '100.127.1.1' in response.output, 'Control Connection Failed to vManage'

###################################################################################

def test_vsmart_control(deviceId):
    response = runner.invoke(device, ['--control', deviceId])
    assert response.exit_code == 0
    assert '100.127.3.1' in response.output, 'Control Connection Failed to vSmart'
    assert '100.127.3.2' in response.output, 'Control Connection Failed to vSmart'

###################################################################################

def test_bfd(deviceId):
    response = runner.invoke(device, ['--bfd', deviceId])
    assert response.exit_code == 0
    assert (re.search('up\s+private', response.output)),'No BFD Sessions on MPLS'

###################################################################################

def test_sla_stats(deviceId):
    response = runner.invoke(device, ['--sla', deviceId])
    assert response.exit_code == 0
    assert (re.search('\d,\d,\d\s+\d+\s+\d\d+\s+\d+', response.output)),'No BFD SLA Statistics'

##################################################################################
