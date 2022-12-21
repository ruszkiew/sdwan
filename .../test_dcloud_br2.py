#! /usr/bin/env python3

###################################################################################

#  Version 1.0 - Last Updated: Ed Ruszkiewicz

###################################################################################

"""

Automated Remote Site Test Script - Site Type 12 - Layer 2

USAGE: pytest --disable-warnings -v test_dcloud_br2.py --deviceId 100.100.4.1

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
    assert (re.search('up\s+mpls', response.output)),'No BFD Sessions on MPLS'
    assert (re.search('up\s+internet', response.output)),'No BFD Sessions on INET'

###################################################################################

def test_omp_route(deviceId):
    response = runner.invoke(device, ['--omp', deviceId, '0.0.0.0/0' ])
    assert response.exit_code == 0
    assert 'C I R' in response.output, 'No Default Route'

###################################################################################

def test_int_wan(deviceId):
    response = runner.invoke(device, ['--int', deviceId])
    assert response.exit_code == 0
    assert (re.search('ge0\/1.*if-state-up\s+if-oper-state-ready', response.output)),'MPLS WAN Interface is DOWN'
    assert (re.search('ge0\/1.*if-state-up\s+if-oper-state-ready\s+\d\d+', response.output)),'MPLS WAN Interface NO Traffic'
    assert (re.search('ge0\/0.*if-state-up\s+if-oper-state-ready', response.output)),'INET WAN Interface is DOWN'
    assert (re.search('ge0\/0.*if-state-up\s+if-oper-state-ready\s+\d\d+', response.output)),'INET WAN Interface NO Traffic'

###################################################################################

def test_int_lan(deviceId):
    response = runner.invoke(device, ['--int', deviceId])
    assert response.exit_code == 0
    assert (re.search('ge0\/2.*if-state-up\s+if-oper-state-ready', response.output)),'LAN Interface is DOWN'
    assert (re.search('ge0\/2.*if-state-up\s+if-oper-state-ready\s+\d\d+', response.output)),'LAN Interface NO Traffic'

###################################################################################

def test_ospf_lan(deviceId):
    response = runner.invoke(device, ['--ospf', deviceId])
    assert response.exit_code == 0
    assert 'full' in response.output, 'No OSPF Neighbors'

###################################################################################

def test_sla_stats(deviceId):
    response = runner.invoke(device, ['--sla', deviceId])
    assert response.exit_code == 0
    assert (re.search('\d,\d,\d\s+\d+\s+\d\d+\s+\d+', response.output)),'No BFD SLA Statistics'

##################################################################################
