#! /usr/bin/env python3

###################################################################################

#  Version 1.0 - Last Updated: Ed Ruszkiewicz

###################################################################################

"""

Automated Remote Site Test Script

USAGE: pytest --disable-warnings -v test_site.py --deviceId 100.65.1.1

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

def test_bfd_mpls(deviceId):
    response = runner.invoke(device, ['--bfd', deviceId])
    assert response.exit_code == 0
    assert (re.search('up\s+mpls', response.output)),'No BFD Sessions on MPLS'

###################################################################################

def test_omp_default(deviceId):
    response = runner.invoke(device, ['--omp', deviceId, 'summary' ])
    assert response.exit_code == 0
    assert '0.0.0.0/0' in response.output, 'No Default Route'

###################################################################################

def test_omp_summary(deviceId):
    response = runner.invoke(device, ['--omp', deviceId, 'summary' ])
    assert response.exit_code == 0
    assert '10.2.1.0/24' in response.output, 'No Summary Route'

###################################################################################

def test_omp_vsmart(deviceId):
    response = runner.invoke(device, ['--omp', '100.127.3.1', 'summary' ])
    assert response.exit_code == 0
    assert deviceId in response.output,'No OMP Route on vSmart' 
    assert (re.search(deviceId + '.*OSPF', response.output)),'No OSPF OMP Route on vSmart'

###################################################################################

def test_int_wan(deviceId):
    response = runner.invoke(device, ['--int', deviceId])
    assert response.exit_code == 0
    assert (re.search('ge0\/0.*Up\s+Up', response.output)),'WAN Interface is DOWN'
    assert (re.search('ge0\/0.*Up\s+Up\s+\d\d+', response.output)),'WAN Interface NO Traffic'

###################################################################################

def test_int_lan(deviceId):
    response = runner.invoke(device, ['--int', deviceId])
    assert response.exit_code == 0
    assert (re.search('ge0\/1.*Up\s+Up', response.output)),'LAN Interface is DOWN'
    assert (re.search('ge0\/1.*Up\s+Up\s+\d\d+', response.output)),'LAN Interface NO Traffic'

###################################################################################

def test_ospf_lan(deviceId):
    response = runner.invoke(device, ['--ospf', deviceId])
    assert response.exit_code == 0
    assert (re.search('ge0\/1.*full', response.output)),'No OSPF Neighbor LAN'

###################################################################################

def test_sla_stats(deviceId):
    response = runner.invoke(device, ['--sla', deviceId])
    assert response.exit_code == 0
    assert (re.search('\d,\d,\d\s+\d+\s+\d\d+\s+\d+', response.output)),'No BFD SLA Statistics'

##################################################################################