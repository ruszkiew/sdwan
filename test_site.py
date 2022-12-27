#! /usr/bin/env python3

###################################################################################

#  Version 1.0 - Last Updated: Ed Ruszkiewicz

###################################################################################

"""

Automated Remote Site Test Script

USAGE: pytest test_site.py --deviceId A.A.A.A

"""

###################################################################################

# IMPORTS

import pytest
import re
from click.testing import CliRunner
from sdwan import device

###################################################################################

@pytest.fixture(scope="session")

def deviceId(pytestconfig):
    return pytestconfig.getoption("deviceId")

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

def test_version(deviceId):
    response = runner.invoke(device, ['--detail', deviceId])
    assert response.exit_code == 0
    assert '17.03.02' in response.output, 'Not the desired Software Version'

###################################################################################

def test_template_sync(deviceId):
    response = runner.invoke(device, ['--detail', deviceId])
    assert response.exit_code == 0
    assert 'In Sync' in response.output, 'Router not in Sync with Device Template'

###################################################################################

def test_ntp(deviceId):
    response = runner.invoke(device, ['--ntp', deviceId])
    assert response.exit_code == 0
    assert 'SYNC_' in response.output, 'NTP is Unsynchronized'

###################################################################################

def test_sla_stats(deviceId):
    response = runner.invoke(device, ['--sla', deviceId])
    assert response.exit_code == 0
    assert (re.search('\d,\d,\d\s+\d+\s+\d\d+\s+\d+', response.output)),'No BFD SLA Statistics'

##################################################################################

def test_omp_learned_route(deviceId):
    response = runner.invoke(device, ['--omp', deviceId, 'summary' ])
    assert response.exit_code == 0
    assert '0.0.0.0/0' in response.output, 'No Default Route'
    assert '10.0.0.0/8' in response.output, 'No Summary Route'

##################################################################################

def test_vsmart(deviceId):
    response = runner.invoke(device, ['--vsmart', deviceId])
    assert response.exit_code == 0
    assert '-- data --' in response.output, 'No Traffic Data Definition Applied to Router'
    assert '-- control --' in response.output, 'No Topology Definition Applied to Router'
    assert '-- appRoute --' in response.output, 'No AAR Definition Applied to Router'
    assert 'AAR learned from-vsmart: YES' in response.output, 'No AAR Definition learned from vSmart'

##################################################################################

def test_ospf_lan(deviceId):
    response = runner.invoke(device, ['--ospf', deviceId])
    assert response.exit_code == 0
    assert (re.search('GigabitEthernet0\/0\/0.*full', response.output)),'No OSPF Neighbor LAN'

##################################################################################

def test_tracker(deviceId):
    response = runner.invoke(device, ['--tracker', deviceId])
    assert response.exit_code == 0
    assert 'tracker-if-state-up' in response.output, 'No Tracker or Tracker Down'

##################################################################################


'''

IDEAS

SaaS onRamp
Definition Hits

EXAMPLES

def test_intf_wan(deviceId):
    response = runner.invoke(device, ['--intf', deviceId])
    assert response.exit_code == 0
    assert (re.search('GigabitEthernet0\/1\/1.*if-state-up\s+if-oper-state-ready', response.output)),'MPLS WAN Interface is DOWN'
    assert (re.search('GigabitEthernet0\/1\/1.*if-state-up\s+if-oper-state-ready\s+\d\d+', response.output)),'MPLS WAN Interface NO Traffic'

def test_intf_lan(deviceId):
    response = runner.invoke(device, ['--intf', deviceId])
    assert response.exit_code == 0
    assert (re.search('GigabitEthernet0\/0\/0.*if-state-up\s+if-oper-state-ready', response.output)),'LAN Interface is DOWN'
    assert (re.search('GigabitEthernet0\/0\/0.*if-state-up\s+if-oper-state-ready\s+\d\d+', response.output)),'LAN Interface NO Traffic'

def test_vrrp_lan(deviceId):
    response = runner.invoke(device, ['--vrrp', deviceId])
    host = deviceId.split('.')[3]
    assert response.exit_code == 0
    if host == '1':
        assert (re.search('GigabitEthernet0\/0\/0\.100.*200\s+.*master.*\s+.*up', response.output)),'VLAN 100 VRRP Issue'
        assert (re.search('GigabitEthernet0\/0\/0\.200.*200\s+.*master.*\s+.*up', response.output)),'VLAN 200 VRRP Issue'
        assert (re.search('GigabitEthernet0\/0\/0\.900.*200\s+.*master.*\s+.*up', response.output)),'VLAN 900 VRRP Issue'
    elif host == '2':
        assert (re.search('GigabitEthernet0\/0\/0\.100.*100\s+.*backup.*\s+.*up', response.output)),'VLAN 100 VRRP Issue'
        assert (re.search('GigabitEthernet0\/0\/0\.200.*100\s+.*backup.*\s+.*up', response.output)),'VLAN 200 VRRP Issue'
        assert (re.search('GigabitEthernet0\/0\/0\.900.*100\s+.*backup.*\s+.*up', response.output)),'VLAN 900 VRRP Issue'
    else:
        assert False


'''
