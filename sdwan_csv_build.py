#! /usr/bin/env python3

###################################################################################

#  Version 1.0 - Last Updated: Ed Ruszkiewicz

###################################################################################

"""

SDWAN Variable Grabber

USAGE: sdwan_csv_build <device_template> <config>

EXAMPLE: sdwan_csv_build 44a926d9-3834-4d5a-8f30-f7b188964266 router.cfg


-- get list of variable from template
-- read variable/regex
-- iterate and create a variable/value hash - bouncing variable regex off of
-- print to csv - stdio and file


"""

###################################################################################

# IMPORTS

import re
from sdwan import template-device

###################################################################################

runner = CliRunner()

###################################################################################

def test_vmanage_control(deviceId):
    response = runner.invoke(device, ['--control', deviceId])
    assert response.exit_code == 0
    assert '100.127.1.1' in response.output, 'Control Connection Failed to vManage'

##################################################################################
