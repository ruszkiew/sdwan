#! /usr/bin/env python3

###############################################################################

#  SDWAN CLI Tool

#  Version 4.5 - Last Updated: Ed Ruszkiewicz


###############################################################################

"""

TODO

Change a specific variable by device - ./sdway.py device --set_var 100.64.1.1 "/0/vpn-instance/ip/route/0.0.0.0/0/next-hop/vpn0_inet_next_hop_ip_addr/address":"205.203.91.130"
    download current variable list - put into hash
    grab CLI variable/value to change - update hash
    attache device to template with new payload

Attach device template by device - ./sdwan.py device --attach 100.64.1.1 <variable_file>
    need to figure out best we to grab variables -- .csv ?
    need to figure out best we for user to identify template to use
    should it move to the 'device' major command like detach ?

Fix upload reference ID
    Cisco does not have a solution for this
    braninstorming some auxilary scripts - not part of this script
    would like to retain object IDs

Add more error corrrection - see Cisco sample config

ISSUE

19.2 apears to not store a templateID in a device template file
Waiting to see what Sai from Cisco says - may be bug

"""


###############################################################################

# IMPORTS

import requests
import os
import sys
import json
import click
import tabulate
import re
import time
import csv
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # NOQA
from requests.auth import HTTPBasicAuth
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)       # NOQA
requests.packages.urllib3.disable_warnings()
from pprint import pprint

###############################################################################

# ENVIRONMENTAL VARIABLES

SDWAN_IP = os.environ.get("SDWAN_IP")
SDWAN_PORT = os.environ.get("SDWAN_PORT")
SDWAN_USERNAME = os.environ.get("SDWAN_USERNAME")
SDWAN_PASSWORD = os.environ.get("SDWAN_PASSWORD")
SDWAN_CFGDIR = os.environ.get("SDWAN_CFGDIR")
SDWAN_PROXY = os.environ.get("SDWAN_PROXY")

if SDWAN_IP is None or SDWAN_USERNAME is None or SDWAN_PASSWORD is None:
    print("CISCO SDWAN details must be set via environment ",
          "variables before running.")
    print("   export SDWAN_IP=64.103.37.21")
    print("   export SDWAN_PORT=443")
    print("   export SDWAN_USERNAME=devnetuser")
    print("   export SDWAN_PASSWORD=Cisco123!")
    print("   export SDWAN_CFGDIR=./cfg/")
    print("")
    exit("1")

if SDWAN_PROXY is not None:
    tmp = 'socks5://' + SDWAN_PROXY
    proxy = {
        'https': tmp
        }
else:
    proxy = {}
    SDWAN_PROXY = 'None'


###############################################################################

# REST API CLASS

class rest_api_lib:

    def __init__(self, vmanage_ip, vmanage_port, username, password):
        self.vmanage_ip = vmanage_ip
        self.vmanage_port = vmanage_port
        self.session = {}
        self.login(self.vmanage_ip, vmanage_port, username, password)

    def login(self, vmanage_ip, vmanage_port, username, password):

        base_url = 'https://%s:%s/' % (vmanage_ip, vmanage_port)

        login_action = '/j_security_check'

        login_data = {'j_username': username, 'j_password': password}

        login_url = base_url + login_action

        token_url = base_url + 'dataservice/client/token'

        sess = requests.session()

        login_response = sess.post(url=login_url,
                                   data=login_data,
                                   proxies=proxy,
                                   verify=False)

        if b'<html>' in login_response.content:
            print("Login Failed")
            sys.exit(0)

        login_token = sess.get(url=token_url,
                               proxies=proxy,
                               verify=False)

        if b'<html>' in login_token.content:
            print ("Login Token Failed")
            sys.exit(0)

        sess.headers['X-XSRF-TOKEN'] = login_token.content

        self.session[vmanage_ip] = sess

    def get_request(self, mount_point):

        url = "https://%s:%s/dataservice/%s" % (self.vmanage_ip, self.vmanage_port, mount_point)
        response = self.session[self.vmanage_ip].get(url,
                                                     proxies=proxy,
                                                     verify=False)
        data = response.content
        return data

    def post_request(self, mount_point, payload,
                     headers={'Content-Type': 'application/json'}):

        url = "https://%s:%s/dataservice/%s" % (self.vmanage_ip, self.vmanage_port, mount_point)
        payload = json.dumps(payload)
        response = self.session[self.vmanage_ip].post(url=url,
                                                      data=payload,
                                                      headers=headers,
                                                      proxies=proxy,
                                                      verify=False)
        try:
            data = response.json()
        except:
            data = response

        return data


###############################################################################


# CREATE OBJECT

sdwanp = rest_api_lib(SDWAN_IP, SDWAN_PORT, SDWAN_USERNAME, SDWAN_PASSWORD)

###############################################################################

# NESTED DICTIONARY VARIABLE FIND / PRINT


def var_find(dkey, dval, dret, d):
    for k, v in d.items():
        if isinstance(v, dict):
            if dkey in v.keys():
                if(v[dkey] == dval):
                    print('       var: ' + v[dret])
            var_find(dkey, dval, dret, v)
        elif isinstance(v, list):
            for i in v:
                if isinstance(i, dict):
                    var_find(dkey, dval, dret, i)
    return

# NESTED DICTIONARY LIST FIND / PRINT


def list_find(d):
    for k, v in d.items():
        if(re.match("(\w+)List", k) is None):
            if isinstance(v, dict):
                list_find(v)
            elif isinstance(v, list):
                for i in v:
                    if isinstance(i, dict):
                        list_find(i)
        else:
            if isinstance(v, list):
                for i in v:
                    m = re.match("(\w+)List", k)
                    ltype = m.group(1)
                    response = json.loads(sdwanp.get_request('template/policy/list/' +
                                                             ltype + '/' + i))
                    print('         list: ' + i + ' : ' + ltype +
                          " "*(10 - len(ltype)) + ': ' + response['name'])
            else:
                m = re.match("(\w+)List", k)
                ltype = m.group(1)
                response = json.loads(sdwanp.get_request('template/policy/list/' +
                                      ltype + '/' + v))
                print('         list: ' + v + ' : ' + ltype +
                      " "*(10 - len(ltype)) + ': ' + response['name'])
    return


# SEARCH AND REPLACE ID


def id_fix(oldid, newid, drc):
    pattern = re.compile(oldid)
    for dirpath, dirname, filename in os.walk(drc):
        for fname in filename:
            path = os.path.join(dirpath, fname)
            try:
                strg = open(path).read()
                if re.search(pattern, strg):
                    strg = strg.replace(oldid, newid)
                    f = open(path, 'w')
                    f.write(strg)
                    print('  Updated ID in file' + path)
                f.close()
            except:
                pass


###############################################################################

# PRINT ENVIRONMENT


@click.command()
# @click.option()
def env():
    """Print SDWAN Environment Values.

        Display the SDWAN Environment Values.

        Example command:

            ./sdwan.py env

    """

    print()
    print('*****************')
    print('SDWAN Environment')
    print('*****************')
    print()
    print('SDWAN_IP = ' + SDWAN_IP)
    print('SDWAN_USERNAME = ' + SDWAN_USERNAME)
    print('SDWAN_PASSWORD = ' + SDWAN_PASSWORD)
    print('SDWAN_CFGDIR = ' + SDWAN_CFGDIR)
    print('SDWAN_PROXY = ' + SDWAN_PROXY)
    print()
    print('*****************')
    print()

    return

###############################################################################


# SEND CERTIFICATE

@click.command()
def certificate():
    """Send Certificates to Controllers.

        Example command:

            ./sdwan.py certificate

    """

    print()

    payload = {}
    response = sdwanp.post_request("certificate/vedge/list?action=push", payload)

    print("***********************************")
    print("Sending Certificates to Controllers")
    print("    *  May take 2 Minutes *        ")
    print("***********************************")

    for i in range(34, 1, -1):
        time.sleep(3)
        print("*"*i)

    print()
    print(response)
    print()

    return


###############################################################################

# RAW REST GET


@click.command()
@click.option("--object", help="URL Object.")
def rest(object):
    """Execute raw REST GET request.

        Returns raw output in JSON format.

        Example command:

            ./sdwan.py rest --object <rest_object>

    """

    click.secho("Retrieving REST response.")
    response = json.loads(sdwanp.get_request(object))
    pprint(response)
    return


###############################################################################


# VMANAGE TASKS

@click.command()
@click.option("--clear", help="ProcessID.")
def tasks(clear):
    """Retrieve and/or Clear vManage Active Tasks.

        Returns vManage Process

        Example command:

            ./sdwan.py tasks

            ./sdwan.py tasks --clear processID

    """
    if clear:
        print()
        print("Clearing vManage Task -- " + clear)
        print()
        response = sdwanp.get_request('device/action/status/tasks/clean?processId=' +
                                      clear)
        print(response)
        return

    print()
    click.secho("Retrieving Active vManage Tasks.")
    response = json.loads(sdwanp.get_request('device/action/status/tasks'))
    print()
    items = response['runningTasks']
    headers = ["Task Name", "Process ID", "Action", "Status", "Start Time"]
    table = list()
    for item in items:
        tr = [item['name'], item['processId'], item['action'],
              item['status'], item['startTime']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
    print()
    return


###############################################################################

# DEVICE

@click.command()
@click.option("--attach", help="Attach Device Template")
@click.option("--config", help="Print Device CLI Configuration")
@click.option("--csv", help="Output Device Variables to CSV")
@click.option("--detach", help="Detach Device from Device Template")
@click.option("--download", help="Download Device CLI Configuration")
@click.option("--invalid", help="Make Device Certificate Invalid")
@click.option("--staging", help="Make Device Certificate Staging")
@click.option("--template", help="Display Device Template")
@click.option("--valid", help="Make Device Certificate Valid")
@click.option("--variable", help="Display Device Variable and Values")
def device(attach, config, csv, detach, download, staging, template, invalid, valid, variable):
    """Display, Download, and View CLI Config for Devices.

        Returns information about each device that is part of the fabric.

        Example command:

            ./sdwan.py device

            ./sdwan.py device --attach templateID --csv <csv_file>

            ./sdwan.py device --config deviceID

            ./sdwan.py device --csv deviceID | all

            ./sdwan.py device --detach deviceID

            ./sdwan.py device --download deviceID | all

            ./sdwan.py device --invalid deviceID

            ./sdwan.py device --staging deviceID

            ./sdwan.py device --template deviceID

            ./sdwan.py device --valid deviceID

            ./sdwan.py device --variable deviceID

    """

    if attach:
        print("Attempting to Attach Device Template...")
        print()

        # grab variables from specified device template
        payload = {
            "templateId": str(attach),
            "deviceIds":
                [
                    "1.1.1.1"
                ],
            "isEdited": "false",
            "isMasterEdited": "false"
        }
        response = sdwanp.post_request('template/device/config/input',
                                       payload)

        items = response['header']['columns']
        payload_var = []
        for item in items:
            payload_var.append(item['property'])

        # grab variables from csv - put into a dictionary for lookup
        csv_file = open(csv, "rb")
        csv_var = str(csv_file.readline(),'utf-8').split('","')
        csv_val = str(csv_file.readline(),'utf-8').split('","')
        csv_dict = {}
        i = 0
        for key in csv_var:
            if i >= len(csv_val):
                csv_val.extend([None])
            csv_dict[key.replace('"','').replace('\n','').replace(',','')] = csv_val[i].replace('"','').replace(',','')
            i = i + 1
        csv_file.close()

        # base payload
        payload = {
            "deviceTemplateList":[
            {
                "templateId":str(attach),
                "device":[
                {
                    "csv-status":"complete",
                    "csv-deviceId":str(csv_dict['csv-deviceId']),
                    "csv-deviceIP":str(csv_dict['csv-deviceIP']),
                    "csv-host-name":str(csv_dict['csv-host-name']),
                    "//system/host-name":str(csv_dict['//system/host-name']),
                    "//system/system-ip":str(csv_dict['//system/system-ip']),
                    "//system/site-id":str(csv_dict['//system/site-id']),
                    "csv-templateId":str(attach),
                    "selected":"true"
                }
                ],
                "isEdited":"false",
                "isMasterEdited":"false"
            }
            ]
        }

        pprint(payload)

        # response = sdwanp.post_request('template/device/config/attachfeature', payload)
        # print (response)

        return

    if config:
        response = sdwanp.get_request('device/config?deviceId=' +
                                      config)
        print()
        # print('!')
        # print("! Device ID: ", config)
        # print('!')
        # remove base64 header/trailer
        print(re.sub("'|b'", '', str(response)).replace('\\n', '\n'))
        return

    if csv:
        # get templateId of attached template to device
        response = json.loads(sdwanp.get_request('system/device/vedges'))
        items = response['data']
        if(csv != 'all'):
            for item in items:
                try:
                    deviceId = item['system-ip']
                    if deviceId == csv:
                        templateId = item['templateId']
                        hostName = item['host-name']
                        deviceModel = item['deviceModel']
                        uuid = item['uuid']
                except KeyError:
                    pass
            print()
            print("Printing CSV for " + deviceModel + ": " + hostName + " -- deviceID: " + deviceId)
            print("  Attached to Device Template: " + templateId)
            print()
            # grab variables and values
            payload = {"templateId": templateId, "deviceIds": [uuid],
                       "isEdited": "false", "isMasterEdited": "false"}
            response = sdwanp.post_request('template/device/config/input/',
                                           payload)
            objects = response['data'][0]
            properties = response['header']['columns']
            date_string = f'{datetime.now():%Y-%m-%d__%H:%M:%S%z}'
            csv_file = open(SDWAN_CFGDIR + "csv-variable_______" +
                            csv +
                            "_"*(32 - len(csv)) +
                            date_string + '.csv', "w")
            for var in properties:
                if var['property'] != 'csv-status':
                    print('"' + var['property'], end='",', file=csv_file)
                    print('"' + var['property'], end='",')
            print('', file=csv_file)
            print()
            for var in properties:
                if var['property'] != 'csv-status':
                    print('"' + objects[var['property']], end='",', file=csv_file)
                    print('"' + objects[var['property']], end='",')
            csv_file.close()
            print()
            print()
            print("Device ID:", csv, " Variables downloaded...")
            print()
        else:
            print()
            print("Downloading all Device Variables...")
            print()
            # get list of all device-templates and devices attached
            response = json.loads(sdwanp.get_request('template/device'))
            templs = response['data']
            # get list of devices attached to template
            for templ in templs:
                url = "template/device/config/attached/{0}".format(templ['templateId'])
                response = json.loads(sdwanp.get_request(url))
                devs = response['data']
                # calculate variables for each device
                for dev in devs:
                    print("  Device ID:", dev['deviceIP'], " Variables downloaded...")
                    payload = {"templateId": templ['templateId'], "deviceIds": [dev['uuid']],
                               "isEdited": "false", "isMasterEdited": "false"}
                    response = sdwanp.post_request('template/device/config/input/',
                                                   payload)
                    objects = response['data'][0]
                    properties = response['header']['columns']
                    date_string = f'{datetime.now():%Y-%m-%d__%H:%M:%S%z}'
                    csv_file = open(SDWAN_CFGDIR + "csv-variable_______" +
                                    dev['deviceIP'] +
                                    "_"*(32 - len(dev['deviceIP'])) +
                                    date_string + '.csv', "w")
                    for var in properties:
                        if var['property'] != 'csv-status':
                            print('"' + var['property'], end='",', file=csv_file)
                    print('', file=csv_file)
                    for var in properties:
                        if var['property'] != 'csv-status':
                            print('"' + objects[var['property']], end='",', file=csv_file)
                    csv_file.close()
            print()
        return

    if variable:
        # get information of device
        response = json.loads(sdwanp.get_request('system/device/vedges'))
        items = response['data']
        for item in items:
            try:
                deviceId = item['system-ip']
                if deviceId == variable:
                    templateId = item['templateId']
                    hostName = item['host-name']
                    deviceModel = item['deviceModel']
                    uuid = item['uuid']
            except KeyError:
                pass
        print()
        print("Variables for " + deviceModel + ": " + hostName + " -- deviceID: " + deviceId + "\n")
        print("  Attached to Device Template: " + templateId)
        print()
        # grab variables and values
        payload = {"templateId": templateId, "deviceIds": [uuid],
                   "isEdited": "false", "isMasterEdited": "false"}
        response = sdwanp.post_request('template/device/config/input/',
                                       payload)
        objects = response['data'][0]
        properties = response['header']['columns']
        headers = ["Object Path", "Device Value", "Variable Name"]
        table = list()
        for var in properties:
            if var['property'] != 'csv-status':
                tr = [var['property'], objects[var['property']], var['title']]
                table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="grid"))
        return

    if detach:

        response = json.loads(sdwanp.get_request('system/device/vedges?deviceIP=' + detach))
        items = response['data']

        for item in items:
            try:
                deviceIP = item['deviceIP']
                if deviceIP == detach:
                    hostName = item['host-name']
                    deviceModel = item['deviceModel']
                    uuid = item['uuid']
                    template = item['template']
                    templateId = item['templateId']
            except KeyError:
                print()
                print("** Device not Attached to a Template **")
                print()
                return

        print()
        print("Detach Device Template")
        print()
        print(" ** hostname -    ", hostName)
        print(" ** system-ip -   ", deviceIP)
        print(" ** chassis-id -  ", uuid)
        print(" ** template -    ", template)
        print(" ** template-id - ", templateId)
        print()
        print()
        
        payload = {
            "deviceType": "vedge",
            "devices": [
                {
                    "deviceId": uuid,
                    "deviceIP": deviceIP 
                }
            ]
        }

        response = sdwanp.post_request('template/config/device/mode/cli',
                                       payload)
        print(response)
        print()

        return

    if download:
        if(download == 'all'):
            response = json.loads(sdwanp.get_request('device'))
            items = response['data']
            print()
            print("Downloading all Device Configurations...")
            print()
            for item in items:
                date_string = f'{datetime.now():%Y-%m-%d__%H:%M:%S%z}'
                print("  Device ID:", item['deviceId'], "downloaded...")
                response = sdwanp.get_request('device/config?deviceId=' +
                                              item['deviceId'])
                json_file = open(SDWAN_CFGDIR + "cli-configuration__" +
                                 item['deviceId'] +
                                 "_"*(32 - len(item['deviceId'])) +
                                 date_string, "w")
                json_file.write(re.sub("'|b'", '', str(response)).replace('\\n', '\n'))
                json_file.close()
            print()
        else:
            date_string = f'{datetime.now():%Y-%m-%d__%H:%M:%S%z}'
            response = sdwanp.get_request('device/config?deviceId=' +
                                          download)
            print()
            print("Device ID:", download, "downloaded...")
            print()
            json_file = open(SDWAN_CFGDIR + "cli_configuration__" +
                             download +
                             "_"*(32 - len(download)) +
                             date_string, "w")
            json_file.write(re.sub("'|b'", '', str(response)).replace('\\n', '\n'))
            json_file.close()
        return

    if template:

        response = json.loads(sdwanp.get_request('system/device/vedges?deviceIP=' + template))
        items = response['data']

        for item in items:
            try:
                deviceIP = item['deviceIP']
                if deviceIP == template:
                    hostName = item['host-name']
                    deviceModel = item['deviceModel']
                    uuid = item['uuid']
                    serialNumber = item['serialNumber']
                    valid = item['validity']
                    template = item['template']
                    templateId = item['templateId']
            except KeyError:
                print()
                print("** Device not Attached to a Template **")
                print()
                return
        print()
        print("Device and Template Details")
        print()
        print(" ** hostname       ", hostName)
        print(" ** system-ip      ", deviceIP)
        print(" ** device-model   ", deviceModel)
        print(" ** certificate    ", valid)
        print(" ** chassis-id     ", uuid)
        print(" ** serial_num     ", serialNumber)
        print(" ** template       ", template)
        print(" ** template-id    ", templateId)
        print()
        print()
        
        return

    if valid:    

        response = json.loads(sdwanp.get_request('system/device/vedges?deviceIP=' + valid))
        items = response['data']

        for item in items:
            try:
                deviceIP = item['deviceIP']
                if deviceIP == valid:
                    hostName = item['host-name']
                    deviceModel = item['deviceModel']
                    uuid = item['uuid']
                    serialNumber = item['serialNumber']
                    valid = item['validity']
                    template = item['template']
                    templateId = item['templateId']
            except KeyError:
                print()
                print("** Device not Retrieved **")
                print()
                return

        payload = [{"chasisNumber" : uuid, "serialNumber" : serialNumber, "validity" : "valid"}]
        response = sdwanp.post_request('certificate/save/vedge/list', payload)

        print()
        print("Attempting to Validate Device Certificate")
        print()
        print(" ** hostname       ", hostName)
        print(" ** system-ip      ", deviceIP)
        print(" ** device-model   ", deviceModel)
        print(" ** chassis-id     ", uuid)
        print(" ** serial_num     ", serialNumber)
        print(" ** template       ", template)
        print(" ** template-id    ", templateId)
        print()
        print (response)
        print()

        return

    if invalid:

        response = json.loads(sdwanp.get_request('system/device/vedges?deviceIP=' + invalid))
        items = response['data']

        for item in items:
            try:
                deviceIP = item['deviceIP']
                if deviceIP == invalid:
                    hostName = item['host-name']
                    deviceModel = item['deviceModel']
                    uuid = item['uuid']
                    serialNumber = item['serialNumber']
                    valid = item['validity']
                    template = item['template']
                    templateId = item['templateId']
            except KeyError:
                print()
                print("** Device not Retrieved **")
                print()
                return

        payload = [{"chasisNumber" : uuid, "serialNumber" : serialNumber, "validity" : "invalid"}]
        response = sdwanp.post_request('certificate/save/vedge/list', payload)

        print()
        print("Attempting to Invalidate Device Certificate")
        print()
        print(" ** hostname       ", hostName)
        print(" ** system-ip      ", deviceIP)
        print(" ** device-model   ", deviceModel)
        print(" ** chassis-id     ", uuid)
        print(" ** serial_num     ", serialNumber)
        print(" ** template       ", template)
        print(" ** template-id    ", templateId)
        print()
        print (response)
        print()

        return

    if staging:

        response = json.loads(sdwanp.get_request('system/device/vedges?deviceIP=' + staging))
        items = response['data']

        for item in items:
            try:
                deviceIP = item['deviceIP']
                if deviceIP == staging:
                    hostName = item['host-name']
                    deviceModel = item['deviceModel']
                    uuid = item['uuid']
                    serialNumber = item['serialNumber']
                    valid = item['validity']
                    template = item['template']
                    templateId = item['templateId']
            except KeyError:
                print()
                print("** Device not Retrieved **")
                print()
                return

        payload = [{"chasisNumber" : uuid, "serialNumber" : serialNumber, "validity" : "staging"}]
        response = sdwanp.post_request('certificate/save/vedge/list', payload)

        print()
        print("Attempting to put Device Certificate in Staging")
        print()
        print(" ** hostname       ", hostName)
        print(" ** system-ip      ", deviceIP)
        print(" ** device-model   ", deviceModel)
        print(" ** chassis-id     ", uuid)
        print(" ** serial_num     ", serialNumber)
        print(" ** template       ", template)
        print(" ** template-id    ", templateId)
        print()
        print (response)
        print()

        return

    # no parameter passed in - list all
    click.secho("Retrieving Attached Devices.")

    response = json.loads(sdwanp.get_request('device'))
    items = response['data']
    headers = ["Device Name", "Device Type", "UUID", "System IP",
               "Device ID", "Site ID", "Version", "Device Model", "Cert"]
    table = list()
    for item in items:
        # check for site-id - 17.x vBond does not assign one
        if 'site-id' in item:
            tr = [item['host-name'], item['device-type'], item['uuid'],
                  item['system-ip'], item['deviceId'], item['site-id'],
                  item['version'], item['device-model'], item['validity']]
            table.append(tr)
        else:
            tr = [item['host-name'], item['device-type'], item['uuid'],
                  item['system-ip'], item['deviceId'], '',
                  item['version'], item['device-model'], item['validity']]
            table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))

    click.secho("Retrieving Unattached Devices.")
    response = json.loads(sdwanp.get_request('system/device/vedges'))
    items = response['data']
    headers = ["Chassis Number", "Operating Mode", "Model", "Serial Number",
               "Certificate"]
    table = list()
    for item in items:
        if item['configOperationMode'] == 'cli':
            tr = [item['chasisNumber'], item['configOperationMode'], item['deviceModel'],
                  item['serialNumber'], item['validity']]
            table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="grid"))
    return


###############################################################################

# DEVICE TEMPLATE

@click.command()
@click.option("--attached", help="Template to display attached devices")
@click.option("--config", help="Template to display")
@click.option("--csv", help="Template CSV Header")
@click.option("--download", help="Template to download")
@click.option("--upload", help="File to upload Template")
@click.option("--tree", help="List templates and variables referenced")
@click.option("--variable", help="List of variables required")
def template_device(attached, config, csv, download, upload, tree, variable):
    """Display, Download, and Upload Device Templates.

          List templates to derive templateID for additional actions

        Example command:

            ./sdwan.py template_device

            ./sdwan.py template_device --attached <templateID>

            ./sdwan.py template_device --config <templateID>

            ./sdwan.py template_device --csv <templateID>

            ./sdwan.py template_device --download <templateID> | all

            ./sdwan.py template_device --upload <file>

            ./sdwan.py template_device --tree <templateID>

            ./sdwan.py template_device --variable <templateID>

    """

    # print attached devices
    if attached:
        url = "template/device/config/attached/{0}".format(attached)
        response = json.loads(sdwanp.get_request(url))
        items = response['data']
        headers = ["Host Name", "Device IP", "Site ID", "Host ID", "Host Type"]
        table = list()
        for item in items:
            tr = [item['host-name'], item['deviceIP'], item['site-id'],
                  item['uuid'], item['personality']]
            table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="grid"))
        return

    # print specific template to stdout
    if config:
        response = sdwanp.get_request('template/device/object/' +
                                      config)
        # print()
        # print("Template ID: ", config)
        # print()
        # remove base64 header/trailer
        print(re.sub("'|b'", '', str(response)))
        print()
        return

    # download specific template or all templates
    if download:
        if(download == 'all'):
            response = json.loads(sdwanp.get_request('template/device'))
            items = response['data']
            print()
            print("Downloading all Device Templates...")
            print()
            for item in items:
                print("  Template ID:", item['templateId'], "downloaded...")
                response = sdwanp.get_request('template/device/object/' +
                                              item['templateId'])
                json_file = open(SDWAN_CFGDIR + "template-device____" +
                                 item['deviceType'] +
                                 "_"*(32 - len(item['deviceType'])) +
                                 item['templateId'] + '___' +
                                 item['templateName'].replace('/', '-'), "w")
                json_file.write(re.sub("'|b'", '', str(response)))
                json_file.close()
            print()
        else:
            response = sdwanp.get_request('template/device/object/' +
                                          download)
            item = json.loads(response)
            print()
            print(item['deviceType'])
            print(item['templateName'])
            print(download)
            print()
            print("Template ID:", download, "downloaded...")
            print()
            json_file = open(SDWAN_CFGDIR + "template-device____" +
                             item['deviceType'] +
                             "_"*(32 - len(item['deviceType'])) +
                             download + '___' +
                             item['templateName'].replace('/', '-'), "w")
            json_file.write(re.sub("'|b'", '', str(response)))
            json_file.close()
        return

    # upload a template from a file
    if upload:
        json_file = open(upload, "rb")
        payload = json.loads(json_file.read())
        print()
        print("Template File:", upload, "attempting upload...")
        print()
        response = sdwanp.post_request('template/device/feature',
                                       payload)
        print()
        print(response)
        print()
        '''
        # 19.2 Broke this as the TemplateId is not stored in JSON
        if 'templateId' in response:
            if(payload['templateId'] != response['templateId']):
                print('  ** The Template ID Changed **')
                print('      This may effect other Definitions, Policies, and Templates referencing it')
                print('      Object files in the ' + SDWAN_CFGDIR + " directory will be updated")
                print('      Template ID ' + payload['templateId'] + ' will be replaced with ' + response['templateId'])
                print()
                id_fix(payload['templateId'], response['templateId'], SDWAN_CFGDIR)
        json_file.close()
        print()
        '''
        print()
        return

    # display hiearchial tree of templates and variables
    if tree:
        print()
        # identify feature-templates attached
        response = json.loads(sdwanp.get_request('template/device/object/' +
                                                 tree))
        dev_temp = response
        print()
        print('  ****** Device Template ******')
        print('  ' + dev_temp['templateName'])
        print('  ' + tree)
        print()

        if 'generalTemplates' in dev_temp:
            gen_temp = response['generalTemplates']
            print('  *** Feature Template Tree ***')
            print('          +Variables       ')
            print()
            # identify first level templates
            for tmp in gen_temp:
                response = json.loads(sdwanp.get_request('template/feature/object/' +
                                                         tmp['templateId']))
                print('  tmpl: ' + response['templateId'] + ' ---------- ' + response['templateType'] + ' ' +
                      "-"*(25 - len(response['templateType'])) + ' ' + response['templateName'])
                # search for k,v pair of vipType,variableName and return value of vipVariableName
                var_find("vipType", "variableName", "vipVariableName", response['templateDefinition'])
                # identify second level templates
                if 'subTemplates' in tmp.keys():
                    sub_temp = tmp['subTemplates']
                    for sub in sub_temp:
                        response = json.loads(sdwanp.get_request('template/feature/object/' +
                                              sub['templateId']))
                        print('    tmpl: ' + response['templateId'] + ' -------- ' + response['templateType'] + ' ' +
                              "-"*(25 - len(response['templateType'])) + ' ' + response['templateName'])
                        # search for k,v pair of vipType,variableName and return value of vipVariableName
                        var_find("vipType", "variableName", "vipVariableName", response['templateDefinition'])
        else:
            print('    ** CLI Template - No Attached Feature Templates **')
        print()
        print()
        return

    if variable:
        payload = {
            "templateId": str(variable),
            "deviceIds":
                [
                    "1.1.1.1"
                ],
            "isEdited": "false",
            "isMasterEdited": "false"
        }
        response = sdwanp.post_request('template/device/config/input',
                                       payload)
        items = response['header']['columns']
        headers = ["Title(variable)", "Object Path"]
        table = list()
        for item in items:
            tr = [item['title'], item['property']]
            table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="grid"))
        return

    if csv:
        payload = {
            "templateId": str(csv),
            "deviceIds":
                [
                    "1.1.1.1"
                ],
            "isEdited": "false",
            "isMasterEdited": "false"
        }
        response = sdwanp.post_request('template/device/config/input',
                                       payload)
        items = response['header']['columns']
        print()
        for item in items:
            if item['property'] == 'csv-status':
                print()
            else:
                print('"', item['property'], '",', end='', sep='')
        print()
        print()
        return

    # no parameter passed in - list all templates
    response = json.loads(sdwanp.get_request('template/device'))
    items = response['data']

    headers = ["Template Name", "Device Type", "Template ID",
               "Attached Devices", "Feature Template Attached"]
    table = list()
    for item in items:
        tr = [item['templateName'], item['deviceType'], item['templateId'],
              item['devicesAttached'], item['templateAttached']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
    return


###############################################################################

# FEATURE TEMPLATE

@click.command()
@click.option("--attached", help="Template to display")
@click.option("--config", help="Template to display")
@click.option("--download", help="Template to download")
@click.option("--upload", help="File to Upload Template")
def template_feature(attached, config, download, upload):
    """Display, Download, and Upload Feature Templates.

          List templates to derive templateID for additional action

        Example command:

            ./sdwan.py template_feature

            ./sdwan.py template_feature --attached <templateID>

            ./sdwan.py template_feature --config <templateID>

            ./sdwan.py template_feature --download <templateID> | all

            ./sdwan.py template_feature --upload <file>


    """

    # print attached device templates
    if attached:
        url = "template/feature/devicetemplates/{0}".format(attached)
        response = json.loads(sdwanp.get_request(url))
        items = response['data']
        headers = ["Device Template Name", "Device Template ID"]
        table = list()
        for item in items:
            if 'templateId' in item:
                tr = [item['templateName'], item['templateId']]
            else:
                tr = [item['templateName'], 'Not Listed in 17.x Code']
            table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="grid"))
        return

    # print specific template to stdout
    if config:
        # response is of type bytes - convert to string
        response = sdwanp.get_request('template/feature/object/' +
                                      config)
        # print()
        # print("Template ID: ", config)
        # print()
        # remove base64 header/trailer
        print(re.sub("'|b'", '', str(response)))
        print()
        return

    # download specific template or all templates
    if download:
        if(download == 'all'):
            response = json.loads(sdwanp.get_request('template/feature'))
            items = response['data']
            print()
            print("Downloading all Feature Templates...")
            print()
            for item in items:
                if re.search(r'Factory_Default', item['templateName']) is None:
                    print("  Template ID:", item['templateId'], "downloaded...")
                    response = sdwanp.get_request('template/feature/object/' +
                                                  item['templateId'])
                    json_file = open(SDWAN_CFGDIR + "template-feature___" +
                                     item['templateType'] +
                                     "_"*(32 - len(item['templateType'])) +
                                     item['templateId'] + '___' +
                                     item['templateName'].replace('/', '-'), "w")
                    json_file.write(re.sub("'|b'", '', str(response)))
                    json_file.close()
            print()
        else:
            response = sdwanp.get_request('template/feature/object/' +
                                          download)
            item = json.loads(response)
            print()
            print(item['templateType'])
            print(item['templateName'])
            print(item['templateId'])
            print()
            print("Template ID:", download, "downloaded...")
            print()
            json_file = open(SDWAN_CFGDIR + "template-feature___" +
                             item['templateType'] +
                             "_"*(32 - len(item['templateType'])) +
                             item['templateId'] + '___' +
                             item['templateName'].replace('/', '-'), "w")
            json_file.write(re.sub("'|b'", '', str(response)))
            json_file.close()
        return

    # upload a template from a file
    if upload:
        json_file = open(upload, "rb")
        payload = json.loads(json_file.read())
        print()
        print("Template File:", upload, "attempting upload...")
        print()
        response = sdwanp.post_request('template/feature',
                                       payload)
        print()
        print(response)
        print()
        if 'templateId' in response:
            if(payload['templateId'] != response['templateId']):
                print('  ** The Template ID Changed **')
                print('      This may effect other Definitions, Policies, and Templates referencing it')
                print('      Object files in the ' + SDWAN_CFGDIR + " directory will be updated")
                print('      Template ID ' + payload['templateId'] + ' will be replaced with ' + response['templateId'])
                print()
                id_fix(payload['templateId'], response['templateId'], SDWAN_CFGDIR)
        json_file.close()
        print()
        print()
        return

    # no parameter passed in - list all templates
    response = json.loads(sdwanp.get_request('template/feature'))
    items = response['data']
    headers = ["Template Name", "Template Type", "Template ID",
               "Attached Devices", "Device Template Attached"]
    table = list()
    for item in items:
        tr = [item['templateName'], item['templateType'], item['templateId'],
              item['devicesAttached'], item['attachedMastersCount']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
    return


###############################################################################

# ATTACH TEMPLATE

@click.command()
@click.option("--template", help="TemplateID to deploy")
@click.option("--target", help="Hostname of target network device.")
def attach(template, target):
    """Attach a Device to a Device Template.

        Attach a Device to a Device Template.
          Provide all template parameters and their values as arguments.

        Example command:

          ./sdwan.py attach --template TemplateID --target deviceID

    """

    print("** Need to Code **")
    return


###############################################################################

# LISTS

@click.command()
@click.option("--ltype", help="Type of List")
@click.option("--config", help="Print List contents")
@click.option("--download", help="List to download")
@click.option("--upload", help="File to Upload List")
def policy_list(ltype, config, download, upload):
    """Display, Download, and Upload Policy Lists.

          List policy lists to derive listID or ltype for additional action

        Example command:

            ./sdwan.py policy-list

            ./sdwan.py policy-list --ltype

            ./sdwan.py policy-list --config <ListID>

            ./sdwan.py policy-list --download <ListID> | all

            ./sdwan.py policy-list --upload <file>

    """

    # print specific policy list to stdout
    if config:
        response = json.loads(sdwanp.get_request('template/policy/list'))
        items = response['data']
        for item in items:
            if(item['listId'] == config):
                ltype = item['type'].lower()
        response = sdwanp.get_request('template/policy/list/' +
                                      ltype + '/' + config)
        # print()
        # print("Template ID: ", config)
        # print()
        # remove base64 header/trailer
        print(re.sub("'|b'", '', str(response)))
        print()
        return

    # list specific list types
    if ltype:
        response = json.loads(sdwanp.get_request('template/policy/list/' +
                                                 ltype))
        items = response['data']
        headers = ["List Name", "List Type", "List ID", "Policies Attached"]
        table = list()
        for item in items:
            tr = [item['name'], item['type'], item['listId'],
                  item['referenceCount']]
            table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="grid"))
        return

    # download specific lists or all lists
    if download:
        if(download == 'all'):
            response = json.loads(sdwanp.get_request('template/policy/list'))
            items = response['data']
            print()
            print("Downloading all Policy Lists...")
            print()
            for item in items:
                print("  List ID:", item['listId'], "downloaded..."),
                response = sdwanp.get_request('template/policy/list/' +
                                              item['type'].lower() + '/' +
                                              item['listId'])
                json_file = open(SDWAN_CFGDIR + "policy-list________" +
                                 item['type'].lower() + "_"*(32 - len(item['type'])) +
                                 item['listId'] + '___' +
                                 item['name'].replace('/', '-'), "w")
                json_file.write(re.sub("'|b'", '', str(response)))
                json_file.close()
            print()
        else:
            response = json.loads(sdwanp.get_request('template/policy/list'))
            items = response['data']
            for item in items:
                if(item['listId'] == download):
                    ltype = item['type'].lower()
            response = sdwanp.get_request('template/policy/list/' +
                                          ltype + '/' + download)
            item = json.loads(response)
            print()
            print(item['type'])
            print(item['name'])
            print(item['listId'])
            print()
            print("Policy List ID:", download, "downloaded...")
            print()
            json_file = open(SDWAN_CFGDIR + "policy-list________" +
                             item['type'] + "_"*(32 - len(item['type'])) +
                             item['listId'] + '___' +
                             item['name'].replace('/', '-'), "w")
            json_file.write(re.sub("'|b'", '', str(response)))
            json_file.close()
        return

    # upload a list from a file
    if upload:
        json_file = open(upload, "rb")
        payload = json.loads(json_file.read())
        ltype = payload['type']
        print()
        print("Policy List File:", upload, "attempting upload...")
        print()
        response = sdwanp.post_request('template/policy/list/' + ltype,
                                       payload)
        print()
        print(response)
        print()
        if 'listId' in response:
            if(payload['listId'] != response['listId']):
                print('  ** The List ID Changed **')
                print('      This may effect other Definitions, Policies, and Templates referencing it')
                print('      Object files in the ' + SDWAN_CFGDIR + " directory will be updated")
                print('      List ID ' + payload['listId'] + ' will be replaced with ' + response['listId'])
                print()
                id_fix(payload['listId'], response['listId'], SDWAN_CFGDIR)
        json_file.close()
        print()
        print()
        return

    # no parameter passed in - list all templates
    response = json.loads(sdwanp.get_request('template/policy/list'))
    items = response['data']
    headers = ["List Name", "List Type", "List ID", "Policies Attached"]
    table = list()
    for item in items:
        tr = [item['name'], item['type'], item['listId'],
              item['referenceCount']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
    return


###############################################################################

# POLICY CENTRAL

@click.command()
@click.option("--config", help="Print Policy contents")
@click.option("--download", help="Policy to download")
@click.option("--upload", help="File to Upload Policy")
@click.option("--definition", help="Referenced Definitions")
@click.option("--tree", help="List definitions and lists referenced")
def policy_central(config, download, upload, definition, tree):
    """Display, Download, and Upload Centralized Policy.

          List Policy to derive PolicyID for additional action

        Example command:

            ./sdwan.py policy-central

            ./sdwan.py policy-central --config PolicyID

            ./sdwan.py policy-central --download PolicyID | all

            ./sdwan.py policy-central --upload <file>

            ./sdwan.py policy-central --definition PolicyID

            ./sdwan.py policy-central --tree PolicyID

    """
    # print specific policy to stdout
    if config:
        response = sdwanp.get_request('template/policy/vsmart/definition/' +
                                      config)
        # print()
        # print("Policy ID: ", config)
        # print()
        # remove base64 header/trailer
        print(re.sub("'|b'", '', str(response)))
        print()
        return

    # download specific policy or all policies
    if download:
        if(download == 'all'):
            response = json.loads(sdwanp.get_request('template/policy/vsmart'))
            items = response['data']
            print()
            print("Downloading all Central Policy...")
            print()
            for item in items:
                print("  Policy ID:", item['policyId'], "downloaded...")
                response = sdwanp.get_request('template/policy/vsmart/definition/' +
                                              item['policyId'])
                json_file = open(SDWAN_CFGDIR + "policy-central_____" +
                                 item['policyType'] +
                                 "_"*(32 - len(item['policyType'])) +
                                 item['policyId'] + '___' +
                                 item['policyName'].replace('/', '-'), "w")
                json_file.write(re.sub("'|b'", '', str(response)))
                json_file.close()
            print()
        else:
            response = sdwanp.get_request('template/policy/vsmart/definition/' +
                                          download)
            item = json.loads(response)
            print()
            print(item['policyType'])
            print(item['policyName'])
            print(download)
            print()
            print("Policy ID:", download, "downloaded...")
            print()
            json_file = open(SDWAN_CFGDIR + "policy-central_____" +
                             item['policyType'] +
                             "_"*(32 - len(item['policyType'])) +
                             download + '___' +
                             item['policyName'].replace('/', '-'), "w")
            json_file.write(re.sub("'|b'", '', str(response)))
            json_file.close()
        return

    # upload a policy from a file
    if upload:
        json_file = open(upload, "rb")
        payload = json.loads(json_file.read())
        print()
        print("Policy File:", upload, "attempting upload...")
        print()
        response = sdwanp.post_request('template/policy/vsmart',
                                       payload)
        print()
        print(response)
        print()
        json_file.close()
        return

    # display referenced definitions
    if definition:
        response = sdwanp.get_request('template/policy/vsmart/definition/' +
                                      definition)
        item = json.loads(response)
        print()
        print("Policy Name:", item['policyName'])
        print("Policy ID:", definition)
        print()
        print("--- Attached Definitions ---")
        print()
        defs = item['policyDefinition']['assembly']
        headers = ["Definition ID", "Definition Type"]
        table = list()
        for d in defs:
            tr = [d['definitionId'], d['type']]
            table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="grid"))
        return

    # display hiearchial tree of definitions and lists
    if tree:
        print()
        # identify referenced definitions
        response = json.loads(sdwanp.get_request('template/policy/vsmart/definition/' +
                                                 tree))
        print()
        print('  ****** Central Policy *******')
        print('  ' + response['policyName'])
        print('  ' + tree)
        print()
        print('  *** Definitions and Lists ***')
        print()
        # identify definitions
        defs = {}
        assembly = response['policyDefinition']
        for def1 in assembly['assembly']:
            defs[def1['definitionId']] = def1['type']
            response = json.loads(sdwanp.get_request('template/policy/definition/' +
                                  def1['type'].lower() + '/' + def1['definitionId']))
            print('  def: ' + response['definitionId'] + ' ---------- ' + response['type'] + ' ' +
                  "-"*(25 - len(response['type'])) + ' ' + response['name'])
            list_find(response)
        print()
        print()
        return

    # no parameter passed in - list all policies
    response = json.loads(sdwanp.get_request('template/policy/vsmart'))
    items = response['data']
    headers = ["Policy Name", "Policy ID", "Policy Activated"]
    table = list()
    for item in items:
        tr = [item['policyName'], item['policyId'], item['isPolicyActivated']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
    return


###############################################################################

# POLICY LOCAL

@click.command()
@click.option("--config", help="Print Policy Contents")
@click.option("--download", help="Policy to Download")
@click.option("--upload", help="File to Upload Policy")
@click.option("--definition", help="Referenced Definitions")
@click.option("--tree", help="List definitions and lists referenced")
def policy_local(config, download, upload, definition, tree):
    """Display, Download, and Upload Local Policy.

          List Policy to derive PolicyID for additional actio

        Example command:

            ./sdwan.py policy-local

            ./sdwan.py policy-local --config PolicyID

            ./sdwan.py policy-local --download PolicyID | all

            ./sdwan.py policy-local --upload <file>

            ./sdwan.py policy-local --definition PolicyID

            ./sdwan.py policy-local --tree PolicyID

    """

    # print specific policy to stdout
    if config:
        response = sdwanp.get_request('template/policy/vedge/definition/' +
                                      config)
        # print()
        # print("Policy ID: ", config)
        # print()
        # remove base64 header/trailer
        print(re.sub("'|b'", '', str(response)))
        print()
        return

    # download specific policy or all policies
    if download:
        if(download == 'all'):
            response = json.loads(sdwanp.get_request('template/policy/vedge'))
            items = response['data']
            print()
            print("Downloading all Local Policy...")
            print()
            for item in items:
                print("  Policy ID:", item['policyId'], "downloaded...")
                response = sdwanp.get_request('template/policy/vedge/definition/' +
                                              item['policyId'])
                item2 = json.loads(response)
                if 'policyName' in item2:
                    json_file = open(SDWAN_CFGDIR + "policy-local_______" +
                                     item['policyType'] +
                                     "_"*(32 - len(item['policyType'])) +
                                     item['policyId'] + '___' +
                                     item['policyName'].replace('/', '-'), "w")
                else:
                    json_file = open(SDWAN_CFGDIR + "policy-local_______" +
                                     'cli-policy' + "_"*(22) + item['policyId'] + '___No_Name', "w")
                json_file.write(re.sub("'|b'", '', str(response)))
                json_file.close()
            print()
        else:
            response = sdwanp.get_request('template/policy/vedge/definition/' +
                                          download)
            item = json.loads(response)
            print()
            if 'policyName' in item:
                print(item['policyType'])
                print(item['policyName'])
                print(download)
                json_file = open(SDWAN_CFGDIR + "policy-local_______" +
                                 item['policyType'] +
                                 "_"*(32 - len(item['policyType'])) +
                                 download + '___' +
                                 item['policyName'].replace('/', '-'), "w")
            else:
                print('CLI Policy')
                print(download)
                json_file = open(SDWAN_CFGDIR + "policy-local_______" +
                                 'cli-policy' + "_"*(22) + download + '___No_Name', "w")

            json_file.write(re.sub("'|b'", '', str(response)))
            json_file.close()

            print()
            print("Policy ID:", download, "downloaded...")
            print()

        return

    # upload a policy from a file
    if upload:
        json_file = open(upload, "rb")
        payload = json.loads(json_file.read())
        print()
        print("Policy File:", upload, "attempting upload...")
        print()
        response = sdwanp.post_request('template/policy/vedge',
                                       payload)
        print()
        print(response)
        print()

        # glean original policyId from file name
        m = re.search("^.*_(\w{8}\-\w{4}\-\w{4}\-\w{4}\-\w{12})_*(\w.*$)", upload)
        if m:
            lpid = m.group(1)
            lpname = m.group(2)
        # search for current Policy Id from local policy listing
        response = json.loads(sdwanp.get_request('template/policy/vedge'))
        items = response['data']
        # compare active ID and the one in the file
        for item in items:
            if item['policyName'] == lpname:
                print(item['policyName'])
                if(item['policyId'] != lpid):
                    print(item['policyId'])
                    print('  ** The Policy ID Changed **')
                    print('      This may effect other Definitions, Policies, and Templates referencing it')
                    print('      Object files in the ' + SDWAN_CFGDIR + " directory will be updated")
                    print('      Policy ID ' + lpid + ' will be replaced with ' + item['policyId'])
                    print()
                    id_fix(lpid, item['policyId'], SDWAN_CFGDIR)
        print()
        json_file.close()
        return

    # display referenced definitions
    if definition:
        response = sdwanp.get_request('template/policy/vedge/definition/' +
                                      definition)
        item = json.loads(response)
        if 'policyName' in item:
            print()
            print("Policy Name:", item['policyName'])
            print("Policy ID:", definition)
            print()
            print("--- Attached Definitions ---")
            print()
            defs = item['policyDefinition']['assembly']
            headers = ["Definition ID", "Definition Type"]
            table = list()
            for d in defs:
                tr = [d['definitionId'], d['type']]
                table.append(tr)
            try:
                click.echo(tabulate.tabulate(table, headers,
                                             tablefmt="fancy_grid"))
            except UnicodeEncodeError:
                click.echo(tabulate.tabulate(table, headers,
                                             tablefmt="grid"))
        else:
            print()
            print("Policy is CLI - No Definitions or Lists")
            print()
        return

    # display hiearchial tree of definitions and lists
    if tree:
        print()
        # identify referenced definitions
        response = sdwanp.get_request('template/policy/vedge/definition/' +
                                      tree)
        item = json.loads(response)
        if 'policyName' in item:
            print()
            print('  ******* Local Policy ********')
            print('  ' + item['policyName'])
            print('  ' + tree)
            print()
            print('  *** Definitions and Lists ***')
            print()
            # identify definitions
            defs = {}
            assembly = item['policyDefinition']
            for def1 in assembly['assembly']:
                defs[def1['definitionId']] = def1['type']
                response = json.loads(sdwanp.get_request('template/policy/definition/' +
                                      def1['type'].lower() + '/' + def1['definitionId']))
                print('  def: ' + response['definitionId'] + ' ---------- ' + response['type'] + ' ' +
                      "-"*(25 - len(response['type'])) + ' ' + response['name'])
                list_find(response)
            print()
            print()
        else:
            print()
            print("Policy is CLI - No Definitions or Lists")
            print()
        return

    # no parameter passed in - list all policies
    response = json.loads(sdwanp.get_request('template/policy/vedge'))
    items = response['data']
    headers = ["Policy Name", "Policy ID", "Templates Attached",
               "Devices Attached"]
    table = list()
    for item in items:
        tr = [item['policyName'], item['policyId'], item['mastersAttached'],
              item['devicesAttached']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
    return


###############################################################################

# POLICY DEFINITION

@click.command()
@click.option("--config", help="Print Definition Contents")
@click.option("--download", help="Definition to Download")
@click.option("--upload", help="File to Upload Definition")
def policy_definition(config, download, upload):
    """Display, Download, and Upload Policy Definitions.

          List Policy to derive PolicyID for additional actions

        Example command:

            ./sdwan.py policy-definition

            ./sdwan.py policy-definition --config DefinitionID

            ./sdwan.py policy-definition --download DefinitionID | all

            ./sdwan.py policy-definition --upload <file>

    """

    # load all definitions referenced in local and central policies
    # definitionId is key and type is value
    defs = {}
    response = json.loads(sdwanp.get_request('template/policy/vedge'))
    items = response['data']
    for item in items:
        # check to ensure it is not CLI definition - 17.x
        if 'assembly' in item['policyDefinition']:
            assembly = json.loads(item['policyDefinition'])
            for def1 in assembly['assembly']:
                defs[def1['definitionId']] = def1['type']

    response = json.loads(sdwanp.get_request('template/policy/vsmart'))
    items = response['data']
    for item in items:
        # check to ensure it is not CLI definition - 17.x
        if 'assembly' in item['policyDefinition']:
            assembly = json.loads(item['policyDefinition'])
            for def1 in assembly['assembly']:
                defs[def1['definitionId']] = def1['type']

    # print specific definition to stdout
    if config:
        response = sdwanp.get_request('template/policy/definition/' +
                                      defs[config].lower() + '/' + config)
        # print()
        # print("Definition ID: ", config)
        # print()
        # remove base64 header/trailer
        print(re.sub("'|b'", '', str(response)))
        print()
        return

    # download specific definition or all definitions
    if download:
        if(download == 'all'):
            print()
            print("Downloading all Policy Definitionss...")
            print()
            for def_id, def_type in defs.items():
                print("  Definition ID:", def_id, "downloaded..."),
                response = sdwanp.get_request('template/policy/definition/' +
                                              def_type.lower() + '/' + def_id)
                item = json.loads(response)
                json_file = open(SDWAN_CFGDIR + "policy-definition__" +
                                 item['type'] + "_"*(32 - len(item['type'])) +
                                 item['definitionId'] + '___' +
                                 item['name'].replace('/', '-'), "w")
                json_file.write(re.sub("'|b'", '', str(response)))
                json_file.close()
            print()
        else:
            response = sdwanp.get_request('template/policy/definition/' +
                                          defs[download].lower() + '/' + download)
            item = json.loads(response)
            print()
            print(item['type'])
            print(item['name'])
            print(item['definitionId'])
            print()
            print("Policy Definition ID:", download, "downloaded...")
            print()
            json_file = open(SDWAN_CFGDIR + "policy-definition__" +
                             item['type'] + "_"*(32 - len(item['type'])) +
                             item['definitionId'] + '___' +
                             item['name'].replace('/', '-'), "w")
            json_file.write(re.sub("'|b'", '', str(response)))
            json_file.close()
        return

    # upload a definition from a file
    if upload:
        json_file = open(upload, "rb")
        payload = json.loads(json_file.read())
        dtype = payload['type']
        print()
        print("Policy Definition File:", upload, "attempting upload...")
        print()
        response = sdwanp.post_request('template/policy/definition/' +
                                       dtype.lower(), payload)
        print()
        print(response)
        print()
        if 'definitionId' in response:
            if(payload['definitionId'] != response['definitionId']):
                print('  ** The Definition ID Changed **')
                print('      This may effect other Definitions, Policies, and Templates referencing it')
                print('      Object files in the ' + SDWAN_CFGDIR + " directory will be updated")
                print('      Definition ID ' + payload['definitionId'] + ' will be replaced with ' + response['definitionId'])
                print()
                id_fix(payload['definitionId'], response['definitionId'], SDWAN_CFGDIR)
        json_file.close()
        print()
        print()
        return

    # no parameter passed in - list all definitions and types
    headers = ["Definition Name", "Definition Type", "Definition ID"]
    table = list()
    for def_id, def_type in defs.items():
        response = json.loads(sdwanp.get_request('template/policy/definition/' +
                              defs[def_id].lower() + '/' + def_id))
        tr = [response['name'], response['type'], response['definitionId']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
    print()
    return

###############################################################################

# HELP


@click.group()
def cli():
    """CLI for managing policies and templates in Cisco SDWAN.
    """
    pass

###############################################################################


cli.add_command(env)
cli.add_command(rest)
cli.add_command(policy_list)
cli.add_command(policy_central)
cli.add_command(policy_local)
cli.add_command(policy_definition)
cli.add_command(device)
cli.add_command(certificate)
cli.add_command(tasks)
cli.add_command(template_device)
cli.add_command(template_feature)
cli.add_command(attach)


###############################################################################

# MAIN

if __name__ == "__main__":
    cli()
