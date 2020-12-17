#! /usr/bin/env python3

###############################################################################

#  SDWAN CLI Tool

#  Version 5.5 - Last Updated: Ed Ruszkiewicz

###############################################################################

"""

TODO

- Token Auth

- Add Security Policy / Definition

- Add a 'Diff' function to Device Templates - Compare if migratoing to new platform
- Copy a Device Template to a new Model

- Add 'Update' function to lists - navigate the activate of policy/templates to devices
        need to reference if it is a CLI or UI template
        if you PUT to an attached item - you have 5 minutes to do the 'input' and 'attachment' follow up
        Need to figure out how to reference listID and parse/create the payload

- Investigate packet tracker functionality - similar to Silverpeak flow details

- Unit Testing - Started

- REST Error Correction

"""

###############################################################################

# IMPORTS

import requests
import os
import sys
import socket
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
from netmiko import ConnectHandler, SCPConn

###############################################################################

# ENVIRONMENTAL VARIABLES

SDWAN_IP = os.environ.get("SDWAN_IP")
SDWAN_PORT = os.environ.get("SDWAN_PORT")
SDWAN_USERNAME = os.environ.get("SDWAN_USERNAME")
SDWAN_PASSWORD = os.environ.get("SDWAN_PASSWORD")
SDWAN_CFGDIR = os.environ.get("SDWAN_CFGDIR")
SDWAN_PROXY = os.environ.get("SDWAN_PROXY")
SDWAN_SSH_CONFIG = './.ssh_config'

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

# NETMIKO SSH DEVICE

SSH_DEVICE = {
    'device_type': 'linux',
    'host': SDWAN_IP,
    'username': SDWAN_USERNAME,
    'password': SDWAN_PASSWORD,
    'ssh_config_file': SDWAN_SSH_CONFIG,
} 


###############################################################################

# REST API CLASS

class rest_api_lib:

    DEBUG = False

    def __init__(self, vmanage_ip, vmanage_port, username, password):
        self.vmanage_ip = vmanage_ip
        self.vmanage_port = vmanage_port
        self.session = {}
        self.login(self.vmanage_ip, vmanage_port, username, password)

    def login(self, vmanage_ip, vmanage_port, username, password):

        base_url = 'https://%s:%s/dataservice/' % (vmanage_ip, vmanage_port)

        login_action = 'j_security_check'

        login_data = {'j_username': username, 'j_password': password}

        login_url = base_url + login_action

        token_url = base_url + 'client/token'

        sess = requests.session()

        if self.DEBUG: print()
        if self.DEBUG: print("**************** LOGIN *************************")
        if self.DEBUG: print()
        if self.DEBUG: print(login_url)
        if self.DEBUG: print()
        if self.DEBUG: pprint(login_data)
        if self.DEBUG: print()

        login_response = sess.post(url=login_url,
                                   data=login_data,
                                   proxies=proxy,
                                   verify=False)


        if self.DEBUG: print()
        if self.DEBUG: print("**************** RESPONSE **********************")
        if self.DEBUG: print()
        if self.DEBUG: pprint(login_response)
        if self.DEBUG: print()

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

        if self.DEBUG: print()
        if self.DEBUG: print("**************** GET ***************************")
        if self.DEBUG: print()
        if self.DEBUG: print(url)
        if self.DEBUG: print()

        response = self.session[self.vmanage_ip].get(url,
                                                     proxies=proxy,
                                                     verify=False)

        if self.DEBUG: print()
        if self.DEBUG: print("**************** RESPONSE **********************")
        if self.DEBUG: print()
        if self.DEBUG: pprint(response)
        if self.DEBUG: print()
        if self.DEBUG: print("************************************************")
        if self.DEBUG: print()

        data = response.content

        return data

    def post_request(self, mount_point, payload,
                     headers={'Content-Type': 'application/json'}):


        url = "https://%s:%s/dataservice/%s" % (self.vmanage_ip, self.vmanage_port, mount_point)

        payload = json.dumps(payload)

        if self.DEBUG: print()
        if self.DEBUG: print("**************** POST **************************")
        if self.DEBUG: print()
        if self.DEBUG: print(url)
        if self.DEBUG: print()
        if self.DEBUG: pprint(payload)
        if self.DEBUG: print()

        response = self.session[self.vmanage_ip].post(url=url,
                                                      data=payload,
                                                      headers=headers,
                                                      proxies=proxy,
                                                      verify=False)

        if self.DEBUG: print()
        if self.DEBUG: print("**************** RESPONSE **********************")
        if self.DEBUG: print()
        if self.DEBUG: pprint(response)
        if self.DEBUG: print()
        if self.DEBUG: print("************************************************")
        if self.DEBUG: print()

        try:
            data = response.json()
        except:
            data = response

        return data

    def put_request(self, mount_point, payload,
                     headers={'Content-Type': 'application/json'}):

        url = "https://%s:%s/dataservice/%s" % (self.vmanage_ip, self.vmanage_port, mount_point)
        payload = json.dumps(payload)

        if self.DEBUG: print()
        if self.DEBUG: print("**************** PUT ***************************")
        if self.DEBUG: print()
        if self.DEBUG: print(url)
        if self.DEBUG: print()
        if self.DEBUG: pprint(payload)
        if self.DEBUG: print()

        response = self.session[self.vmanage_ip].put(url=url,
                                                      data=payload,
                                                      headers=headers,
                                                      proxies=proxy,
                                                      verify=False)

        if self.DEBUG: print()
        if self.DEBUG: print("**************** RESPONSE **********************")
        if self.DEBUG: print()
        if self.DEBUG: pprint(response)
        if self.DEBUG: print()
        if self.DEBUG: print("************************************************")
        if self.DEBUG: print()

        try:
            data = response.json()
        except:
            data = response

        return data

    def delete_request(self, mount_point,
                     headers={'Content-Type': 'application/json'}):

        url = "https://%s:%s/dataservice/%s" % (self.vmanage_ip, self.vmanage_port, mount_point)

        if self.DEBUG: print()
        if self.DEBUG: print("************ DELETE ************************")
        if self.DEBUG: print()
        if self.DEBUG: print(url)
        if self.DEBUG: print()

        response = self.session[self.vmanage_ip].delete(url=url,
                                                      headers=headers,
                                                      proxies=proxy,
                                                      verify=False)

        if self.DEBUG: print()
        if self.DEBUG: print("************ RESPONSE **********************")
        if self.DEBUG: print()
        if self.DEBUG: pprint(response)
        if self.DEBUG: print()
        if self.DEBUG: print("********************************************")
        if self.DEBUG: print()

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

        Example Command:

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

# BACKUP DATABASE FILE

@click.command()
@click.option("--backup", help="File Name to Backup")
def configuration_db(backup):
    """Create Database Backup File and Download.

        Returns Zipped Tarball Database File

        Example Command:

            ./sdwan.py configuration-db --backup <file_name>

    """

    print()

    # generate backup tarball
    print()
    print("***********************************")
    print("  Generating Database Tarball      ")
    print("    *  May take a minute ...       ")
    print("***********************************")
    print()
    ssh_command = 'request nms configuration-db backup path /home/' + SDWAN_USERNAME + '/' + backup
    net_connect = ConnectHandler(**SSH_DEVICE)
    ssh_output = net_connect.send_command(ssh_command)
    print(ssh_output)
    print()
    net_connect.disconnect()

    # scp backup file from vmanage
    print()
    print("***********************************")
    print("  Attempting to Download File      ")
    print("    *  May take a minute ...       ")
    print("***********************************")
    print()
    net_connect = ConnectHandler(**SSH_DEVICE)
    scp_connect = SCPConn(net_connect)
    src_file = '/home/' + SDWAN_USERNAME + '/' + backup + '.tar.gz'
    dst_file = SDWAN_CFGDIR + backup + '.tar.gz'
    scp_connect.scp_get_file(src_file, dst_file)
    scp_connect.close()
    net_connect.disconnect()
    if os.path.isfile(dst_file):
        print('** ', dst_file, 'Successfully Downloaded')
        print()
        print(os.system('ls -la ' + dst_file))
    else:
        print('** ', dst_file, 'ERROR - Downloaded Failed')
    
    print()

    return



###############################################################################

# SEND CERTIFICATE

@click.command()
def certificate():
    """Send Certificates to Controllers.

        Example Command:

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

        Example Command:

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

        Example Command:

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
@click.option("--arp", help="Display Device ARP Cache")
@click.option("--attach", help="Attach Device Template")
@click.option("--bfd", help="Display Device BFD Sessions")
@click.option("--bgp", help="Display Device BGP Information")
@click.option("--config", help="Print Device CLI Configuration")
@click.option("--control", help="Display Device Control Connections")
@click.option("--csv", help="Output Device Variables to CSV")
@click.option("--detach", help="Detach Device from Device Template")
@click.option("--download", help="Download Device CLI Configuration")
@click.option("--invalid", help="Make Device Certificate Invalid")
@click.option("--int", help="Display Interface Statistics and State")
@click.option("--omp", nargs=2, help="Display Device OMP Routes") 
@click.option("--ospf", help="Display Device OSPF Information") 
@click.option("--set_var", nargs=3, help="Set Variable/Value for Device")
@click.option("--staging", help="Make Device Certificate Staging")
@click.option("--sla", help="Display Tunnel BFD SLA Statistics")
@click.option("--template", help="Display Device Template")
@click.option("--valid", help="Make Device Certificate Valid")
@click.option("--variable", help="Display Device Variable and Values")
@click.option("--vrrp", help="Display Device VRRP Status")
@click.option("--wan", help="Display Device WAN Interface")
def device(arp, attach, bfd, bgp, config, control, detach, download, int, omp, ospf,
           set_var, csv, sla, staging, template, invalid, valid, variable, vrrp, wan):
    """Display, Download, and View CLI Config for Devices.

        Returns information about each device that is part of the fabric.

        Example Command:

            ./sdwan.py device

            ./sdwan.py device --arp deviceID

            ./sdwan.py device --attach templateID --csv <csv_file>

            ./sdwan.py device --bfd deviceID

            ./sdwan.py device --bgp deviceID

            ./sdwan.py device --config deviceID

            ./sdwan.py device --control deviceID

            ./sdwan.py device --csv deviceID | all

            ./sdwan.py device --detach deviceID

            ./sdwan.py device --download deviceID | all

            ./sdwan.py device --int deviceID

            ./sdwan.py device --invalid deviceID

            ./sdwan.py device --omp deviceID summary | <prefix>

            ./sdwan.py device --ospf deviceID summary | <prefix>

            ./sdwan.py device --set_var deviceID <object> <value>

            ./sdwan.py device --staging deviceID

            ./sdwan.py device --sla deviceID

            ./sdwan.py device --template deviceID

            ./sdwan.py device --valid deviceID

            ./sdwan.py device --variable deviceID

            ./sdwan.py device --vrrp deviceID

            ./sdwan.py device --wan deviceID

    """

    if arp:
        print()
        response = json.loads(sdwanp.get_request('device/arp?deviceId=' + arp))
        items = response['data']

        headers = ["VPN", "Protocol", "Address", "Hardware Addr",
                   "Type", "Interface"]
        table = list()
        for item in items:
            if 'address' in item:
                tr = [item['vpn-id'], 'Internet', item['address'],
                      item['hardware'], 'ARPA', item['interface']]
                table.append(tr)
            else:
                tr = [item['vpn-id'], 'Internet', item['ip'],
                      item['mac'], 'ARPA', item['if-name']]
                table.append(tr)

        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="simple"))

        print()
        return

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
        csv_file.close()

        csv_dict = {}
        i = 0
        for key in csv_var:
            #print(key)
            if i >= len(csv_val):
                csv_val.extend([None])
            csv_dict[key.replace('",','').replace('\n','').replace(',','').replace('"','')] = csv_val[i].replace('",','').replace('"','').replace('\n','')
            i = i + 1

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
                    "csv-templateId":str(attach),
                    "selected":"true"
                }
                ],
                "isEdited":"false",
                "isMasterEdited":"false"
            }
            ]
        }

        # run template variable list against csv list to check for missing values
        # populate the payload
        for k in payload_var:
            if k == 'csv-status':
                payload['deviceTemplateList'][0]['device'][0][k] = 'complete'
            else:
                payload['deviceTemplateList'][0]['device'][0][k] = csv_dict[k]

        pprint(payload)

        print()
        print(" ** hostname -    ", str(csv_dict['//system/host-name']))
        print(" ** system-ip -   ", str(csv_dict['csv-deviceIP']))
        print(" ** chassis-id -  ", str(csv_dict['csv-deviceId']))
        print(" ** template-id - ", attach)
        print()
        print()

        # attach template
        response = sdwanp.post_request('template/device/config/attachfeature', payload)
        print("Attachment Results...")
        print()
        print (response)
        print()

        return

    if bfd:
        response = json.loads(sdwanp.get_request('device/bfd/sessions?deviceId=' + bfd))
        items = response['data']

        print()

        headers = ["SYSTEM IP", "SITE ID", "STATE", "SRC TLOC COLOR",
                   "DST TLOC COLOR", "SRC IP", "DST IP", "DST PORT",
                   "ENCAP", "DETECT MULT", "TX INTERVAL", "UPTIME", "TRANSITIONS"]
        table = list()
        for item in items:
            tr = [item['system-ip'], item['site-id'], item['state'],
                  item['local-color'], item['color'], item['src-ip'], item['dst-ip'],
                  item['dst-port'], item['proto'], item['detect-multiplier'], item['tx-interval'],
                  item['uptime'], item['transitions']]
            table.append(tr)

        click.echo(tabulate.tabulate(table, headers, tablefmt="simple"))
        print()

        return

    if bgp:

        print()
        print('-------------')
        print('BGP NEIGHBORS')
        print('-------------')
        print()

        response = json.loads(sdwanp.get_request('device/bgp/neighbors?deviceId=' + bgp))
        items = response['data']

        headers = ["VPN", "NEIGHBOR", "AS", "STATE"]
        table = list()

        for item in items:
            tr = [item['vpn-id'], item['peer-addr'], item['as'],
                  item['state']]
            table.append(tr)

        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="simple"))

        print()

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

    if control:
        response = json.loads(sdwanp.get_request('device/control/connections?deviceId=' + control))
        items = response['data']

        print()

        headers = ["PEER TYPE", "PEER PROT", "PEER SYSTEM IP", "SITE ID",
                   "DOMAIN ID", "PEER PRIVATE IP", "PEER PRIV PORT", "PEER PUB IP",
                   "PEER PUB PORT", "LOCAL COLOR", "PROXY", "STATE", "UPTIME"]
        table = list()
        for item in items:
            tr = [item['peer-type'], item['protocol'], item['system-ip'],
                  item['site-id'], item['domain-id'], item['private-ip'], item['private-port'],
                  item['public-ip'], item['public-port'], item['local-color'], item['behind-proxy'],
                  item['state'], item['uptime']]
            table.append(tr)

        click.echo(tabulate.tabulate(table, headers, tablefmt="simple"))

        print()

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
            print('eol', file=csv_file)
            print('eol')
            print()
            for var in properties:
                if var['property'] != 'csv-status':
                    print('"' + objects[var['property']], end='",', file=csv_file)
                    print('"' + objects[var['property']], end='",')
            print('eol', file=csv_file)
            print('eol')
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
                    print('eol', file=csv_file)
                    print('', file=csv_file)
                    for var in properties:
                        if var['property'] != 'csv-status':
                            print('"' + objects[var['property']], end='",', file=csv_file)
                    print('eol', file=csv_file)
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

    if int:
        response = json.loads(sdwanp.get_request('device/interface?deviceId=' + int))
        items = response['data']

        print()

        headers = ["VPN", "INTERFACE", "MAC ADDR", "IP ADDR",
                   "ADMIN STATE", "OPER STATE", "RX KBPS", "TX KBPS",
                   "RX ERROR", "TX ERROR", "RX DROP", "TX DROP",
                   "RX PPS", "TX PPS"]
        table = list()
        for item in items:
            tr = [item['vpn-id'], item['ifname'], item['hwaddr'],
                  item['ip-address'], item['if-admin-status'], item['if-oper-status'],
                  item['rx-kbps'], item['tx-kbps'], item['rx-errors'],
                  item['tx-errors'], item['rx-drops'], item['tx-drops'], item['rx-pps'],
                  item['tx-pps']]
            table.append(tr)

        click.echo(tabulate.tabulate(table, headers, tablefmt="simple"))

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

    if omp:
        # get arguements
        deviceIP = omp[0]
        _prefix = omp[1]

        response = json.loads(sdwanp.get_request('device/omp/routes/received?deviceId=' + deviceIP))
        items = response['data']

        print()

        if _prefix == 'summary':

            print()
            print('Code:')
            print('C   -> chosen')
            print('I   -> installed')
            print('Red -> redistributed')
            print('Rej -> rejected')
            print('L   -> looped')
            print('R   -> resolved')
            print('S   -> stale')
            print('Ext -> extranet')
            print('Inv -> invalid')
            print('Stg -> staged')
            print('IA  -> On-demand inactive')
            print('U   -> TLOC unresolved')
            print()
            print()

            headers = ["VPN", "PREFIX", "FROM PEER", "PATH ID","LABEL",
                       "STATUS", "ATTRIBUTE TYPE", "TLOC IP", "SITE ID", "COLOR",
                       "ENCAP", "PROTOCOL"]
            table = list()
            for item in items:
                tr = [item['vpn-id'], item['prefix'], item['from-peer'],
                      item['path-id'], item['label'], item['status'], item['attribute-type'],
                      item['originator'], item['site-id'], item['color'], item['encap'],
                      item['protocol']]
                table.append(tr)

            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="simple"))
        else:
            vpn = 1000
            for item in items:
                if item['prefix'] == _prefix:
                    if item['vpn-id'] != vpn:
                        print('---------------------------------------------------')
                        print('omp route entries for vpn ' + item['vpn-id'] + ' route ' + item['prefix'])
                        print('---------------------------------------------------')
                        print()
                        vpn = item['vpn-id']
                    pprint(item)
                    print()

        print()

        return

    if ospf:

        print()
        print('--------------')
        print('OSPF INTERFACE')
        print('--------------')
        print()

        response = json.loads(sdwanp.get_request('device/ospf/interface?deviceId=' + ospf))
        items = response['data']

        headers = ["AREA", "INTERFACE", "COST", "PRIORITY",
                   "TYPE", "HELLO", "DR", "STATE"]
        table = list()

        for item in items:
            if 'area-addr' in item:
                tr = [item['area-addr'], item['if-name'], item['cost'],
                      item['priority'], item['if-type'], item['hello-timer'],
                      item['designated-router-id'], item['ospf-if-state']]
                table.append(tr)
            else:
                tr = [item['area-id'], item['name'], item['cost'],
                      item['priority'], item['network-type'], item['hello-interval'],
                      item['dr'], item['state']]
                table.append(tr)

        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="simple"))

        print()
        print('--------------')
        print('OSPF NEIGHBORS')
        print('--------------')
        print()

        response = json.loads(sdwanp.get_request('device/ospf/neighbor?deviceId=' + ospf))
        items = response['data']

        headers = ["AREA", "INTERFACE", "NEIGHBOR ID", "STATE"]
        table = list()

        for item in items:
            if 'area' in item:
                tr = [item['area'], item['if-name'], item['router-id'],
                      item['neighbor-state']]
                table.append(tr)
            else:
                if 'neighbor-id' in item:
                    tr = [item['area-id'], item['name'], item['neighbor-id'],
                          item['state']]
                    table.append(tr)

        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="simple"))

        print()

        return


    if set_var:
        # get arguements
        deviceIP = set_var[0]
        _object = set_var[1]
        _value = set_var[2]

        # find device template attached to
        response = json.loads(sdwanp.get_request('system/device/vedges?deviceId=' + deviceIP))
        try:
            templateId = response['data'][0]['templateId']
            uuid = response['data'][0]['uuid']
        except KeyError:
            print()
            print("** Device not Attached to a Template **")
            print()
            return 

        # grab variables from device based on device template
        payload = {"templateId": templateId, "deviceIds": [uuid],
                       "isEdited": "false", "isMasterEdited": "false"}

        response = sdwanp.post_request('template/device/config/input/',
                                       payload)

        objects = response['data'][0]

        print()
        print("Replacing Object : " + _object) 
        print("   Current Value : " + objects[_object]) 
        print("   New Value     : " + _value)
        print()
        print("On Device: " + objects['//system/host-name'] + " -- System IP: " + deviceIP)
        print()

        # change object/value
        objects[_object] = _value

        # attach device with new values

        payload = {
            "deviceTemplateList":[
            {
                "templateId":str(templateId),
                "device":[
                {
                # to be poplulated by objects dict
                }
                ],
                "isEdited":"false",
                "isMasterEdited":"false"
            }
            ]
        }
        payload['deviceTemplateList'][0]['device'][0] = objects
        payload['deviceTemplateList'][0]['device'][0]['csv-templateId'] = str(templateId)
        payload['deviceTemplateList'][0]['device'][0]['selected'] = 'true'

        # attach template
        response = sdwanp.post_request('template/device/config/attachfeature', payload)
        print("Attachment Results...")
        print()
        print (response)
        print()

        return

    if sla:

        print()

        response = json.loads(sdwanp.get_request('device/app-route/sla-class?deviceId=' + sla))
        items = response['data']

        headers = ["SLA", "NAME", "LOSS", "LATENCY", "JITTER"]

        table = list()

        for item in items:
            tr = [item['index'], item['name'], item['loss'], item['latency'],
                  item['jitter']]
            table.append(tr)

        click.echo(tabulate.tabulate(table, headers, tablefmt="simple"))

        print()
        print()

        response = json.loads(sdwanp.get_request('device/app-route/statistics?deviceId=' + sla))
        items = response['data']

        headers = ["LOCAL TLOC", "LOCAL IP", "PORT", "COLOR", "TX", "RX",
                   "COLOR", "PORT", "REMOTE IP", "REMOTE TLOC", "INPOLICY",
                   "LOSS", "LATENCY", "JITTER"]
        table = list()

        for item in items:
            tr = [item['vdevice-name'], item['src-ip'], item['src-port'], item['local-color'],
                  item['tx-data-pkts'], item['rx-data-pkts'], item['remote-color'], item['dst-port'],
                  item['dst-ip'], item['remote-system-ip'], item['sla-class-index'], item['loss'],
                  item['average-latency'], item['average-jitter']]
            table.append(tr)

        click.echo(tabulate.tabulate(table, headers, tablefmt="simple"))

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

    if vrrp:

        print()

        response = json.loads(sdwanp.get_request('device/vrrp?deviceId=' + vrrp))
        items = response['data']

        headers = ["IF NAME", "GROUP ID", "VIRTUAL IP", "VIRTUAL MAC","PRIORITY",
                   "VRRP STATE", "OMP STATE", "LAST STATE CHANGE TIME"]
        table = list()
        for item in items:
            tr = [item['if-name'], item['group-id'], item['virtual-ip'],
                  item['virtual-mac'], item['priority'], item['vrrp-state'], item['omp-state'],
                  item['last-state-change-time']]
            table.append(tr)

        click.echo(tabulate.tabulate(table, headers,
                                             tablefmt="simple"))

        print()

        return

    if wan:
        response = json.loads(sdwanp.get_request('device/control/synced/waninterface?deviceId=' + wan))
        items = response['data']

        print()

        headers = ["SYSTEM IP", "HOSTNAME", "INTERFACE", "COLOR","RESTRICT",
                   "PRIVATE IP", "PRIVATE PORT", "PUBLIC IP", "PUBLIC PORT",
                   "STATE", "VSMARTS", "VMANAGE", "TUNNEL PREF"]
        table = list()
        for item in items:
            tr = [item['vmanage-system-ip'], item['vdevice-host-name'], item['interface'],
                  item['color'], item['restrict-str'], item['private-ip'], item['private-port'],
                  item['public-ip'], item['public-port'], item['operation-state'], item['num-vsmarts'],
                  item['num-vmanages'], item['preference']]
            table.append(tr)

        click.echo(tabulate.tabulate(table, headers, tablefmt="simple"))

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

        Example Command:

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

        Example Command:

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
                # 'Default' in Template Name will not be downloaded
                if re.search(r'Default_', item['templateName']) is None:
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

# LISTS

@click.command()
@click.option("--ltype", help="Type of List")
@click.option("--config", help="Print List contents")
@click.option("--delete", help="List to delete")
@click.option("--download", help="List to download")
@click.option("--update", help="File to Update List")
@click.option("--upload", help="File to Upload List")
def policy_list(ltype, config, delete, download, update, upload):
    """Display, Download, and Upload Policy Lists.

          List policy lists to derive listID or ltype for additional action

        Example Command:

            ./sdwan.py policy-list

            ./sdwan.py policy-list --ltype

            ./sdwan.py policy-list --config <ListID>

            ./sdwan.py policy-list --delete <ListID>

            ./sdwan.py policy-list --download <ListID> | all

            ./sdwan.py policy-list --update <ListID>

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

        # remove base64 header/trailer
        print(re.sub("'|b'", '', str(response)))
        print()
        return

    # list specific list types
    if ltype:
        response = json.loads(sdwanp.get_request('template/policy/list/' +
                                                 ltype.lower()))
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

    # delete a list
    if delete:
        print()
        print("Attempting to Delete Policy List...")
        print()
        response = json.loads(sdwanp.get_request('template/policy/list'))
        items = response['data']
        i = 0
        for item in items:
            if(item['listId'] == delete):
                ltype = item['type'].lower()
                print("  listtype:"+ ltype + " -- name:" + item['name'])
                print()
                i = 1
                response = sdwanp.delete_request('template/policy/list/' +
                                                  ltype + '/' + delete)
                print(response)
        if i == 0:
            print("  List Object not Found")
        print()
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

    # update a list 
    if update:
        print()
        print("Policy List Update.  Need to Program")
        print()
        
        # get the existing list - identify references
        # how do we want to import new list content ?
        # create new payload with new content
        # put the new list
        # run an 'input' on devices currently attached
        # run an 'attach' on devices currently attached

        return

    # upload a list from a file
    if upload:
        json_file = open(upload, "rb")
        payload = json.loads(json_file.read())
        ltype = payload['type'].lower()
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

        Example Command:

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

        Example Command:

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

        Example Command:

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

@click.group()
def cli():
    """CLI for managing policies and templates in Cisco SDWAN.
    """
    pass

cli.add_command(configuration_db)
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


###############################################################################

# MAIN

def main():
    cli()

if __name__ == '__main__':
    main()
