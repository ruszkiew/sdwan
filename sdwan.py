#! /usr/bin/env python3

###############################################################################

#  SDWAN CLI Tool

#  Version 6.7 - Last Updated: Ed Ruszkiewicz

###############################################################################

"""
NTP status check
SDAVC status from router
Grab tracker state
Display flow table
Speedtest
Traceroute
Ping
Display centralized policy configured
NWP Trace


Add Tenant ENV_VAR - Enable Multi-tenant policy/templates

 - Use a post to see if tenant exists and get a vsession id
 - Add vsession id to session headers
 - should just work after that

class Rest:
    def __init__(self, base_url: str, username: str, password: str, proxy: str, tenant_name: Optional[str] = None,
                 timeout: int = 20, verify: bool = False):
        self.base_url = base_url
        self.timeout = timeout
        self.verify = verify
        self.session = None
        self.server_facts = None
        self.is_tenant_scope = False
        self.proxies = proxy

        ....

    def login(self, username: str, password: str, tenant_name: Optional[str]) -> bool:
        data = {
            'j_username': username,
            'j_password': password
        }
        session = requests.Session()
        response = session.post(f'{self.base_url}/j_security_check',
                                data=data, timeout=self.timeout, proxies=self.proxies, verify=self.verify)
        response.raise_for_status()

        # Multi-tenant vManage with a provider account, insert vsessionid
        if tenant_name is not None:
            if not self.is_multi_tenant or not self.is_provider:
                raise BadTenantException('Tenant is only applicable to provider accounts in multi-tenant deployments')

            tenant_list = self.get('tenant').get('data')
            if tenant_list is None:
                raise RestAPIException('Could not retrieve vManage tenant list')

            for tenant in tenant_list:
                if tenant_name == tenant['name']:
                    session_id = self.post({}, 'tenant', tenant['tenantId'], 'vsessionid').get('VSessionId')
                    self.session.headers['VSessionId'] = session_id
                    self.is_tenant_scope = True
                    break
            else:
                raise BadTenantException(f'Invalid tenant: {tenant_name}')

        return True

    def get(self, *path_entries: str, **params: Union[str, int]) -> Dict[str, Any]:
        response = self.session.get(self._url(*path_entries),
                                    params=params if params else None,
                                    timeout=self.timeout, proxies=self.proxies, verify=self.verify)
        raise_for_status(response)
        return response.json()

    @property
    def is_multi_tenant(self) -> bool:
        return self.server_facts.get('tenancyMode', '') == 'MultiTenant'



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
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # pylint: disable=import-error
from requests.auth import HTTPBasicAuth
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

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # pylint: disable=no-member
        requests.packages.urllib3.disable_warnings()                        # pylint: disable=no-member

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

        # validate a successful response
        if response.status_code == 200:
            data = response.content
            return data
        else:
            print()
            print('*** ERROR ***')
            print()
            pprint(response)
            print()
            pprint(json.loads(response.content))
            print()
            quit()
        
        return

    def post_request(self, mount_point, payload,
                     headers={'Content-Type': 'application/json'}):


        url = "https://%s:%s/dataservice/%s" % (self.vmanage_ip, self.vmanage_port, mount_point)

        payload = json.dumps(payload)

        if self.DEBUG: print()
        if self.DEBUG: print("**************** POST **************************")
        if self.DEBUG: print()
        if self.DEBUG: print(url)
        if self.DEBUG: print()
        if self.DEBUG: print(payload)
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
        # payload = json.dumps(payload, indent=1)
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

# DICTIONARY VARIABLE FIND / PRINT - USED IN TREE FUNCTIONS

def var_find(dkey, dval, dret, d):
    for k, v in d.items():                            # pylint: disable=unused-variable
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

# DICTIONARY LIST FIND / PRINT - USED IN TREE FUNCTIONS

def list_find(d,l):
    for k1, v1 in d.items():                         # pylint: disable=unused-variable
        if isinstance(v1,dict):
            list_find(v1,l)
        elif isinstance(v1,list):
            for i in v1:
                if isinstance(i,dict):
                    list_find(i,l)
        else:
            for k2, v2 in l.items():
                if k2 == v1:
                    print('         list: ' + v1 + ' : ' + v2['type'] +
                      " "*(10 - len(v2['type'])) + ': ' + v2['name'])
    return


# SEARCH AND REPLACE ID - USED IN UPLOAD FUNCTIONS

def id_fix(oldid, newid, drc):
    pattern = re.compile(oldid)
    for dirpath, dirname, filename in os.walk(drc):  # pylint: disable=unused-variable
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
    return

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
@click.option("--get", help="URL Object.")
def rest(get):
    """Execute raw REST GET request.

        Returns raw output in JSON format.

        Example Command:

            ./sdwan.py rest --get <rest_object>

    """

    click.secho("Retrieving REST response.")
    response = json.loads(sdwanp.get_request(get))
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

            ./sdwan.py tasks --clear <processId>

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
@click.option("--count_aar", help="Display AAR Policy Counters")
@click.option("--count_dp", help="Display Traffic Data Policy Counters")
@click.option("--csv", help="Output Device Variables to CSV")
@click.option("--detach", help="Detach Device from Device Template")
@click.option("--download", help="Download Device CLI Configuration")
@click.option("--events_hr", help="Display 1 Hour All Events")
@click.option("--events_crit", help="Display 7 Days Critical Events")
@click.option("--invalid", help="Make Device Certificate Invalid")
@click.option("--int", help="Display Interface Statistics and State")
@click.option("--models", is_flag=True, help="Display Valid Device Models")
@click.option("--ntp", help="Display Device NTP State") 
@click.option("--omp", nargs=2, help="Display Device OMP Routes") 
@click.option("--ospf", help="Display Device OSPF Information") 
@click.option("--saas", help="Display SaaS OnRamp State")
@click.option("--sdavc", help="Display SD-AVC Status")
@click.option("--set_var", nargs=3, help="Set Variable/Value for Device")
@click.option("--staging", help="Make Device Certificate Staging")
@click.option("--sla", help="Display Tunnel BFD SLA Statistics")
@click.option("--template", help="Display Device Template")
@click.option("--valid", help="Make Device Certificate Valid")
@click.option("--variable", help="Display Device Variable and Values")
@click.option("--vrrp", help="Display Device VRRP Status")
@click.option("--wan", help="Display Device WAN Interface")
def device(arp, attach, bfd, bgp, config, control, count_aar, count_dp, detach, download, events_hr, events_crit, int,
             models, ntp, omp, ospf, set_var, csv, saas,sdavc ,sla, staging, template, invalid, valid, variable, vrrp, wan):
    """Display, Download, and View CLI Config for Devices.

        Returns information about each device that is part of the fabric.

        Example Command:

            ./sdwan.py device

            ./sdwan.py device --arp <deviceId>

            ./sdwan.py device --attach <templateId> --csv <csv_file>

            ./sdwan.py device --bfd <deviceId>

            ./sdwan.py device --bgp <deviceId>

            ./sdwan.py device --config <deviceId>

            ./sdwan.py device --control <deviceId>

            ./sdwan.py device --count_aar <deviceId>

            ./sdwan.py device --count_dp <deviceId>

            ./sdwan.py device --csv <deviceId> | all

            ./sdwan.py device --detach <deviceId>

            ./sdwan.py device --download <deviceId> | all

            ./sdwan.py device --events_hr <deviceId>

            ./sdwan.py device --events_crit <deviceId>

            ./sdwan.py device --int <deviceId>

            ./sdwan.py device --invalid <deviceId>

            ./sdwan.py device --models

            ./sdwan.py device --ntp <deviceId>

            ./sdwan.py device --omp <deviceId> summary | <prefix>

            ./sdwan.py device --ospf <deviceId>

            ./sdwan.py device --saas <deviceId>

            ./sdwan.py device --sdavc <deviceId>

            ./sdwan.py device --set_var <deviceId> <object> <value>

            ./sdwan.py device --staging <deviceId>

            ./sdwan.py device --sla <deviceId>

            ./sdwan.py device --template <deviceId>

            ./sdwan.py device --valid <deviceId>

            ./sdwan.py device --variable <deviceId>

            ./sdwan.py device --vrrp <deviceId>

            ./sdwan.py device --wan <deviceId>

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

    if count_aar:
        print()
        response = json.loads(sdwanp.get_request('device/policy/approutepolicyfilter?deviceId=' + count_aar))
        items = response['data']

        headers = ["VPN", "Policy", "Counter", "Packets", "Bytes"]
        table = list()
        for item in items:
            tr = [item['vpn-name'], item['policy-name'], item['counter-name'],
                  item['packets'], item['bytes']]
            table.append(tr)

        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="simple"))

        print()
        return

    if count_dp:
        print()
        response = json.loads(sdwanp.get_request('device/policy/datapolicyfilter?deviceId=' + count_dp))
        items = response['data']

        headers = ["VPN", "Policy", "Counter", "Packets", "Bytes"]
        table = list()
        for item in items:
            tr = [item['vpn-name'], item['policy-name'], item['counter-name'],
                  item['packets'], item['bytes']]
            table.append(tr)

        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="simple"))

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

    if events_hr:
        print()
        print('Printing last 60 minutes of events : ', events_hr)
        print()

        payload = {
            "query": {
                "condition": "AND",
                "rules": [
                {
                    "field": "entry_time",
                    "operator": "last_n_hours",
                    "type": "date",
                    "value": ["1"]
                },
                {
                    "field": "system_ip",
                    "operator": "in",
                    "type": "string",
                    "value": [events_hr]
                }
                ]
            }
        }

        response = sdwanp.post_request('event', payload)
        items = response['data']
        for item in items:
            print(item['event'])
        print()
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
            # vedge carries af-type - match to prevent duplicate of lines
            if 'af-type' in item:
                if item['af-type'] == 'ipv4':
                    tr = [item['vpn-id'], item['ifname'], item['hwaddr'],
                          item['ip-address'], item['if-admin-status'], item['if-oper-status'],
                          item['rx-kbps'], item['tx-kbps'], item['rx-errors'],
                          item['tx-errors'], item['rx-drops'], item['tx-drops'], item['rx-pps'],
                          item['tx-pps']]
                    table.append(tr)
            else:
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

    if models:
        print()
        response = json.loads(sdwanp.get_request('device/models'))
        items = response['data']
        headers = ["Device Class", "Template Class", "Model Name", "Model Display Name"]
        table = list()
        for item in items:
            tr = [item['deviceClass'], item['templateClass'], item['name'],
                  item['displayName']]
            table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                         tablefmt="grid"))

        print()

        return

    if ntp:
        print()
        response = json.loads(sdwanp.get_request('device/ntp/status?deviceId=' + ntp))
        items = response['data']
        pprint(items)
        print()
        response = json.loads(sdwanp.get_request('device/ntp/associations?deviceId=' + ntp))
        items = response['data']
        pprint(items)
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

    if saas:
        print()
        response = json.loads(sdwanp.get_request('device/cloudx/applications?deviceId=' + saas))
        pprint(response)
        items = response['data']
        headers = ["Site ID", "Hostname", "System IP","Application", "Interface","VPN", "Color","Loss", "Latency","VQE Score", "VQE Status","Exit", "Gateway"]
        table = list()
        for item in items:
            tr = [item['site-id'], item['vdevice-host-name'], item['vdevice-name'], item['application'],
                  item['interface'], item['vpn-id'], item['local-color'], item['loss'], item['latency'],
                  item['vqe-score'], item['vqe-status'], item['exit-type'], item['gateway-system-ip']]
            table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
        print()
        return

    if sdavc:
        print()
        print('Working on SD-AVC Status Call')
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
                   "COLOR", "PORT", "REMOTE IP", "REMOTE TLOC", "IN POLICY",
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
        print()

        response = json.loads(sdwanp.get_request('device/control/synced/waninterface?deviceId=' + wan))
        items = response['data']

        wan_ints = []
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
            wan_ints.append(item['interface'])

        click.echo(tabulate.tabulate(table, headers, tablefmt="simple"))

        # determine license watermark - 95 percentile
        # will be moved to an 'audit' function once cisco confirms measurements
        # collect wan interface statistics - 720 hours - 30 minute averages
        payload = {
            "query": {
                "condition": "AND",
                "rules": [
                {
                    "value": [
                        "720"
                    ],
                    "field": "entry_time",
                    "type": "date",
                    "operator": "last_n_hours"
                },
                {
                    "value": [
                        str(wan)
                    ],
                    "field": "vdevice_name",
                    "type": "string",
                    "operator": "in"
                },
                {
                    "value": wan_ints,
                    "field": "interface",
                    "type": "string",
                    "operator": "in"
                }
                ]
            },
            "sort": [
            {
               "field": "entry_time",
               "type": "date",
               "order": "asc"
            }
            ],
            "aggregation": {
                "field": [
                {
                    "property": "interface",
                    "sequence": 1
                }
                ],
               "histogram": {
                    "property": "entry_time",
                    "type": "minute",
                    "interval": 30,
                    "order": "asc"
                },
                "metrics": [
                {
                    "property": "rx_kbps",
                    "type": "avg"
                },
                {
                    "property": "tx_kbps",
                    "type": "avg"
                }
                ]
            }
        }

        # retrieve wan interface rx and tx statistics
        response = sdwanp.post_request('statistics/interface/aggregation', payload)
        items = response['data']

        # aggregate rx and tx of all wan interfaces to single hash
        agg_data = {}
        for item in items:
            if item['entry_time'] not in agg_data:
                agg_data[item['entry_time']] = {}
                agg_data[item['entry_time']]['rx_kbps'] = 0
                agg_data[item['entry_time']]['tx_kbps'] = 0
            agg_data[item['entry_time']]['rx_kbps'] = agg_data[item['entry_time']]['rx_kbps'] + round(item['rx_kbps'])
            agg_data[item['entry_time']]['tx_kbps'] = agg_data[item['entry_time']]['tx_kbps'] + round(item['tx_kbps'])

        # identify for each time slice which rx or tx is higher - put higher in a dict
        # cisco measures on larger of ingress/egress
        bw_list = []
        for k in agg_data.keys():
            if agg_data[k]['rx_kbps'] > agg_data[k]['tx_kbps']:
                bw_list.append(agg_data[k]['rx_kbps'])
            else:
                bw_list.append(agg_data[k]['tx_kbps'])
        # sort list - lowest to highest
        bw_list.sort()
        # choose the time slice below the 95% of highest - return as bandwidth aggregate for device licensing
        bw_index = round(.95 * len(bw_list))

        print()
        print('Bandwidth License Watermark: ' + str(bw_list[bw_index]) + 'kbps')
        print(' License level is based on 95 percentile with 30 minute time slice averages')
        print(' Duration of measurement is 30 days')
        print(' Aggregation of all WAN Interfaces')
        print(' Higher of RX or TX used per WAN Interface per time slice')
        print()

        return

    # no parameter passed in - list all
    click.secho("Retrieving Attached Devices.")

    response = json.loads(sdwanp.get_request('device'))
    items = response['data']
    # pprint(items)
    headers = ["Device Name", "Device Type", "UUID", "System IP",
               "Device ID", "Site ID", "Version", "Device Model", "Cert"]
    table = list()
    for item in items:
        # check for site-id - 17.x vBond does not assign one
        if 'site-id' in item:
            tr = [item['host-name'], item['device-type'], item['uuid'],
                  item['local-system-ip'], item['deviceId'], item['site-id'],
                  item['version'], item['device-model'], item['validity']]
            table.append(tr)
        else:
            tr = [item['host-name'], item['device-type'], item['uuid'],
                  item['local-system-ip'], item['deviceId'], '',
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
@click.option("--clone", nargs=2, help="Clone Template to same or different Model")
@click.option("--config", help="Template to display")
@click.option("--csv", help="Template CSV Header")
@click.option("--download", help="Template to download")
@click.option("--upload", help="File to upload Template")
@click.option("--tree", help="List templates and variables referenced")
@click.option("--variable", help="List of variables required")
def template_device(attached, clone, config, csv, download, upload, tree, variable):
    """Display, Download, and Upload Device Templates.

          List templates to derive templateID for additional actions

        Example Command:

            ./sdwan.py template_device

            ./sdwan.py template_device --attached <templateId>

            ./sdwan.py template_device --clone <templateId> <model>

            ./sdwan.py template_device --config <templateId>

            ./sdwan.py template_device --csv <templateId>

            ./sdwan.py template_device --download <templateId> | all

            ./sdwan.py template_device --upload <file>

            ./sdwan.py template_device --tree <templateId>

            ./sdwan.py template_device --variable <templateId>

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

    # clone device template
    if clone:
        # get arguements
        templateId = clone[0]
        dst_model = clone[1]

        print()
        
        # grab source template model and class
        response = json.loads(sdwanp.get_request('template/device/object/' +
                                      templateId))
        src_class = response['templateClass']
        src_model = response['deviceType']

        # validate dst model and class is valid to device template
        response = json.loads(sdwanp.get_request('device/models'))
        items = response['data']
        i = 0
        for item in items:
            if dst_model == item['name']:
                if item['templateClass'] == src_class:
                   print('** Device Model is Validated')
                   print()
                   i = 1
                else:
                   print('** Device Model is wrong Temmplate Class')
                   print()
                   return
        if i == 0:
            print('** Device Model not Valid')
            print()
            return

        # validate dst model exists in feature templates attached to device template
        print('Validating Feature Templates support the new Model...')
        print()
        response = json.loads(sdwanp.get_request('template/device/object/' +
                                      templateId))
        if 'generalTemplates' in response:
            gen_temp = response['generalTemplates']
            # identify first level templates
            flag=0
            for tmp in gen_temp:
                response = json.loads(sdwanp.get_request('template/feature/object/' +
                                      tmp['templateId']))
                device_models=response['deviceType']
                if dst_model in response['deviceType']:
                    print(' Feature Tempalte: ' + response['templateName'] + ' -- ' +  response['templateId'] + ' -- SUCCESS')
                else:
                    print(' Feature Tempalte: ' + response['templateName'] + ' -- ' +  response['templateId'] + ' -- FAILED')
                    flag=1
                # identify second level templates
                if 'subTemplates' in tmp.keys():
                    sub_temp = tmp['subTemplates']
                    for sub in sub_temp:
                        response = json.loads(sdwanp.get_request('template/feature/object/' +
                                              sub['templateId']))
                        device_models=response['deviceType']
                        if dst_model in response['deviceType']:
                            print(' Feature Tempalte: ' + response['templateName'] + ' -- ' +  response['templateId'] + ' -- SUCCESS')
                        else:
                            print(' Feature Tempalte: ' + response['templateName'] + ' -- ' +  response['templateId'] + ' -- FAILED')
                            flag=1
            print()
            if flag == 1:
                print('** Feature Templates do NOT support the Model of the Clone Device Template')
                print()
                print('Device Template Clone NOT created')
                print()
                return
            else:
                print('** Feature Templates ALL support the Model of the Clone Device Template')
                print()
        else:
            print('    ** CLI Template - No Attached Feature Templates **')
        print()

        # download source template
        response = json.loads(sdwanp.get_request('template/device/object/' +
                                      templateId))

        # update names, id, type
        new_template = response
        new_template['templateName'] = ('Clone_' + response['templateName'])
        new_template['templateId'] = '10101010-1010-1010-1010-101010101010'
        new_template['deviceType'] = dst_model

        # push new template
        print('Attempting to upload new Template: ' + new_template['templateName'])
        print()
        response = sdwanp.post_request('template/device/feature',
                                    new_template)
        pprint(response)
        print()
        print('Please update Template Name and Description in vManage')
        print()
        # put - update new template with new description (cleanup)
        new_template['templateId'] = response['templateId']
        new_template['templateDescription'] = ('CLONE - ' + new_template['templateDescription'])
        response = sdwanp.put_request('template/device/' + new_template['templateId'],
                            new_template)

        # download new template
        response = json.loads(sdwanp.get_request('template/device/object/' +
                                      new_template['templateId']))
        print('Template Name: ' + response['templateName'])
        print('Template Description: ' + response['templateDescription'])
        print('Template ID: ' + response['templateId'])
        print()
        print('** Clone Completed')
        print()
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
            if 'policyId' in dev_temp:
                local_policy = response['policyId']
            else:
                local_policy = False
            if 'securityPolicyId' in dev_temp:
                security_policy = response['securityPolicyId']
            else:
                security_policy = False
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
            print()
            if local_policy:
                response = json.loads(sdwanp.get_request('template/policy/vedge/definition/' + local_policy))
                print(' local policy: ' + local_policy + ' ------------------------------ ' + response['policyName'])
            if security_policy:
                response = json.loads(sdwanp.get_request('template/policy/security/definition/' + security_policy))
                print(' security policy: ' + security_policy + ' --------------------------- ' + response['policyName'])
            print()
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
@click.option("--clone", nargs=2, help="Clone Template to same or different Models")
@click.option("--config", help="Template to display")
@click.option("--download", help="Template to download")
@click.option("--models", help="Device Models Eanbled for Template")
@click.option("--model_update", nargs=2, help="Update Models Eanbled for Template")
@click.option("--upload", help="File to Upload Template")
def template_feature(attached, clone, config, download, models, model_update, upload):
    """Display, Download, and Upload Feature Templates.

          List templates to derive templateID for additional action

        Example Command:

            ./sdwan.py template_feature

            ./sdwan.py template_feature --attached <templateId>

            ./sdwan.py template_feature --clone <templateId> <list_of_models>

            ./sdwan.py template_feature --config <templateId>

            ./sdwan.py template_feature --download <templateId> | all

            ./sdwan.py template_feature --models <templateId>

            ./sdwan.py template_feature --model_update <templateId> <list_of_models>

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


    if clone:
        deviceId = clone[0]
        models = list(clone[1].split(","))

        # download feature template to get template class
        response = json.loads(sdwanp.get_request('template/feature/object/' +
                                      deviceId))

        #template_class = response['gTemplateClass']

        print()
        print('Cloning Feature Template: ' + deviceId)
        print('  with device model list: ' + clone[1])
        print()

        # validate models in list
        # grab all sdwan supported models

        #
        response = json.loads(sdwanp.get_request('device/models'))
        items = response['data']
        valid_models = []
        for item in items:
            if item['templateClass'] == template_class:
                valid_models.append(item['name'])

        # check to ensure all input models are in the supported model list
        iflag = 0
        if (set(models).issubset(set(valid_models))):
            flag = 1
        if flag:
            print('** Input model list is Validated')
            print()
        else :
            print('ERROR - Input model list is not Supported')
            print()
            return

        # download feature template
        response = sdwanp.get_request('template/feature/object/' +
                                      deviceId)
        new_template = json.loads(response)

        # swap content of feature tempate
        new_template['templateName'] = ('Clone_' + new_template['templateName'])
        new_template['templateDescription'] = ('CLONE - ' + new_template['templateDescription'])
        new_template['deviceType'] = models

        # upload new feature template
        print('Please update Template Name and Description in vManage')
        print()
        print("Template File:", new_template['templateName'], "Attempting upload...")
        print()
        response = sdwanp.post_request('template/feature/',
                                       new_template)
        print('Template Name: ' + new_template['templateName'])
        print('Template Description: ' + new_template['templateDescription'])
        print('Template ID: ' + response['templateId'])
        print()
        print(response)
        print()
        print('** Clone Completed')
        print()

        return


    # print specific template to stdout
    if config:
        # response is of type bytes - convert to string
        response = sdwanp.get_request('template/feature/object/' +
                                      config)

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

    # print specific models enabled on template
    if models:
        response = sdwanp.get_request('template/feature/object/' +
                                      models)
        items = json.loads(response)
        device_models=items['deviceType']
        print()
        print(items['templateName'], ' --- ', items['templateId'])
        print()
        print('Device Models Enabled')
        print()
        print(' ')
        for item in device_models:
            sys.stdout.write(item + ',')
        print()
        print()
        pprint(device_models)
        print()
        print('Device Templates Attached')
        print()

        # pull attached device templates
        url = "template/feature/devicetemplates/{0}".format(models)
        response = json.loads(sdwanp.get_request(url))
        items = response['data']
        for item in items:
            if 'templateId' in item:
                # pull device model for device template
                device_type = json.loads(sdwanp.get_request('template/device/object/' +
                                     item['templateId']))['deviceType']
                print('  ', device_type, ' --- ', item['templateName'],' --- ',item['templateId'])
        print()
        return

    # update model list on feature template
    if model_update:
        deviceId = model_update[0]
        print()
        print('Update Feature Template: ' + deviceId)
        print('  with device model list: ' + model_update[1])
        print()

        models = list(model_update[1].split(","))

        # download feature template to get template class
        response = json.loads(sdwanp.get_request('template/feature/object/' +
                                      deviceId))

        template_class = response['gTemplateClass']

        # validate models in list are valid
        response = json.loads(sdwanp.get_request('device/models'))
        items = response['data']
        valid_models = []
        for item in items:
            if item['templateClass'] == template_class:
                valid_models.append(item['name'])
        
        # check to ensure all input models are in the supported model list
        flag = 0
        if (set(models).issubset(set(valid_models))):
            flag = 1
        if flag:
            print('** Input model list is Validated')
            print()
        else :
            print('ERROR - Input model list is not Supported')
            print()
            return

        # check to ensure new model list supports all attached device templates
        print('** Checking new model list supprts attached Device Templates')
        print()
        url = "template/feature/devicetemplates/{0}".format(deviceId)
        response = json.loads(sdwanp.get_request(url))
        items = response['data']
        for item in items:
            if 'templateId' in item:
                device_type = json.loads(sdwanp.get_request('template/device/object/' +
                                     item['templateId']))['deviceType']
                if device_type in models:
                    flag = 0
                else:
                    flag = 1
                    print(item['templateName'] + " -- " + item['templateId'] + " -- " + device_type +
                        " is MISSING")
                    print()
                    print("Changes will NOT be Submitted")
                    print()
                    return
        print()
        print('** Attached device template models are Validated')
        print()

        # get existing template
        response = sdwanp.get_request('template/feature/object/' +
                                      deviceId)
        items = json.loads(response)
        items['deviceType'] = models

        # create put payload with updated deviceType
        payload = items

        print()
        print("Template File:", deviceId, "attempting to update with new model list")
        print()

        # put updated template
        response = sdwanp.put_request('template/feature/' + deviceId,
                                       payload)
        print(response)
        print()

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

            ./sdwan.py policy-list --config <listId>

            ./sdwan.py policy-list --delete <listId>

            ./sdwan.py policy-list --download <listId> | all

            ./sdwan.py policy-list --update <listId>

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

            ./sdwan.py policy-central --config <policyId>

            ./sdwan.py policy-central --download <policyId> | all

            ./sdwan.py policy-central --upload <file>

            ./sdwan.py policy-central --definition <policyId>

            ./sdwan.py policy-central --tree <policyId>

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

        # load all lists to a dict
        response = json.loads(sdwanp.get_request('template/policy/list'))
        items = response['data']
        list_dict = {}
        for item in items:
            list_dict[item['listId']] = {}
            list_dict[item['listId']]['type'] = item['type']
            list_dict[item['listId']]['name'] = item['name']

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
            try:
                response = json.loads(sdwanp.get_request('template/policy/definition/' +
                                      def1['type'].lower() + '/' + def1['definitionId']))
            except:
                response = json.loads(sdwanp.get_request('template/policy/definition/' +
                                      def1['type'] + '/' + def1['definitionId']))
            print('  def: ' + response['definitionId'] + ' ---------- ' + response['type'] + ' ' +
                  "-"*(25 - len(response['type'])) + ' ' + response['name'])
            list_find(response, list_dict)
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

            ./sdwan.py policy-local --config <policyId>

            ./sdwan.py policy-local --download <policyId> | all

            ./sdwan.py policy-local --upload <file>

            ./sdwan.py policy-local --definition <policyId>

            ./sdwan.py policy-local --tree <policyId>

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
        m = re.search("^.*_(\w{8}\-\w{4}\-\w{4}\-\w{4}\-\w{12})_*(\w.*$)", upload) # pylint: disable=anomalous-backslash-in-string
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
            headers = ["Definition ID", "Definition Type","Definition Name"]
            table = list()
            for d in defs:
                try:
                    response = json.loads(sdwanp.get_request('template/policy/definition/' +
                              d['type'].lower() + '/' + d['definitionId']))
                except:
                    response = json.loads(sdwanp.get_request('template/policy/definition/' +
                              d['type'] + '/' + d['definitionId']))
                tr = [d['definitionId'], d['type'], response['name']]
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

        # load all lists to a dict
        response = json.loads(sdwanp.get_request('template/policy/list'))
        items = response['data']
        list_dict = {}
        for item in items:
            list_dict[item['listId']] = {}
            list_dict[item['listId']]['type'] = item['type']
            list_dict[item['listId']]['name'] = item['name']

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
                try:
                    response = json.loads(sdwanp.get_request('template/policy/definition/' +
                                          def1['type'] + '/' + def1['definitionId']))
                except:
                    response = json.loads(sdwanp.get_request('template/policy/definition/' +
                                          def1['type'].lower() + '/' + def1['definitionId']))
                print('  def: ' + response['definitionId'] + ' ---------- ' + response['type'] + ' ' +
                      "-"*(25 - len(response['type'])) + ' ' + response['name'])
                list_find(response, list_dict)
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

# POLICY SECURITY

@click.command()
@click.option("--config", help="Print Policy Contents")
@click.option("--download", help="Policy to Download")
@click.option("--upload", help="File to Upload Policy")
@click.option("--definition", help="Referenced Definitions")
@click.option("--tree", help="List definitions and lists referenced")
def policy_security(config, download, upload, definition, tree):
    """Display, Download, and Upload Security Policy.

          List Policy to derive PolicyID for additional actions

        Example Command:

            ./sdwan.py policy-security

            ./sdwan.py policy-security --config <policyId>

            ./sdwan.py policy-security --download <policyId> | all

            ./sdwan.py policy-security --upload <file>

            ./sdwan.py policy-security --definition <policyId>

            ./sdwan.py policy-security --tree <policyId>

    """

    # print specific policy to stdout
    if config:
        response = sdwanp.get_request('template/policy/security/definition/' +
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
            response = json.loads(sdwanp.get_request('template/policy/security'))
            items = response['data']
            print()
            print("Downloading all Security Policy...")
            print()
            for item in items:
                print("  Policy ID:", item['policyId'], "downloaded...")
                response = sdwanp.get_request('template/policy/security/definition/' +
                                              item['policyId'])
                json_file = open(SDWAN_CFGDIR + "policy-security____" +
                                 item['policyType'] +
                                 "_"*(32 - len(item['policyType'])) +
                                 item['policyId'] + '___' +
                                 item['policyName'].replace('/', '-'), "w")
                json_file.write(re.sub("'|b'", '', str(response)))
                json_file.close()
            print()
        else:
            response = sdwanp.get_request('template/policy/security/definition/' +
                                          download)
            item = json.loads(response)
            print()
            print(item['policyType'])
            print(item['policyName'])
            print(download)
            json_file = open(SDWAN_CFGDIR + "policy-security____" +
                             item['policyType'] +
                             "_"*(32 - len(item['policyType'])) +
                             download + '___' +
                             item['policyName'].replace('/', '-'), "w")
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
        response = sdwanp.post_request('template/policy/security',
                                       payload)
        print()
        print(response)
        print()

        # glean original policyId from file name
        m = re.search("^.*_(\w{8}\-\w{4}\-\w{4}\-\w{4}\-\w{12})_*(\w.*$)", upload) # pylint: disable=anomalous-backslash-in-string
        if m:
            lpid = m.group(1)
            lpname = m.group(2)
        # search for current Policy Id from local policy listing
        response = json.loads(sdwanp.get_request('template/policy/security'))
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
        response = sdwanp.get_request('template/policy/security/definition/' +
                                      definition)
        item = json.loads(response)
        print()
        print("Policy Name:", item['policyName'])
        print("Policy ID:", definition)
        print()
        print("--- Attached Definitions ---")
        print()
        defs = item['policyDefinition']['assembly']
        headers = ["Definition ID", "Definition Type","Definition Name"]
        table = list()
        for d in defs:
            try:
                response = json.loads(sdwanp.get_request('template/policy/definition/' +
                          d['type'].lower() + '/' + d['definitionId']))
            except:
                response = json.loads(sdwanp.get_request('template/policy/definition/' +
                          d['type'] + '/' + d['definitionId']))
            tr = [d['definitionId'], d['type'], response['name']]
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

        # load all lists to a dict
        response = json.loads(sdwanp.get_request('template/policy/list'))
        items = response['data']
        list_dict = {}
        for item in items:
            list_dict[item['listId']] = {}
            list_dict[item['listId']]['type'] = item['type']
            list_dict[item['listId']]['name'] = item['name']

        # identify referenced definitions
        response = sdwanp.get_request('template/policy/security/definition/' +
                                      tree)
        item = json.loads(response)
        print()
        print('  ******* Security Policy ********')
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
            try:
                response = json.loads(sdwanp.get_request('template/policy/definition/' +
                                      def1['type'] + '/' + def1['definitionId']))
            except:
                response = json.loads(sdwanp.get_request('template/policy/definition/' +
                                      def1['type'].lower() + '/' + def1['definitionId']))
            print('  def: ' + response['definitionId'] + ' ---------- ' + response['type'] + ' ' +
                  "-"*(25 - len(response['type'])) + ' ' + response['name'])
            list_find(response,list_dict)
        print()
        print()
        return
    
    # no parameter passed in - list all policies
    response = json.loads(sdwanp.get_request('template/policy/security'))
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

            ./sdwan.py policy-definition --config <definitionId>

            ./sdwan.py policy-definition --download <definitionId> | all

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
    
    response = json.loads(sdwanp.get_request('template/policy/security'))
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
        try:
            response = json.loads(sdwanp.get_request('template/policy/definition/' +
                              defs[def_id].lower() + '/' + def_id))
        except:
            response = json.loads(sdwanp.get_request('template/policy/definition/' +
                              defs[def_id] + '/' + def_id))

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

# SAAS ONRAMP

@click.command()
@click.option("--status", help="SaaS Application")
def saas(status):
    """Display SaaS OnRamp Status.

        Example Command:

            ./sdwan.py saas

            ./sdwan.py saas --status <app_name>

    """
    if status:
        print()
        response = json.loads(sdwanp.get_request('template/cloudx/status/?appName=' + status))
        items = response['data']
        headers = ["Site ID", "Hotname", "System IP","Interface","Color", "Latency","VQE Score", "VQE Status", "Gateway"]
        table = list()
        for item in items:
            tr = [item['site-id'], item['host-name'], item['system-ip'],
                  item['interface'], item['local-color'], item['latency'],
                  item['vqe-score'], item['vqe-status'], item['gateway-system-ip']]
            table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
        print()
        return

    # no parameter passed in 
    print()
    response = json.loads(sdwanp.get_request('template/cloudx/manage/apps'))
    items = response['data']
    headers = ["Application", "App Name", "VPN", "Enabled"]
    table = list()
    for item in items:
        tr = [item['longName'], item['appType'], item['appVpnList'],
              item['policyEnabled']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
    print()
    headers = ["Site Type", "Site ID", "Hostname", "System IP", "Color", "Status"]
    table = list()
    response = json.loads(sdwanp.get_request('template/cloudx/attachedgateway'))
    items = response['data']
    for item in items:
        for i in range(len(item['vedgeList'])):
            tr = ['Gateway', item['site-id'], item['vedgeList'][i]['host-name'],item['vedgeList'][i]['system-ip'],
                 item['vedgeList'][i]['colorList'],
                 item['vedgeList'][i]['configStatusMessage']]
            table.append(tr)
    response = json.loads(sdwanp.get_request('template/cloudx/attachedclient'))
    items = response['data']
    for item in items:
        for i in range(len(item['vedgeList'])):
            tr = ['Client', item['site-id'], item['vedgeList'][i]['host-name'],item['vedgeList'][i]['system-ip'],
                 item['vedgeList'][i]['colorList'],
                 item['vedgeList'][i]['configStatusMessage']]
            table.append(tr)
    response = json.loads(sdwanp.get_request('template/cloudx/attacheddia'))
    items = response['data']
    for item in items:
        for i in range(len(item['vedgeList'])):
            tr = ['DIA', item['site-id'], item['vedgeList'][i]['host-name'],item['vedgeList'][i]['system-ip'],
                 item['vedgeList'][i]['colorList'],
             item['vedgeList'][i]['configStatusMessage']]
            table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="grid"))
    print()

    return

##############################################################################

# SDAVC

@click.command()
@click.option("--domain", is_flag=True, help="SDAVC Applications by Domain")
@click.option("--ip", is_flag=True, help="SDAVC Applications by IP")
def sdavc(domain,ip):
    """Display SDAVC Cloud Connector

        Example Command:

            ./sdwan.py sdavc --domain

            ./sdwan.py sdavc --ip

            ./sdwan.py sdavc

    """
    if domain:
        print()
        response = json.loads(sdwanp.get_request('monitor/sdavccloudconnector/domain'))
        items = response['data']
        headers = ["Application", "Domain", "Optimize", "Allow", "Service"]
        table = list()
        for item in items:
            tr = [item['appName'], item['domainName'], item['optimize'],
                  item['allow'], item['serviceArea']]
            table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                    tablefmt="grid"))
        print()
        return

    if ip:
        print()
        response = json.loads(sdwanp.get_request('monitor/sdavccloudconnector/ipaddress'))
        items = response['data']
        headers = ["Application", "IP", "Protocol", "Port", "Optimize", "Allow", "Service"]
        table = list()
        for item in items:
            tr = [item['appName'], item['ipAddress'].replace('"',''), item['l4Protocol'], item['port'],
                  item['optimize'], item['allow'], item['serviceArea']]
            table.append(tr)
        try:
            click.echo(tabulate.tabulate(table, headers,
                                     tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, headers,
                                    tablefmt="grid"))
        print()
        return

    # no parameter passed in - sdavc connector settings and status
    print()
    response = json.loads(sdwanp.get_request('sdavc/cloudconnector'))
    pprint(response)
    print()
    response = json.loads(sdwanp.get_request('sdavc/cloudconnector/status'))
    pprint(response)
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
cli.add_command(policy_security)
cli.add_command(device)
cli.add_command(certificate)
cli.add_command(saas)
cli.add_command(sdavc)
cli.add_command(tasks)
cli.add_command(template_device)
cli.add_command(template_feature)


###############################################################################

# MAIN

def main():
    cli()

if __name__ == '__main__':
    main()
