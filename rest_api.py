###############################################################################

# REST API CLASS

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # pylint: disable=import-error
from requests.auth import HTTPBasicAut
from netmiko import ConnectHandler, SCPConn
import urllib3
import json
from time import time


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
