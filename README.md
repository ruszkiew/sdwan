# SDWAN

Cisco SDWAN Catalyst CLI Tool

This project has several objectives:
 * Learn Cisco Catalyst SDWAN API
 * Learn Python
 * Provide a method to gather data via CLI
 * Bridge functional gaps in the vManage UI
 * Optimize configuration, deployment, and validation of SDWAN
 * Provide somewhat intuitive sample configuration chunks
 * Have some fun

 This code has grown and is pretty long.  It could and should be modularized.  It is intentionaly kept in a single script to provide a single place to explore.

 The script grew from the Cisco DevNet SDWAN Learning Labs.

Cisco UX2.0 has NOT yet been integrated.  It will as the configuration develops.
 * Configuration Group
 * Policy Group
 * Topology
 * Hiearchy

## BRIDGING THE GAP

These are the functional items the script provides that cannot be done in Manager(vManage).

 * Import/Export Template and Policy Objects.
 * Clear Tasks.
 * Database Backup.
 * Send CLI Commands to Device via vManage
 * Change Device Models in Feature Template.
 * Clone Feature/Device Template to different Model.
 * Identify Central Policy Applied to a Device.
 * Automate Validation.
 * Review FEC Operation.

## INSTALLATION

    Install python modules (pip)
       * requests
       * pysocks
       * click
       * tabulate
       * netmiko

    Clone or download this repo

    
     
## USAGE

Before running the script, the environment variables need to be set.

    Create an environmental variable file.  Example environment is 'myenv'.
	vi export/myenv

    Create environment backup directory
	mkdir ./cfg/myenv

    Display the environment file.
    cat export/myenv

    If the password is stored in 'myenv', it is recommended to encrypt the file.  OpenSSL works nicely.
        # encrypt myenv
        openssl aes-256-cbc -a -salt -in export/myenv -out export/myenv.enc
        # remove myenv with the cleartext password
        rm export/myenv
        # decrypt myenvn to stdout to copy 
        openssl aes-256-cbc -d -a -salt -in export/myenv.enc

    Copy and Paste the contents into the terminal

## ENVIRONMENT VARIABLES

The script will use Environmental Values to target the SDWAN environment.

 * SDWAN_IP=<vmanage_ip>

 * SDWAN_PORT=<vmanage_port>
	
 * SDWAN_USERNAME=<username>

 * SDWAN_PASSWORD=<password>

 * SDWAN_CFGDIR=./cfg/<environment_name>/

Optional Environmental Values
	
 * SDWAN_PROXY=127.0.0.1:12345

 * ROUTER_USERNAME=<username>

 * ROUTER_PASSWORD=<password>


It is good to organize different environments by creating a file in the export direcotry.

This is the DevNet environment file.

    cat export/devnet 

    export SDWAN_IP=64.103.37.21
    export SDWAN_PORT=443
    export SDWAN_USERNAME=devnetuser
    export SDWAN_PASSWORD=Cisco123!
    export SDWAN_CFGDIR=./cfg/devnet/

The current environment can be viewed with the 'env' command in the script.

    sdwan.py env

If using SOCKS Proxy to Port forward SSH/HTTPS through a Bastion Host, add Manager entry to the .ssh_config file.

It would look like:

    host <ip_proxy_host>
     ProxyCommand=nc -X 5 -x localhost:12345 %h %p


Script Usage

    
    sdwan.py --help

    Usage: sdwan.py [OPTIONS] COMMAND [ARGS]...

        CLI for managing policies and templates in Cisco Catalyst SDWAN.

    Options:
      --help  Show this message and exit.

    Commands:
      certificate        Send Certificates to Controllers.
      configuration-db   Create Database Backup File and Download.
      device             Display, Download, and View CLI Config for Devices.
      env                Print SDWAN Environment Values.
      policy-central     Display, Download, and Upload Centralized Policy.
      policy-custom-app  Display, Download, and Upload Custom Application.
      policy-definition  Display, Download, and Upload Policy Definitions.
      policy-list        Display, Download, and Upload Policy Lists.
      policy-local       Display, Download, and Upload Local Policy.
      policy-security    Display, Download, and Upload Security Policy.
      rest               Execute raw REST GET request.
      saas               Display SaaS OnRamp Status.
      sdavc              Display SDAVC Cloud Connector
      tasks              Retrieve and/or Clear vManage Active Tasks.
      template-device    Display, Download, and Upload Device Templates.
      template-feature   Display, Download, and Upload Feature Templates.


## COMMANDS + ACTIONS

 * [certificate](certificate)
 * [configuration-db](configuration-db)
 * [device](device)
 * [env](env)
 * [policy-central](policy-central)
 * [policy-definition](policy-definition)
 * [policy-list](policy-list)
 * [policy-local](policy-local)
 * [policy-security](policy-security)
 * [rest](rest)
 * [saas](saas)
 * [sdavc](sdavc)
 * [tasks](tasks)
 * [template-device](template-device)
 * [template-feature](template-feature)

Each command has a corresponding file with the --help output.
The presense of this file is simply for 'tab' autocomplete during use.




## MANAGER OBJECTS/COMPONENTS

Lists, Definitions, Policies, and Templates are the core Components to vManage.

[VMANAGE COMPONENTS UX1.0](https://github.com/ruszkiew/sdwan/blob/master/vmanage_ux1.pdf)

[VMANAGE COMPONENTS UX2.0](https://github.com/ruszkiew/sdwan/blob/master/vmanage_ux2.pdf)


## BACKUP (BATCH DOWNLOAD

The [backup](backup) script will download all of the SDWAN objects.

 * Policies + Building Blocks (Lists,Definitions)
 * Templates (Device and Feature)
 * Device Configurations
 * Device Variables


## UPLOAD

Objects may be uploaded to the same or older version of vManage.

Objects are linked with references.  The IDs do change after an upload so the stored object files are updated with the new IDs.  When uploading in batch it is important to start with the 'leaf' objects and work towards the more complex.  Below is the advised order of upload.

WARNING - Do NOT use Factory Default Feature Templates if you plan to Upload Device Templates.  ID linking will be broken.  

  * List
  * Definition
  * Policy Local
  * Policy Security
  * Policy Central
  * Template Feature
  * Template Device

CiscoDevNet/[SASTRE](https://github.com/CiscoDevNet/sastre) is a much better script for heavy exporting and importing.


## EXAMPLES

    sdwan.py certificate
    sdwan.py configuration-db --backup customer_backup_file_1
    sdwan.py device
    sdwan.py device --bfd 100.65.30.11
    sdwan.py device --control 100.65.30.11
    sdwan.py device --variable 100.65.30.11
    sdwan.py device --config 100.65.30.11
    sdwan.py device --valid 100.65.30.11
    sdwan.py device --staging 100.65.30.11
    sdwan.py device --attach 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9 router_var.csv
    sdwan.py device --template 100.65.30.11
    sdwan.py device --set_var 100.65.30.11 '//system/gps-location/latitude' 44.9764 
    sdwan.py device --send 100.65.30.11 'show ip int brief'
    sdwan.py device --send 100.65.30.11 show_command.lst
    sdwan.py device --detail 100.65.30.11
    sdwan.py device --detach 100.65.30.11
    sdwan.py device --fec 100.65.30.11
    sdwan.py device --qos 100.65.30.11
    sdwan.py device --flow 100.65.30.11
    sdwan.py device --csv 100.65.30.11
    sdwan.py device --download 100.65.30.11
    sdwan.py device --download all
    sdwan.py device --sla 100.65.30.11
    sdwan.py device --int 100.65.30.11
    sdwan.py device --arp 100.65.30.11
    sdwan.py device --ospf 100.65.30.11
    sdwan.py device --bgp 100.65.30.11
    sdwan.py device --count_dp 100.65.30.11
    sdwan.py device --count_aar 100.65.30.11
    sdwan.py device --events_hr 100.65.30.11
    sdwan.py device --vsmart 100.65.30.11
    sdwan.py device --models
    sdwan.py device --ping 100.65.30.11 0 24.48.58.1 8.8.8.8
    sdwan.py device --trace 100.65.30.11 0 24.48.58.1 8.8.8.8
    sdwan.py env
    sdwan.py tasks
    sdwan.py policy-definition
    sdwan.py policy-list
    sdwan.py policy-list --config 511ea203-30c5-4c79-9050-76bc896525a2
    sdwan.py policy-list --delete 511ea203-30c5-4c79-9050-76bc896525a2
    sdwan.py policy-list --download 511ea203-30c5-4c79-9050-76bc896525a2
    sdwan.py policy-list --upload list_json_config.txt
    sdwan.py policy-list --download all
    sdwan.py policy-central
    sdwan.py policy-central --definition bf0e9b04-616d-44d5-8c8e-633420a233f3
    sdwan.py policy-central --tree bf0e9b04-616d-44d5-8c8e-633420a233f3
    sdwan.py policy-local
    sdwan.py policy-local --tree 729641be-a54a-43b0-bc86-9c5822aba0f8
    sdwan.py policy-local --config 729641be-a54a-43b0-bc86-9c5822aba0f8
    sdwan.py policy-security
    sdwan.py rest --get <api_object>
    sdwan.py saas
    sdwan.py sdavc
    sdwan.py template-device --clone 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9 vedge-1000
    sdwan.py template-device --tree 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9
    sdwan.py template-device --variable 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9
    sdwan.py template-device --config 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9
    sdwan.py template-device --attached 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9
    sdwan.py template-feature --attached dc079e4e-7631-4246-923a-71943427a4fd
    sdwan.py template-feature --config dc079e4e-7631-4246-923a-71943427a4fd
    sdwan.py template-feature --download dc079e4e-7631-4246-923a-71943427a4fd
    sdwan.py template-feature --download all
    sdwan.py template-feature --models dc079e4e-7631-4246-923a-71943427a4fd
    sdwan.py template-feature --model_update dc079e4e-7631-4246-923a-71943427a4fd vedge-1000,vedge-100,vedge-2000

## EDGE VALIDATION TESTING
Use pytest along with sdwan to automate validation.  See linked file for an example.

[EXAMPLE VALIDATION SCRIPT](https://github.com/ruszkiew/sdwan/blob/master/test_site.py)

This test script can be run in the following form.

    test_site.py --deviceId 100.65.30.11

The 'pytest.ini' file was included to ignore Warning Messages and output Verbose.

## TODO
See the GitHub 'Issues' tracker for a list of planned features/fixes.


## CONTRIBUTING

E-mail the authors for:

  * Bugs
  * Feature Requests

These items will be staged on the GitHub 'Issues' tracker.

Contributors will be assigned to items on the list.


## AUTHORS

Ed Ruszkiewicz - ed@ruszkiewicz.net
 

## CHANGELOG

See [CHANGELOG](CHANGELOG.md) for a list of changes.

