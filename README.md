# SDWAN

Cisco SDWAN (Viptela) CLI Tool

This project has several objectives:
 * Learn Cisco SDWAN API
 * Learn Python
 * Provide a methond to aquire environment information via CLI
 * Bridge functional gaps in the UI
 * Optimize configuration, deployment, and validation of SDWAN
 * Provide sample configuration chunks
 * Have fun

 Certainly this code could and should be modularized.  It is intenially kept
 in a single script to provide a single place to explore.

 The script grew from the Cisco DevNet SDWAN Learning Labs.  It is recommend
 to run through the series.

 https://developer.cisco.com/sdwan/learn/


## INSTALLATION

    Install python modules
       * requests
       * click
       * tabulate
       * netmiko

    Clone or download this repo

    Create an environmental variable file:
	vi ./export/myenv

    Create environment backup directory
	mkdir ./cfg/myenv
    
     
## USAGE

Before running the script, the environment variables need to be set.

    Display the environment file.
       cat ./export/myenv

    Copy and Paste the contents into the terminal


Script Usage

    
    ./sdwan.py --help

    Usage: sdwan.py [OPTIONS] COMMAND [ARGS]...

        CLI for managing policies and templates in Cisco SDWAN.

    Options:
      --help  Show this message and exit.

    Commands:
      certificate        Send Certificates to Controllers.
      configuration-db   Create Database Backup File and Download.
      device             Display, Download, and View CLI Config for Devices.
      env                Print SDWAN Environment Values.
      policy-central     Display, Download, and Upload Centralized Policy.
      policy-definition  Display, Download, and Upload Policy Definitions.
      policy-list        Display, Download, and Upload Policy Lists.
      policy-local       Display, Download, and Upload Local Policy.
      policy-security    Display, Download, and Upload Security Policy.
      rest               Execute raw REST GET request.
      saas               Display SaaS OnRamp Status.
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
 * [tasks](tasks)
 * [template-device](template-device)
 * [template-feature](template-feature)


## ENVIRONMENT VARIABLES

The script will use environmental values to target the SD-WAN environment.

 * SDWAN_IP=<vmanage_ip>

 * SDWAN_PORT=<vmanage_port>
	
 * SDWAN_USERNAME=<username>

 * SDWAN_PASSWORD=<password>

 * SDWAN_CFGDIR=./cfg/<environment_name>/
	
 * SDWAN_PROXY=127.0.0.1:12345


It is good to organize different environments by creating a file in the export direcotry.

This is the DevNet environment file.

    cat export/devnet 

    export SDWAN_IP=64.103.37.21
    export SDWAN_PORT=8443
    export SDWAN_USERNAME=devnetuser
    export SDWAN_PASSWORD=Cisco123!
    export SDWAN_CFGDIR=./cfg/devnet/

The current environment can be viewed with the 'env' command in the script.

    ./sdwan.py env

If using SOCKS Proxy to Port forward SSH/HTTPS through a Bastion Host, add vManage entry to the .ssh_config file.

It would look like:

    host 52.89.253.138
     ProxyCommand=nc -X 5 -x localhost:12345 %h %p


## VMANAGE OBJECTS/COMPONENTS

Lists, Definitions, Policies, and Templates are the core Components to vManage.

[VMANAGE COMPONENTS](https://github.com/ruszkiew/sdwan/blob/master/VMANAGE%20COMPONENTS.pdf)



## BACKUP (BATCH DOWNLOAD)

The [backup](backup) script will download all of the SDWAN environmental objects.

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
  * Policy Central
  * Template Feature
  * Template Device


## EXAMPLES

    ./sdwan.py certificate
    ./sdwan.py configuration-db --backup customer_backup_file_1
    ./sdwan.py device
    ./sdwan.py device --bfd 100.65.30.11
    ./sdwan.py device --control 100.65.30.11
    ./sdwan.py device --variable 100.65.30.11
    ./sdwan.py device --config 100.65.30.11
    ./sdwan.py device --valid 100.65.30.11
    ./sdwan.py device --staging 100.65.30.11
    ./sdwan.py device --attach 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9 router_var.csv
    ./sdwan.py device --template 100.65.30.11
    ./sdwan.py device --set_var 100.65.30.11 '//system/gps-location/latitude' 44.9764 
    ./sdwan.py device --template 100.65.30.11
    ./sdwan.py device --detach 100.65.30.11
    ./sdwan.py device --csv 100.65.30.11
    ./sdwan.py device --download 100.65.30.11
    ./sdwan.py device --download all
    ./sdwan.py device --sla 100.65.30.11
    ./sdwan.py device --wan 100.65.30.11
    ./sdwan.py device --int 100.65.30.11
    ./sdwan.py device --arp 100.65.30.11
    ./sdwan.py device --ospf 100.65.30.11
    ./sdwan.py device --bgp 100.65.30.11
    ./sdwan.py device --count_dp 100.65.30.11
    ./sdwan.py device --count_aar 100.65.30.11
    ./sdwan.py device --events_hr 100.65.30.11
    ./sdwan.py device --events_crit 100.65.30.11
    ./sdwan.py device --models
    ./sdwan.py env
    ./sdwan.py tasks
    ./sdwan.py policy-definition
    ./sdwan.py policy-list
    ./sdwan.py policy-list --config 511ea203-30c5-4c79-9050-76bc896525a2
    ./sdwan.py policy-list --delete 511ea203-30c5-4c79-9050-76bc896525a2
    ./sdwan.py policy-list --download 511ea203-30c5-4c79-9050-76bc896525a2
    ./sdwan.py policy-list --upload list_json_config.txt
    ./sdwan.py policy-list --download all
    ./sdwan.py policy-central
    ./sdwan.py policy-central --definition bf0e9b04-616d-44d5-8c8e-633420a233f3
    ./sdwan.py policy-central --tree bf0e9b04-616d-44d5-8c8e-633420a233f3
    ./sdwan.py policy-local
    ./sdwan.py policy-local --tree 729641be-a54a-43b0-bc86-9c5822aba0f8
    ./sdwan.py policy-local --config 729641be-a54a-43b0-bc86-9c5822aba0f8
    ./sdwan.py policy-security
    ./sdwan.py rest --object <api_object>
    ./sdwan.py saas
    ./sdwan.py template-device --tree 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9
    ./sdwan.py template-device --variable 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9
    ./sdwan.py template-device --config 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9
    ./sdwan.py template-device --attached 38d7931c-3aeb-42e8-bcd2-08b5fc1367e9
    ./sdwan.py template-feature --attached dc079e4e-7631-4246-923a-71943427a4fd
    ./sdwan.py template-feature --config dc079e4e-7631-4246-923a-71943427a4fd
    ./sdwan.py template-feature --download dc079e4e-7631-4246-923a-71943427a4fd
    ./sdwan.py template-feature --download all
    ./sdwan.py template-feature --models dc079e4e-7631-4246-923a-71943427a4fd
    ./sdwan.py template-feature --model_update dc079e4e-7631-4246-923a-71943427a4fd vedge-1000,vedge-100,vedge-2000


## TODO
See the GitHub 'Issues' tracker for a list of planned features/fixes.


## CONTRIBUTING

E-mail the authors for:

  * Bugs
  * Feature Requests

These items will be staged on the GitHub 'Issues' tracker.

Contributors will be assigned to items on the list.


## AUTHORS

[Ed Ruszkiewicz](ed.ruszkiewicz@cdw.com) 


## CHANGELOG

See [CHANGELOG](CHANGELOG.md) for a list of changes.

