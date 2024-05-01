# Zabbix API

This python script uses the python zabbix_utils library to interact with Zabbix.

It is in beta state and might work or it might not. I am still working on documentation and testing.

## Features
* Create host objects in Zabbix
* Update host objects in Zabbix
* Delete host objects in Zabbix
* Query host objects in Zabbix

## Requirements
* Python 3.x
* [python-zabbix-utils](https://github.com/zabbix/python-zabbix-utils) module

## Configuration
There are two steps in configuring the usage of this script:

1. Arranging a form of authentication
2. Configuring the script

### Authentication

#### Create an API token
See [the official Zabbix documentation](https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/users/api_tokens)

#### Create a Zabbix user
See [the official Zabbix documentation](https://www.zabbix.com/documentation/current/en/manual/config/users_and_usergroups/user)

### Configure the script
Create a hidden file in your home directory named .zabbix-api.ini with the following contents. Depending on the chosen authentication type it should contain any of the following:

```
[Api]
Url = <the URL to your Zabbix instance, e.g. https://zabbix.company.org>
Token = <the Zabbix API token retrieved earlier>
```
or
```
[Api]
Url = <the URL to your Zabbix instance, e.g. https://zabbix.company.org>
User = <the Zabbix user you created earlier>
Password = <the Zabbix password you created earlier>
```

## Usage
