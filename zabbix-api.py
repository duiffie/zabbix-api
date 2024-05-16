#!/usr/bin/python3
# pylint: disable=invalid-name,line-too-long

"""
File: zabbix-api.py
Author: Marco van Duijvenbode
Date: 28/04/2024

Description: Wrapper around the zabbix_utils python library
"""

# Built-in/Generic Imports
import argparse
import configparser
import json
import os
import secrets
import sys

# Libs
import logging as log

# Futures
from argparse import Namespace
from zabbix_utils import ZabbixAPI


def parse_args():  # pylint: disable=too-many-locals,too-many-statements
    """Function parsing arguments"""
    DESCRIPTION = 'Wrapper around the zabbix_utils python library'
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    subparsers = parser.add_subparsers(required=True)

    # create the parser for the "host" command
    DESCRIPTION = 'Create/delete/get/update host objects in Zabbix'
    parser_host = subparsers.add_parser('host', description=DESCRIPTION, help=DESCRIPTION)
    host_subparsers = parser_host.add_subparsers(required=True)

    # create the parser for the "host" -> "create" command
    DESCRIPTION = 'Create host objects in Zabbix'
    parser_host_create = host_subparsers.add_parser('create', description=DESCRIPTION, help=DESCRIPTION)
    parser_host_create.add_argument('-f', '--fqdn', type=str, help='Fully qualified domain name', required=True)
    parser_host_create.add_argument('-n', '--name', type=str, help='Visible name of the host')
    parser_host_create.add_argument('-d', '--desc', type=str, help='Description of the host')
    parser_host_create.add_argument('-g', '--group', type=str, action='append', help='Add the host to this group. Can be used multiple times', required=True)
    parser_host_create.add_argument('-t', '--template', type=str, action='append', help='Add this template to the host. Can be used multiple times')
    parser_host_create.add_argument('-p', '--proxy', type=str, help='Connect the agent through this zabbix proxy')
    parser_host_create.add_argument('-it', '--interface_type', type=int, choices=[1, 2, 3, 4], help='Interface type to create. 1 = Agent, 2 = SNMP, 3 = IPMI, 4 = JMX', required=True)
    parser_host_create.add_argument('-ii', '--interface_ip', type=str, help='IP-address used by the interface', required=True)
    parser_host_create.add_argument('-e', '--encryption', type=int, choices=[32, 64, 128, 256, 512], help='Encrypt connections to the host with the specified keylength')
    parser_host_create.add_argument('-v', '--verbose', action='count', help='Be more verbose')
    parser_host_create.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser_host_create.set_defaults(func=host_create)

    # create the parser for the "host" -> "delete" command
    DESCRIPTION = 'Delete host objects from Zabbix'
    parser_host_delete = host_subparsers.add_parser('delete', description=DESCRIPTION, help=DESCRIPTION)
    parser_host_delete.add_argument('-f', '--fqdn', type=str, help='Fully qualified domain name', required=True)
    parser_host_delete.add_argument('-v', '--verbose', action='count', help='Be more verbose')
    parser_host_delete.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser_host_delete.set_defaults(func=host_delete)

    # create the parser for the "host" -> "get" command
    DESCRIPTION = 'Retrieve host object info from Zabbix'
    parser_host_get = host_subparsers.add_parser('get', description=DESCRIPTION, help=DESCRIPTION)
    parser_host_get.add_argument('-a', '--all', action='store_true', help='Retrieve all hosts')
    parser_host_get.add_argument('-f', '--fqdn', type=str, help='Fully qualified domain name')
    parser_host_get.add_argument('-o', '--output', type=str, action='append', help='Limit output fields to this one')
    parser_host_get.add_argument('-v', '--verbose', action='count', help='Be more verbose')
    parser_host_get.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser_host_get.set_defaults(func=host_get)

    # create the parser for the "host" -> "update" command
    DESCRIPTION = 'Update host object in Zabbix'
    parser_host_update = host_subparsers.add_parser('update', description=DESCRIPTION, help=DESCRIPTION)
    parser_host_update.add_argument('-f', '--fqdn', type=str, help='Fully qualified domain name', required=True)
    parser_host_update.add_argument('-n', '--name', type=str, help='Visible name of the host')
    parser_host_update.add_argument('-d', '--desc', type=str, help='Description of the host')
    parser_host_update.add_argument('-g', '--group', type=str, action='append', help='Add the host to this group. Can be used multiple times')
    parser_host_update.add_argument('-t', '--template', type=str, action='append', help='Add this template to the host. Can be used multiple times')
    parser_host_update.add_argument('-p', '--proxy', type=str, help='Connect the agent through this zabbix proxy')
    parser_host_update.add_argument('-it', '--interface_type', type=int, choices=[1, 2, 3, 4], help='Interface type. 1 = Agent, 2 = SNMP, 3 = IPMI, 4 = JMX')
    parser_host_update.add_argument('-ii', '--interface_ip', type=str, help='IP-address used by the interface')
    parser_host_update.add_argument('-ne', '--no_encryption', action="store_true", help="Don't encrypt connections to the host")
    parser_host_update.add_argument('-e', '--encryption', type=int, choices=[32, 64, 128, 256, 512], help='Encrypt connections to the host with the specified keylength')
    parser_host_update.add_argument('-v', '--verbose', action='count', help='Be more verbose')
    parser_host_update.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser_host_update.set_defaults(func=host_update)

    # create the parser for the "hostgroup" command
    DESCRIPTION = 'Get host group objects from Zabbix'
    parser_hostgroup = subparsers.add_parser('hostgroup', description=DESCRIPTION, help=DESCRIPTION)
    hostgroup_subparsers = parser_hostgroup.add_subparsers(required=True)

    # create the parser for the "hostgroup" -> "get" command
    DESCRIPTION = 'Get host group objects from Zabbix'
    parser_hostgroup_get = hostgroup_subparsers.add_parser('get', description=DESCRIPTION, help=DESCRIPTION)
    parser_hostgroup_get.add_argument('-a', '--all', action='store_true', help='Retrieve all host groups')
    parser_hostgroup_get.add_argument('-n', '--name', type=str, help='Host group name')
    parser_hostgroup_get.add_argument('-v', '--verbose', action='count', help='Be more verbose')
    parser_hostgroup_get.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser_hostgroup_get.set_defaults(func=hostgroup_get)

    # create the parser for the "template" command
    DESCRIPTION = 'Get template objects from Zabbix'
    parser_template = subparsers.add_parser('template', description=DESCRIPTION, help=DESCRIPTION)
    template_subparsers = parser_template.add_subparsers(required=True)

    # create the parser for the "template" -> "get" command
    DESCRIPTION = 'Get template objects from Zabbix'
    parser_template_get = template_subparsers.add_parser('get', description=DESCRIPTION, help=DESCRIPTION)
    parser_template_get.add_argument('-a', '--all', action='store_true', help='Retrieve all templates')
    parser_template_get.add_argument('-n', '--name', type=str, help='Template name')
    parser_template_get.add_argument('-v', '--verbose', action='count', help='Be more verbose')
    parser_template_get.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser_template_get.set_defaults(func=template_get)

    # create the parser for the "proxy" command
    DESCRIPTION = 'Get proxy objects from Zabbix'
    parser_proxy = subparsers.add_parser('proxy', description=DESCRIPTION, help=DESCRIPTION)
    proxy_subparsers = parser_proxy.add_subparsers(required=True)

    # create the parser for the "proxy" -> "get" command
    DESCRIPTION = 'Get proxy objects from Zabbix'
    parser_proxy_get = proxy_subparsers.add_parser('get', description=DESCRIPTION, help=DESCRIPTION)
    parser_proxy_get.add_argument('-a', '--all', action='store_true', help='Retrieve all proxies')
    parser_proxy_get.add_argument('-n', '--name', type=str, help='Proxy name')
    parser_proxy_get.add_argument('-v', '--verbose', action='count', help='Be more verbose')
    parser_proxy_get.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser_proxy_get.set_defaults(func=proxy_get)

    # parse the args
    arguments = parser.parse_args()

    return arguments


def gen_psk(length):
    """Function generating PSK's"""
    return secrets.token_hex(length // 2)


def gen_host_request(arguments):  # pylint: disable=too-many-branches,too-many-statements
    """Function generating host api request"""
    api_request = {}

    # host_create specific
    if arguments.func is host_create:
        if arguments.name:
            api_request['name'] = arguments.name

        api_request['groups'] = []

        for group in arguments.group:
            groupdata = hostgroup_get(Namespace(func=arguments.func, all=False, name=group))
            if groupdata is None:
                log.warning("Host group '%s' does not exist", group)
                continue
            api_request['groups'].append({'groupid': groupdata['groupid']})

        if arguments.template is not None:
            api_request['templates'] = []
            for template in arguments.template:
                templatedata = template_get(Namespace(func=arguments.func, all=False, name=template))
                if groupdata is None:
                    log.warning("Template '%s' does not exist", template)
                    continue
                api_request['templates'].append({'templateid': templatedata['templateid']})

        if arguments.proxy is not None:
            proxydata = proxy_get(Namespace(func=arguments.func, all=False, name=arguments.proxy))
            if proxydata is None:
                log.warning("Proxy '%s' does not exist", arguments.proxy)
                sys.exit(1)
            api_request['proxy_hostid'] = proxydata['proxyid']

        api_request['interfaces'] = {}
        api_request['interfaces']['type'] = arguments.interface_type  # 1=Agent, 2=SNMP
        api_request['interfaces']['ip'] = arguments.interface_ip
        api_request['interfaces']['dns'] = arguments.fqdn
        api_request['interfaces']['port'] = 10050 if api_request['interfaces']['type'] == 1 else 161  # 10050 for agent, 161 for snmp
        api_request['interfaces']['useip'] = 1  # 0=dns, 1=ip
        api_request['interfaces']['main'] = 1  # 0=not default, 1=default

    # host_update specific
    if arguments.func is host_update:
        api_request = host_get(Namespace(func=arguments.func, all=False, fqdn=arguments.fqdn))

        if arguments.name:
            api_request['name'] = arguments.name

        if arguments.group:
            api_request['groups'] = []
            for group in arguments.group:
                groupdata = hostgroup_get(Namespace(func=arguments.func, all=False, name=group))
                if groupdata is None:
                    log.warning("Host group '%s' does not exist", group)
                    continue
                api_request['groups'].append({'groupid': groupdata['groupid']})

        if arguments.template:
            api_request['templates'] = []
            for template in arguments.template:
                templatedata = template_get(Namespace(func=arguments.func, all=False, name=template))
                if templatedata is None:
                    log.warning("Template '%s' does not exist", template)
                    continue
                api_request['templates'].append({'templateid': templatedata['templateid']})

        if arguments.interface_type:
            api_request['interfaces'][0]['type'] = arguments.interface_type
        if arguments.interface_ip:
            api_request['interfaces'][0]['ip'] = arguments.interface_ip
        if api_request['interfaces'][0]:
            api_request['interfaces'][0]['port'] = 10050 if int(api_request['interfaces'][0]['type']) == 1 else 161  # 10050 for agent, 161 for snmp
            api_request['interfaces'][0]['dns'] = arguments.fqdn
            api_request['interfaces'][0]['useip'] = 1  # 0=dns, 1=ip
            api_request['interfaces'][0]['main'] = 1  # 0=not default, 1=default

        if arguments.no_encryption:
            api_request['tls_connect'] = 1
            api_request['tls_accept'] = 1

    # generic
    api_request['host'] = arguments.fqdn
    if arguments.desc:
        api_request['description'] = arguments.desc
    if arguments.encryption:
        api_request['tls_connect'] = 2
        api_request['tls_accept'] = 2
        api_request['tls_psk_identity'] = arguments.fqdn
        api_request['tls_psk'] = gen_psk(arguments.encryption)

    return api_request


def host_create(arguments):
    """Function to create hosts"""
    arguments.all = False
    if host_get(arguments) is None:
        api_request = gen_host_request(arguments)

        try:
            api.host.create(api_request)
        except Exception as error:  # pylint: disable=broad-exception-caught
            log.error("Unable to create host '%s' (%s)", arguments.fqdn, error)
            sys.exit(1)

        log.info("Host '%s' successfully created:", arguments.fqdn)
        print(json.dumps(api_request))
    else:
        log.error("Host '%s' already exists", arguments.fqdn)


def host_delete(arguments):
    """Function to delete hosts"""
    arguments.all = False
    hostdata = host_get(arguments)
    if hostdata is not None:
        try:
            api.host.delete(hostdata['hostid'])
        except Exception as error:  # pylint: disable=broad-exception-caught
            log.error("Could not delete host '%s' (%s)", arguments.fqdn, error)
            sys.exit(1)

        log.info("Host '%s' successfully deleted", arguments.fqdn)
    else:
        log.error("Host '%s' does not exist", arguments.fqdn)


def host_get(arguments):
    """Function to query hosts"""
    if not arguments.all and not arguments.fqdn:
        log.error("Argument -a or -f is required for the 'host get' command")
        sys.exit(1)

    if arguments.all and arguments.fqdn:
        log.error("Cannot accept both -a and -f arguments for the 'host get' command")
        sys.exit(1)

    host = api.host.get(
        search={"host": ['*' if arguments.all else arguments.fqdn]},
        output=['hostid', 'host'],
        selectHostGroups=['groupid', 'name'],
        selectInterfaces=['interfaceid', 'type', 'ip', 'dns', 'port', 'useip', 'main'],
        selectParentTemplates=['templateid', 'name'],
        searchWildcardsEnabled=True,
    )

    try:
        if arguments.func is host_get:
            if arguments.all:
                print(json.dumps(host))
                return None
            print(json.dumps(host[0]))
            return None
        return host[0]
    except Exception:  # pylint: disable=broad-exception-caught
        if arguments.func is host_get:
            log.warning("Host '%s' does not exist", arguments.fqdn)
            sys.exit(1)
        log.debug("Host '%s' does not exist", arguments.fqdn)
        return None


def host_update(arguments):
    """Function to update hosts"""
    arguments.all = False
    hostdata = host_get(arguments)
    if hostdata is not None:
        api_request = gen_host_request(arguments)
        api_request['hostid'] = hostdata['hostid']

        try:
            api.host.update(api_request)
        except Exception as error:  # pylint: disable=broad-exception-caught
            log.error("Unable to update host '%s' (%s)", arguments.fqdn, error)
            sys.exit(1)

        log.info("Host '%s' successfully updated:", arguments.fqdn)
        print(json.dumps(api_request))
    else:
        log.error("Host '%s' does not exist", arguments.fqdn)


def hostgroup_get(arguments):
    """Function to query host groups"""
    hostgroup = api.hostgroup.get(
        search={"name": ['*' if arguments.all else arguments.name]},
        output=['groupid', 'name'],
        searchWildcardsEnabled=True,
    )

    try:
        if arguments.func is hostgroup_get:
            if arguments.all:
                print(json.dumps(hostgroup))
                return None
            print(json.dumps(hostgroup[0]))
            return None
        return hostgroup[0]
    except Exception:  # pylint: disable=broad-exception-caught
        if arguments.func is hostgroup_get:
            log.info("Host group '%s' does not exist", arguments.name)
            return None
        log.debug("Host group '%s' does not exist", arguments.name)
        return None


def template_get(arguments):
    """Function to query templates"""
    template = api.template.get(
        search={"name": ['*' if arguments.all else arguments.name]},
        output=['templateid', 'name', 'description'],
        searchWildcardsEnabled=True,
    )

    try:
        if arguments.func is template_get:
            if arguments.all:
                print(json.dumps(template))
                return None
            return json.dumps(template[0])
        return template[0]
    except Exception:  # pylint: disable=broad-exception-caught
        if arguments.func is template_get:
            log.info("Template '%s' does not exist", arguments.name)
            return None
        log.debug("Template '%s' does not exist", arguments.name)
        return None


def proxy_get(arguments):
    """Function to query proxies"""
    if not arguments.all and not arguments.name:
        log.error("Argument -a or -n is required for the 'proxy get' command")
        sys.exit(1)

    proxy = api.proxy.get(
        search={"host": ['*' if arguments.all else arguments.name]},
        output=['proxyid', 'host', 'description'],
        searchWildcardsEnabled=True,
    )

    try:
        if arguments.func is proxy_get:
            if arguments.all:
                print(json.dumps(proxy))
                return None
            return json.dumps(proxy[0])
        return proxy[0]
    except Exception:  # pylint: disable=broad-exception-caught
        if arguments.func is proxy_get:
            log.info("Proxy '%s' does not exist", arguments.name)
            return None
        log.debug("Proxy '%s' does not exist", arguments.name)
        return None

# Check if config file exists
api_config = configparser.ConfigParser()

try:
    api_config.read_file(open(os.path.expanduser('~/.zabbix-api.ini'), encoding="utf-8"))  # pylint: disable=consider-using-with
except FileNotFoundError:
    log.critical("Config file '~/.zabbix-api.ini' does not exist")
    sys.exit(1)

# Load configuration file
api_config.read(os.path.expanduser('~/.zabbix-api.ini'))

# Check required options
if not api_config['Api']['Url']:
    log.critical("Api URL not found in ~/.zabbix-api.ini")
    sys.exit(1)

if 'Token' not in api_config['Api'] and ('User' not in api_config['Api'] or 'Password' not in api_config['Api']):
    log.critical("No Api credentials (token or username/password) found in ~/.zabbix-api.ini")
    sys.exit(1)

# Parse arguments and start required function
args = parse_args()

# check if debug mode is needed
if args.debug:
    log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)
    log.info("Debug mode enabled")
else:
    log.basicConfig(format="%(levelname)s: %(message)s", level=log.INFO)

# Create an instance of the ZabbixAPI class with the specified authentication details
try:
    if 'Token' in api_config['Api']:
        api = ZabbixAPI(url=api_config['Api']['Url'], token=api_config['Api']['Token'])
    else:
        api = ZabbixAPI(url=api_config['Api']['Url'], user=api_config['Api']['User'], password=api_config['Api']['Password'])
except Exception as Error:  # pylint: disable=broad-exception-caught
    log.critical("Could not login to zabbix api (%s)", Error)
    sys.exit(1)

# Check if authentication is still valid
if api.check_auth():

    # call whatever function was selected
    args.func(args)

    # When token is used, calling api.logout() is not necessary
    if 'Token' not in api_config['Api']:
        api.logout()
