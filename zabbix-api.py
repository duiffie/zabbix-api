#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
File: zabbix-api.py
Author: Marco van Duijvenbode
Date: 28/04/2024

Description: Wrapper around the zabbix_utils python library
"""

# Futures
from argparse import Namespace
from zabbix_utils import ZabbixAPI

# Built-in/Generic Imports
import argparse
import configparser
import json
import os
import secrets
import sys

# Libs
import logging as log


# Argument parser function
def parse_args():
    # create the top-level parser
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
    parser_host_create.add_argument('-p', '--template', type=str, action='append', help='Add this template to the host. Can be used multiple times')
    parser_host_create.add_argument('-it', '--interface_type', type=int, choices=[1, 2, 3, 4], help='Interface type to create. 1 = Agent, 2 = SNMP, 3 = IPMI, 4 = JMX', required=True)
    parser_host_create.add_argument('-ii', '--interface_ip', type=str, help='IP-address used by the interface', required=True)
    parser_host_create.add_argument('-t', '--tls', type=int, choices=[32, 64, 128, 256, 512], help='Encrypt connections to the host with the specified keylength')
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
    parser_host_update.add_argument('-p', '--template', type=str, action='append', help='Add this template to the host. Can be used multiple times')
    parser_host_update.add_argument('-it', '--interface_type', type=int, choices=[1, 2, 3, 4], help='Interface type. 1 = Agent, 2 = SNMP, 3 = IPMI, 4 = JMX')
    parser_host_update.add_argument('-ii', '--interface_ip', type=str, help='IP-address used by the interface')
    parser_host_update.add_argument('-nt', '--no_tls', action="store_true", help="Don't encrypt connections to the host")
    parser_host_update.add_argument('-t', '--tls', type=int, choices=[32, 64, 128, 256, 512], help='Encrypt connections to the host with the specified keylength')
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
    DESCRIPTION = 'Get host group objects from Zabbix'
    parser_template_get = template_subparsers.add_parser('get', description=DESCRIPTION, help=DESCRIPTION)
    parser_template_get.add_argument('-a', '--all', action='store_true', help='Retrieve all host groups')
    parser_template_get.add_argument('-n', '--name', type=str, help='Template name')
    parser_template_get.add_argument('-v', '--verbose', action='count', help='Be more verbose')
    parser_template_get.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser_template_get.set_defaults(func=template_get)

    # parse the args
    args = parser.parse_args()

    return args


# PSK generator function
def gen_psk(length):
    return secrets.token_hex(length//2)


# Host request generator function
def gen_host_request(args):
    api_request = {}

    # host_create specific
    if args.func == host_create:
        if args.name:
            api_request['name'] = args.name

        api_request['groups'] = []

        for group in args.group:
            groupdata = hostgroup_get(Namespace(func=args.func, all=False, name=group))
            if groupdata is None:
                log.warning("Host group '" + group + "' does not exist")
                continue
            api_request['groups'].append({'groupid': groupdata['groupid']})

        if args.template is not None:
            api_request['templates'] = []
            for template in args.template:
                templatedata = template_get(Namespace(func=args.func, all=False, name=template))
                if groupdata is None:
                    log.warning("Template '" + group + "' does not exist")
                    continue
                api_request['templates'].append({'templateid': templatedata['templateid']})

        api_request['interfaces'] = {}
        api_request['interfaces']['type'] = args.interface_type  # 1=Agent, 2=SNMP
        api_request['interfaces']['ip'] = args.interface_ip
        api_request['interfaces']['dns'] = args.fqdn
        api_request['interfaces']['port'] = 10050 if api_request['interfaces']['type'] == 1 else 161  # 10050 for agent, 161 for snmp
        api_request['interfaces']['useip'] = 1  # 0=dns, 1=ip
        api_request['interfaces']['main'] = 1  # 0=not default, 1=default

    # host_update specific
    if args.func == host_update:
        api_request = host_get(Namespace(func=args.func, all=False, fqdn=args.fqdn))

        if args.name:
            api_request['name'] = args.name

        if args.group:
            api_request['groups'] = []
            for group in args.group:
                groupdata = hostgroup_get(Namespace(func=args.func, all=False, name=group))
                if groupdata is None:
                    log.warning("Host group '" + group + "' does not exist")
                    continue
                api_request['groups'].append({'groupid': groupdata['groupid']})

        if args.template:
            api_request['templates'] = []
            for template in args.template:
                templatedata = template_get(Namespace(func=args.func, all=False, name=template))
                if templatedata is None:
                    log.warning("Template '" + template + "' does not exist")
                    continue
                api_request['templates'].append({'templateid': templatedata['templateid']})

        if args.interface_type:
            api_request['interfaces'][0]['type'] = args.interface_type
        if args.interface_ip:
            api_request['interfaces'][0]['ip'] = args.interface_ip
        if api_request['interfaces'][0]:
            api_request['interfaces'][0]['port'] = 10050 if int(api_request['interfaces'][0]['type']) == 1 else 161  # 10050 for agent, 161 for snmp
            api_request['interfaces'][0]['dns'] = args.fqdn
            api_request['interfaces'][0]['useip'] = 1  # 0=dns, 1=ip
            api_request['interfaces'][0]['main'] = 1  # 0=not default, 1=default

        if args.no_tls:
            api_request['tls_connect'] = 1
            api_request['tls_accept'] = 1

    # generic
    api_request['host'] = args.fqdn
    if args.desc:
        api_request['description'] = args.desc
    if args.tls:
        api_request['tls_connect'] = 2
        api_request['tls_accept'] = 2
        api_request['tls_psk_identity'] = args.fqdn
        api_request['tls_psk'] = gen_psk(args.tls)

    return api_request


# Host creator function
def host_create(args):
    args.all = False
    if host_get(args) is None:
        api_request = gen_host_request(args)

        try:
            api.host.create(api_request)
        except Exception as error:
            log.error("Unable to create host '" + args.fqdn + "' (%s)", error)
            sys.exit(1)

        if args.tls:
            log.info("Host '" + args.fqdn + "' successfully created (psk: '" + api_request['tls_psk'] + "')")
        else:
            log.info("Host '" + args.fqdn + "' successfully created")
    else:
        log.error("Host '" + args.fqdn + "' already exists")


# Function host_delete
def host_delete(args):
    args.all = False
    hostdata = host_get(args)
    if hostdata is not None:
        try:
            api.host.delete(hostdata['hostid'])
        except Exception as error:
            log.error("Could not delete host '" + args.fqdn + "' (%s)", error)
            sys.exit(1)

        log.info("Host '" + args.fqdn + "' successfully deleted")
    else:
        log.error("Host '" + args.fqdn + "' does not exist")


# Function host_get
def host_get(args):
    if not args.all and not args.fqdn:
        log.error("Argument -a or -f is required for the 'host get' command")
        sys.exit(1)

    if args.all and args.fqdn:
        log.error("Cannot accept both -a and -f arguments for the 'host get' command")
        sys.exit(1)

    host = api.host.get(
        search={"host": ['*' if args.all else args.fqdn]},
        output=['hostid', 'host'],
        selectHostGroups=['groupid', 'name'],
        selectInterfaces=['interfaceid', 'type', 'ip', 'dns', 'port', 'useip', 'main'],
        selectParentTemplates=['templateid', 'name'],
        searchWildcardsEnabled=True,
    )

    try:
        if args.func == host_get:
            if args.all:
                print(json.dumps(host))
            else:
                print(json.dumps(host[0]))
        else:
            return host[0]
    except:
        if args.func == host_get:
            log.warning("Host '" + args.fqdn + "' does not exist")
            sys.exit(1)
        else:
            log.debug("Host '" + args.fqdn + "' does not exist")


# Function host_update
def host_update(args):
    args.all = False
    hostdata = host_get(args)
    if hostdata is not None:
        api_request = gen_host_request(args)
        api_request['hostid'] = hostdata['hostid']

        try:
            api.host.update(api_request)
        except Exception as error:
            log.error("Unable to update host '" + args.fqdn + "' (%s)", error)
            sys.exit(1)

        if args.tls:
            log.info("Host '" + args.fqdn + "' successfully updated (psk: '" + api_request['tls_psk'] + "')")
        else:
            log.info("Host '" + args.fqdn + "' successfully updated")
    else:
        log.error("Host '" + args.fqdn + "' does not exist")


# Function hostgroup_get
def hostgroup_get(args):
    hostgroup = api.hostgroup.get(
        search={"name": ['*' if args.all else args.name]},
        output=['groupid', 'name'],
        searchWildcardsEnabled=True,
    )

    try:
        if args.func == hostgroup_get:
            if args.all:
                print(json.dumps(hostgroup))
            else:
                print(json.dumps(hostgroup[0]))
        else:
            return hostgroup[0]
    except:
        if args.func == hostgroup_get:
            log.info("Host group '" + args.name + "' does not exist")
        else:
            log.debug("Host group '" + args.name + "' does not exist")


# Function template_get
def template_get(args):
    template = api.template.get(
        search={"name": ['*' if args.all else args.name]},
        output=['templateid', 'name', 'description'],
        searchWildcardsEnabled=True,
    )

    try:
        if args.func == template_get:
            if args.all:
                print(json.dumps(template))
            else:
                return json.dumps(template[0])
        else:
            return template[0]
    except:
        if args.func == template_get:
            log.info("Template '" + args.name + "' does not exist")
        else:
            log.debug("Template '" + args.name + "' does not exist")


# Check if config file exists
api_config = configparser.ConfigParser()

try:
    api_config.read_file(open(os.path.expanduser('~/.zabbix-api.ini')))
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
except Exception as error:
    log.critical("Could not login to zabbix api (%s)", error)
    sys.exit(1)

# Check if authentication is still valid
if api.check_auth():

    # call whatever function was selected
    args.func(args)

    # When token is used, calling api.logout() is not necessary
    if 'Token' not in api_config['Api']:
        api.logout()
