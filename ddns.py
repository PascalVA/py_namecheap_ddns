#!/usr/bin/env python3
#
# Simple script that updats a dynamic dns record on namecheap
# It randomly selects a provider to get your current public ip address
# Currently used ip providers: 
#   - httpbin.org
#   - ipfy.org
#   - wtfismyip.com

from __future__ import print_function
import os
import sys
import logging, logging.handlers
import requests
from random import shuffle
from functools import wraps
from re import search
from socket import gethostbyname

SIMPLE_IP_REGEX = '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'


def ip_json(url, json_key):
    return requests.get(url).json().get(json_key, None)


def search_ip(ip_str):
    ip = search(SIMPLE_IP_REGEX, ip_str)
    if ip:
       return ip.group()
    return None


def ip_httpbin_org():
    return search_ip(ip_json('https://httpbin.org/ip', 'origin'))


def ip_ipfy_org():
    return search_ip(ip_json('https://api.ipify.org/?format=json', 'ip'))


def ip_wtfismyip_com():
    return search_ip(ip_json('https://ipv4.wtfismyip.com/json', 'YourFuckingIPAddress'))


def get_ip():
    """Get the ip address from a random provider
       Try them all sequentially until one succeeds
    """
    ip = None
    providers = [
        {'name': 'httpbin.org', 'func': ip_httpbin_org},
        {'name': 'ipfy.org', 'func': ip_ipfy_org},
        {'name': 'wtfismyip.com', 'func': ip_wtfismyip_com}
    ]
    shuffle(providers)

    for provider in providers:
        logger.info('DDNS: Getting public ip (%s)' % provider["name"])
        try:
            ip = provider["func"]()
        except:
            continue
        break
    if ip:
        return ip
    return None


# Setup login
logging.basicConfig(level=logging.INFO)
logger  = logging.getLogger('ddns')
handler = logging.handlers.SysLogHandler(address = '/dev/log')
logger.addHandler(handler)

# Config from environment
ddns_url = os.environ.get('DDNS_URL') 
ddns_password = os.environ.get('DDNS_PASSWORD')
ddns_full_domain = os.environ.get('DDNS_FULL_DOMAIN')

registered_ip = None
try:
    registered_ip = gethostbyname(ddns_full_domain)
except:
    logger.warning('DDNS: Unable to resolve %s, trying to update anyway...' % ddns_full_domain)

ip = get_ip()
if not registered_ip or registered_ip != ip:
    split_domain = ddns_full_domain.split('.') 
    url = "https://dynamicdns.park-your-domain.com/update"
    params = {
      'host'    : split_domain[0],
      'domain'  : '.'.join(split_domain[1:]),
      'password': ddns_password,
      'ip'      : ip
    }
    result = requests.get(url, params=params)
    
    if not search("<ErrCount>0</ErrCount>", result.text):
      logger.error('DDNS: Unable to update ip address (%s)' % ip)
      sys.exit(1)
    logger.info('DDNS: IP Address changed, updated record to ' + ip)
else:
    logger.info('DDNS: IP Address already up to date')
