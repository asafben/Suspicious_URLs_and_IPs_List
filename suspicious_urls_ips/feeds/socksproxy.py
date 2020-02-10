#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import PROXY_TYPE

__url__ = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/socks_proxy_7d.ipset"
__check__ = "socks_proxy_7d"
__info__ = "proxy (suspicious)"
__reference__ = "socks-proxy.net"
__type__ = IP_TYPE
__classification__ = PROXY_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line] = (__info__, __reference__, __type__, __classification__)

    return retval
