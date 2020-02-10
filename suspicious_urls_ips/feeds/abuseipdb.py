#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import ATTACKER_TYPE

__url__ = "https://www.abuseipdb.com/statistics"
__check__ = "distinct users"
__info__ = "known attacker"
__reference__ = "abuseipdb.com"
__type__ = IP_TYPE
__classification__ = ATTACKER_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for ip in re.findall(r">(\d+\.\d+\.\d+\.\d+)</a></b> \(\d+ reports from \d+ distinct users\)", content):
            retval[ip] = (__info__, __reference__, __type__, __classification__)

    return retval
