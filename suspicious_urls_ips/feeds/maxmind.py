#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import ATTACKER_TYPE

__url__ = "https://www.maxmind.com/en/high-risk-ip-sample-list"
__check__ = "Sample List of Higher Risk IP Addresses"
__info__ = "bad reputation (suspicious)"
__reference__ = "maxmind.com"
__type__ = IP_TYPE
__classification__ = ATTACKER_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"high-risk-ip-sample/([\d.]+)", content):
            retval[match.group(1)] = (__info__, __reference__, __type__, __classification__)

    return retval
