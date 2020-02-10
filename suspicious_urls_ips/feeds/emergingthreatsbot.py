#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import CNC_TYPE

__url__ = "https://rules.emergingthreats.net/open/suricata/rules/botcc.rules"
__check__ = "CnC Server"
__info__ = "potential malware site"
__reference__ = "emergingthreats.net"
__type__ = IP_TYPE
__classification__ = CNC_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"\d+\.\d+\.\d+\.\d+", content):
            retval[match.group(0)] = (__info__, __reference__, __type__, __classification__)

    return retval
