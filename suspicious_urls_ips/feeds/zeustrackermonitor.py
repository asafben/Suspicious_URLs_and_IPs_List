#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import DOMAIN_TYPE
from antivirus.lists_based_engine.settings import MALWARE_TYPE

__url__ = "https://zeustracker.abuse.ch/monitor.php?filter=all"
__check__ = "ZeuS Tracker"
__reference__ = "abuse.ch"
__type__ = DOMAIN_TYPE
__classification__ = MALWARE_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r'<td>([^<]+)</td><td><a href="/monitor.php\?host=([^"]+)', content):
            retval[match.group(2)] = (match.group(1).lower() + " (malware)", __reference__, __type__, __classification__)

    return retval
