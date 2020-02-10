#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import CRAWLER_TYPE

__url__ = "https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt"
__check__ = "ADDRESSES DATABASE"
__info__ = "crawler"
__reference__ = "myip.ms"
__type__ = IP_TYPE
__classification__ = CRAWLER_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"deny from (\d+\.\d+\.\d+\.\d+)", content):
            retval[match.group(1)] = (__info__, __reference__, __type__, __classification__)

    return retval
