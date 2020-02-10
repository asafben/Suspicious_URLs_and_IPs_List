#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import MALWARE_TYPE

__url__ = "https://www.talosintelligence.com/feeds/ip-filter.blf"
__check__ = ".1"
__info__ = "bad reputation"
__reference__ = "talosintelligence.com"
__type__ = IP_TYPE
__classification__ = MALWARE_TYPE


# Reference: http://blog.snort.org/2015/09/ip-blacklist-feed-has-moved-locations.html
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
