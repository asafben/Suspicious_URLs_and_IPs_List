#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.update import NAME
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import ATTACKER_TYPE

__url__ = "https://blocklist.greensnow.co/greensnow.txt"
__check__ = ".1"
__info__ = "known attacker"
__reference__ = "greensnow.co"
__type__ = IP_TYPE
__classification__ = ATTACKER_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__, headers={"User-agent": NAME})  # having problems with database (appending error messages to the end of gzip stream)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line] = (__info__, __reference__, __type__, __classification__)

    return retval
