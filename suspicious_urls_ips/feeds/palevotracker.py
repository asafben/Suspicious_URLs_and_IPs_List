#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import MALWARE_TYPE

__url__ = "https://palevotracker.abuse.ch/blocklists.php?download=combinedblocklist"
__check__ = "Palevo"
__info__ = "palevo (malware)"
__reference__ = "abuse.ch"
__type__ = IP_TYPE
__classification__ = MALWARE_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
                retval[line] = (__info__, __reference__, __type__, __classification__)
            else:
                retval[line] = (__info__, __reference__, __type__, __classification__)

    return retval
