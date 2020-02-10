#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import DOMAIN_TYPE
from antivirus.lists_based_engine.settings import CNC_TYPE

__url__ = "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt"
__check__ = "Master Feed"
__reference__ = "bambenekconsulting.com"
__type__ = DOMAIN_TYPE
__classification__ = CNC_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"(?m)^([^,#]+),Domain used by ([^,/]+)", content):
            retval[match.group(1)] = ("%s (malware)" % match.group(2).lower().strip(),
                                      __reference__,
                                      __type__,
                                      __classification__)

    return retval
