#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import CNC_TYPE

__url__ = "https://sslbl.abuse.ch/blacklist/sslipblacklist.rules"
__check__ = "abuse.ch SSLBL"
__reference__ = "abuse.ch"
__type__ = IP_TYPE
__classification__ = CNC_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            match = re.search(r"any -> \[([\d.]+)\] (\d+) .+likely ([^)]+) C&C", line)
            if match:
                retval["%s:%s" % (match.group(1), match.group(2))] = ("%s (malware)" % match.group(3).lower(), __reference__, __type__, __classification__)

    return retval
