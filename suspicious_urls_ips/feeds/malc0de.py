#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import DOMAIN_TYPE
from antivirus.lists_based_engine.settings import MALWARE_TYPE

__url__ = "https://malc0de.com/bl/ZONES"
__check__ = "malc0de"
__info__ = "malware distribution"
__reference__ = "malc0de.com"
__type__ = DOMAIN_TYPE
__classification__ = MALWARE_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r'(?i)zone\s+"([^"]+)"\s+{', content):
            retval[match.group(1)] = (__info__, __reference__, __type__, __classification__)

    return retval
