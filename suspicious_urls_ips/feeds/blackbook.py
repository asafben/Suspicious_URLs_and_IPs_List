#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import DOMAIN_TYPE
from antivirus.lists_based_engine.settings import MALWARE_TYPE

__url__ = "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.csv"
__check__ = "Malware"
__reference__ = "github.com/stamparm/blackbook"
__type__ = DOMAIN_TYPE
__classification__ = MALWARE_TYPE


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line.split(',')[0].strip()] = ("%s (malware)" % line.split(',')[1].strip(), __reference__, __type__, __classification__)

    return retval
