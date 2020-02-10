#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import MALWARE_TYPE

__url__ = "https://github.com/JR0driguezB/malware_configs"
__check__ = "mcconf"
__info__ = "trickbot (malware)"
__reference__ = "github.com/JR0driguezB"
__type__ = IP_TYPE
__classification__ = MALWARE_TYPE


def fetch():
    retval = {}
    content = retrieve_content("https://github.com/JR0driguezB/malware_configs/tree/master/TrickBot/mcconf_files")

    if __check__ in content:
        last = re.findall(r"config.conf_\d+.xml", content)[-1]
        content = retrieve_content("https://raw.githubusercontent.com/JR0driguezB/malware_configs/master/TrickBot/mcconf_files/%s" % last)
        if __check__ in content:
            for match in re.finditer(r"<srv>([\d.]+)", content):
                retval[match.group(1)] = (__info__, __reference__, __type__, __classification__)

    return retval
