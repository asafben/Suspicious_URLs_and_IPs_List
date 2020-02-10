#!/usr/bin/env python

"""
See the file 'LICENSE' for copying permission
"""

from antivirus.lists_based_engine.update import retrieve_content
from antivirus.lists_based_engine.settings import IP_TYPE
from antivirus.lists_based_engine.settings import ATTACKER_TYPE

__url__ = "https://dataplane.org/*.txt"
__check__ = "DataPlane.org"
__info__ = "known attacker"
__reference__ = "dataplane.org"
__type__ = IP_TYPE
__classification__ = ATTACKER_TYPE


def fetch():
    retval = {}
    for url in ("https://dataplane.org/dnsrd.txt", "https://dataplane.org/dnsrdany.txt", "https://dataplane.org/dnsversion.txt", "https://dataplane.org/sipinvitation.txt", "https://dataplane.org/sipquery.txt", "https://dataplane.org/sipregistration.txt", "https://dataplane.org/sshclient.txt", "https://dataplane.org/sshpwauth.txt", "https://dataplane.org/vncrfb.txt"):
        content = retrieve_content(url)

        if __check__ in content:
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#') or '.' not in line or '|' not in line:
                    continue
                retval[line.split('|')[2].strip()] = (__info__, __reference__, __type__, __classification__)

    return retval
