#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import gzip
import os
import re
import tempfile

from antivirus.lists_based_engine.update import NAME
from antivirus.lists_based_engine.update import TIMEOUT
from antivirus.lists_based_engine.update import UNICODE_ENCODING
from antivirus.lists_based_engine.settings import DOMAIN_TYPE
from antivirus.lists_based_engine.settings import CNC_TYPE

from antivirus.lists_based_engine.thirdparty import six
from antivirus.lists_based_engine.thirdparty.six.moves import urllib as _urllib

__url__ = "https://osint.bambenekconsulting.com/feeds/dga-feed.txt"
__check__ = "Domain used by"
__reference__ = "bambenekconsulting.com"
__type__ = DOMAIN_TYPE
__classification__ = CNC_TYPE


def _open():
    retval = None

    try:
        req = _urllib.request.Request(__url__, None, {"User-agent": NAME, "Accept-encoding": "gzip"})
        resp = _urllib.request.urlopen(req, timeout=TIMEOUT)
        handle, filename = tempfile.mkstemp()

        bsize = 1024 * 1024
        while True:
            content = resp.read(bsize)
            if content:
                os.write(handle, content)
                if len(content) != bsize:
                    break
            else:
                break

        os.close(handle)
        retval = gzip.open(filename)

    except:
        pass

    return retval


def fetch():
    retval = {}
    handle = _open()

    if handle:
        try:
            while True:
                line = handle.readline()

                if not line:
                    break

                if six.PY3:
                    line = line.decode(UNICODE_ENCODING)

                match = re.search(r"\A([^,\s]+),Domain used by ([^ ]+)", line)
                if match and '.' in match.group(1):
                    retval[match.group(1)] = ("%s dga (malware)" % match.group(2).lower(),
                                              __reference__,
                                              __type__,
                                              __classification__)
        except:
            pass
        finally:
            try:
                os.remove(handle.filename)
            except (IOError, OSError):
                pass

    return retval
