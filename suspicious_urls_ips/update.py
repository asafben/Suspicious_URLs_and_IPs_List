from suspicious_urls_ips.thirdparty import six
from suspicious_urls_ips.thirdparty.six.moves import urllib as _urllib
import zlib
import gzip
import io
import sys
import os
import inspect
import re
import csv
import codecs


if sys.version_info >= (3, 0):
    xrange = range
else:
    xrange = xrange

from suspicious_urls_ips.settings import UNICODE_ENCODING
from suspicious_urls_ips.settings import TIMEOUT
from suspicious_urls_ips.settings import NAME
from suspicious_urls_ips.settings import FEEDS_DIR
from suspicious_urls_ips.settings import DISABLED_FEEDS
from suspicious_urls_ips.settings import LOW_PRIORITY_INFO_KEYWORDS
from suspicious_urls_ips.settings import HIGH_PRIORITY_INFO_KEYWORDS
from suspicious_urls_ips.settings import HIGH_PRIORITY_REFERENCES
from suspicious_urls_ips.settings import WHITELIST
from suspicious_urls_ips.settings import WHITELIST_RANGES
from suspicious_urls_ips.settings import USER_WHITELIST
from suspicious_urls_ips.settings import BAD_TRAIL_PREFIXES
from suspicious_urls_ips.settings import OUTPUT_FILE_PATH
from suspicious_urls_ips.settings import IS_WIN
from suspicious_urls_ips.settings import DOMAIN_TYPE
from suspicious_urls_ips.settings import IP_TYPE


def load_module(module):
    # module_path = "mypackage.%s" % module
    module_path = "suspicious_urls_ips.feeds." + module

    if module_path in sys.modules:
        return sys.modules[module_path]

    return __import__(module_path, fromlist=[module])


def get_ex_message(ex):
    ret_val = None

    if getattr(ex, "message", None):
        ret_val = ex.message
    elif getattr(ex, "msg", None):
        ret_val = ex.msg
    elif getattr(ex, "args", None):
        for candidate in ex.args[::-1]:
            if isinstance(candidate, six.string_types):
                ret_val = candidate
                break

    return ret_val


def _chown(filepath):
    if not IS_WIN and os.path.exists(filepath):
        try:
            os.chown(filepath, int(os.environ.get("SUDO_UID", -1)), int(os.environ.get("SUDO_GID", -1)))
        except Exception as ex:
            print("[!] chown problem with '%s' ('%s')" % (filepath, ex))


def _fopen(filepath, mode="rb", opener=open):
    retval = opener(filepath, mode)
    if "w+" in mode:
        _chown(filepath)
    return retval


def retrieve_content(url, data=None, headers=None):
    """
    Retrieves page content from given URL
    """

    try:
        req = _urllib.request.Request("".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in
                                              xrange(len(url))), data, headers or {"User-agent": NAME,
                                                                                   "Accept-encoding": "gzip, deflate"})
        resp = _urllib.request.urlopen(req, timeout=TIMEOUT)
        ret_val = resp.read()
        encoding = resp.headers.get("Content-Encoding")

        if encoding:
            if encoding.lower() == "deflate":
                data = io.BytesIO(zlib.decompress(ret_val, -15))
            elif encoding.lower() == "gzip":
                data = gzip.GzipFile("", "rb", 9, io.BytesIO(ret_val))
            ret_val = data.read()
    except Exception as ex:
        ret_val = ex.read() if hasattr(ex, "read") else (get_ex_message(ex) or "")

        if url.startswith("https://") and "handshake failure" in ret_val:
            return retrieve_content(url.replace("https://", "http://"), data, headers)

    ret_val = ret_val or b""

    if six.PY3 and isinstance(ret_val, bytes):
        ret_val = ret_val.decode(UNICODE_ENCODING, errors="replace")

    return ret_val


def make_mask(bits):
    return 0xffffffff ^ (1 << 32 - bits) - 1


def addr_to_int(value):
    _ = value.split('.')
    return (int(_[0]) << 24) + (int(_[1]) << 16) + (int(_[2]) << 8) + int(_[3])


def int_to_addr(value):
    return '.'.join(str(value >> n & 0xff) for n in (24, 16, 8, 0))


def read_whitelist():
    WHITELIST.clear()
    WHITELIST_RANGES.clear()

    if USER_WHITELIST and os.path.isfile(USER_WHITELIST):
        with open(USER_WHITELIST, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                elif re.search(r"\A\d+\.\d+\.\d+\.\d+/\d+\Z", line):
                    try:
                        prefix, mask = line.split('/')
                        WHITELIST_RANGES.add((addr_to_int(prefix), make_mask(int(mask))))
                    except (IndexError, ValueError):
                        WHITELIST.add(line)
                else:
                    WHITELIST.add(line)


def check_whitelisted(trail):
    if trail in WHITELIST:
        return True

    if trail and trail[0].isdigit():
        try:
            _ = addr_to_int(trail)
            for prefix, mask in WHITELIST_RANGES:
                if _ & mask == prefix:
                    return True
        except (IndexError, ValueError):
            pass

    return False


"""
    TODO: Add future support for feeds:
	
    https://iplists.firehol.org/ (includes spamhaus)
    https://www.spamhaus.org/drop/drop.lasso
    https://hosts-file.net/?s=Download
    
    http://cinsscore.com/list/ci-badguys.txt
    http://blocklist.greensnow.co/greensnow.txt
    http://malc0de.com/bl/IP_Blacklist.txt
    https://rules.emergingthreats.net/blockrules/compromised-ips.txt
    https://feodotracker.abuse.ch/downloads/ipblocklist.csv (now we take recommended block list, to check)
    https://pgl.yoyo.org/adservers/iplist.php?format=&showintro=0 (ads)
    https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_7d.ipset
    https://www.dan.me.uk/torlist/?exit (tor exit nodes)
    https://www.maxmind.com/es/proxy-detection-sample-list
    https://www.projecthoneypot.org/list_of_ips.php?t=h
    https://www.projecthoneypot.org/list_of_ips.php?t=s
    https://www.projecthoneypot.org/list_of_ips.php?t=d
    https://www.projecthoneypot.org/list_of_ips.php?t=p
    http://www.unsubscore.com/blacklist.txt
    https://raw.githubusercontent.com/mitchellkrogza/Suspicious.Snooping.Sniffing.Hacking.IP.Addresses/master/ips.list
    https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list
    https://github.com/mitchellkrogza/Phishing.Database
    http://dsi.ut-capitole.fr/blacklists/download/adult.tar.gz
    http://dsi.ut-capitole.fr/blacklists/download/agressif.tar.gz
    http://dsi.ut-capitole.fr/blacklists/download/cryptojacking.tar.gz
    http://dsi.ut-capitole.fr/blacklists/download/ddos.tar.gz
    http://dsi.ut-capitole.fr/blacklists/download/hacking.tar.gz
    http://dsi.ut-capitole.fr/blacklists/download/phishing.tar.gz
    http://dsi.ut-capitole.fr/blacklists/download/warez.tar.gz
	
	https://github.com/mitchellkrogza/Ultimate.Hosts.Blacklist#credits--thanks
"""

def update_trails():
    """
    Update trails from feeds
    """
    success = False
    trails = {}
    duplicates = {}
    filenames = sorted([file for file in os.listdir(FEEDS_DIR) if file.endswith('.py')])

    if len(DISABLED_FEEDS) > 0:
        filenames = [filename for filename in filenames if filename.split('.')[0] not in DISABLED_FEEDS]

    for i, filename in enumerate(filenames):
        try:
            no_ext = str(filename.split(".py")[0])
            module = load_module(no_ext)
        except (ImportError, SyntaxError) as ex:
            print("[x] something went wrong during import of feed file '%s' ('%s')" % (filename, ex))
            continue

        for name, function in inspect.getmembers(module, inspect.isfunction):
            if name == "fetch":
                url = module.__url__  # Note: to prevent "SyntaxError: can not delete variable 'module' referenced in nested scope"

                print(" [o] '%s'%s" % (url, " " * 20 if len(url) < 20 else ""))
                sys.stdout.write("[?] progress: %d/%d (%d%%)\r" % (i, len(filenames), i * 100 // len(filenames)))
                sys.stdout.flush()

                num_attempts = 5
                for attempt in range(1, num_attempts+1):
                    try:
                        results = function()
                        for item in results.items():
                            if item[0].startswith("www.") and '/' not in item[0]:
                                item = [item[0][len("www."):], item[1]]
                            if item[0] in trails:
                                if item[0] not in duplicates:
                                    duplicates[item[0]] = {(item[1][1], item[1][3])}
                                duplicates[item[0]].add((item[1][1], item[1][3]))
                            if not (item[0] in trails and (
                                    any(_ in item[1][0] for _ in LOW_PRIORITY_INFO_KEYWORDS) or trails[item[0]][
                                1] in HIGH_PRIORITY_REFERENCES)) or (
                                    item[1][1] in HIGH_PRIORITY_REFERENCES and "history" not in item[1][0]) or any(
                                    _ in item[1][0] for _ in HIGH_PRIORITY_INFO_KEYWORDS):
                                trails[item[0]] = item[1]
                        if not results and not any(_ in url for _ in ("abuse.ch", "cobaltstrike")):
                            print("[x] something went wrong during remote data retrieval ('%s')" % url)
                            print("[..x] Failed Attempt " + str(attempt) + "/" + str(num_attempts))
                            continue
                        break
                    except Exception as ex:
                        print("[x] something went wrong during processing of feed file '%s' ('%s')" % (filename, ex))

        try:
            sys.modules.pop(module.__name__)
            del module
        except Exception:
            pass

    print("[i] post-processing trails (this might take a while)...")
    # basic cleanup
    for key in list(trails.keys()):
        if key not in trails:
            continue

        try:
            _key = key.decode(UNICODE_ENCODING) if isinstance(key, bytes) else key
            _key = _key.encode("idna")
            if six.PY3:
                _key = _key.decode(UNICODE_ENCODING)
            if _key != key:  # for domains with non-ASCII letters (e.g. phishing)
                trails[_key] = trails[key]
                del trails[key]
                key = _key
        except:
            pass

        if not key or re.search(r"\A(?i)\.?[a-z]+\Z", key) and not any(_ in trails[key][1] for _ in ("custom", "static")):
            del trails[key]
            continue
        if re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", key):
            if any(_ in trails[key][0] for _ in ("parking site", "sinkhole")) and key in duplicates:  # Note: delete (e.g.) junk custom trails if static trail is a sinkhole
                del duplicates[key]
            # if trails[key][0] == "malware":
            #     trails[key] = ("potential malware site", trails[key][1])
        # if trails[key][0] == "ransomware":
        #     trails[key] = ("ransomware (malware)", trails[key][1])
        if key.startswith("www."):
            _ = trails[key]
            del trails[key]
            key = key[len("www."):]
            if key:
                trails[key] = _
        if '?' in key and not key.startswith('/'):
            _ = trails[key]
            del trails[key]
            key = key.split('?')[0]
            if key:
                trails[key] = _
        if key.startswith('http://www.'):
            _ = trails[key]
            del trails[key]
            key = key[len("http://www."):]
            if key:
                trails[key] = _
        if key.startswith('https://www.'):
            _ = trails[key]
            del trails[key]
            key = key[len("https://www."):]
            if key:
                trails[key] = _
        if '//' in key:
            _ = trails[key]
            del trails[key]
            key = key.replace('//', '/')
            trails[key] = _
        if key != key.lower():
            _ = trails[key]
            del trails[key]
            key = key.lower()
            trails[key] = _
        if key.endswith('/'):
            _ = trails[key]
            del trails[key]
            key = key[:-1]
            if key:
                trails[key] = _
        # if key in duplicates:
        #     _ = trails[key]
        #     others = sorted(duplicates[key] - set((_[1],)))
        #     if others and " (+" not in _[1]:
        #         trails[key] = (_[0], "%s (+%s)" % (_[1], ','.join(others)))

    read_whitelist()

    for key in list(trails.keys()):
        if check_whitelisted(key) or any(key.startswith(_) for _ in BAD_TRAIL_PREFIXES):
            del trails[key]
        else:
            try:
                key.decode("utf8") if hasattr(key, "decode") else key.encode("utf8")
                trails[key][0].decode("utf8") if hasattr(trails[key][0], "decode") else trails[key][0].encode("utf8")
                trails[key][1].decode("utf8") if hasattr(trails[key][1], "decode") else trails[key][1].encode("utf8")
            except UnicodeError:
                del trails[key]

    aggregated_trials = {}
    try:
        if trails:

            aggregated_trials = {"domains": {}, "ips": {}}

            for resource, params in trails.items():
                info = params[0]
                reference = params[1]
                type = params[2]
                classification = params[3]

                if type == DOMAIN_TYPE:
                    aggregated_trials['domains'][resource] = {'info': info,
                                                              'engines': {(reference, classification)},
                                                              'engines_count': 1}
                    if resource in duplicates.keys():
                        aggregated_trials['domains'][resource]['engines'].union(duplicates[resource])
                        aggregated_trials['domains'][resource]['engines_count'] = len(aggregated_trials['domains'][resource]['engines'])

                elif type == IP_TYPE:
                    aggregated_trials['ips'][resource] = {'info': info,
                                                          'engines': {(reference, classification)},
                                                          'engines_count': 1}
                    if resource in duplicates.keys():
                        aggregated_trials['ips'][resource]['engines'].union(duplicates[resource])
                        aggregated_trials['ips'][resource]['engines_count'] = len(aggregated_trials['ips'][resource]['engines'])

            with _fopen(OUTPUT_FILE_PATH, "w+b" if six.PY2 else "w+", open if six.PY2 else codecs.open) as f:
                writer = csv.writer(f, delimiter=',', quotechar='\"', quoting=csv.QUOTE_MINIMAL)
                for trail in trails:
                    row = (trail, trails[trail][0], trails[trail][1])
                    writer.writerow(row)

            success = True
    except Exception as ex:
        print("[x] something went wrong during trails file write '%s' ('%s')" % (OUTPUT_FILE_PATH, ex))

    # Move URLs to their own category. Then, extract their domain and add it to 'domains' if not exists.
    aggregated_trials['urls'] = {}
    for domain in list(aggregated_trials['domains'].keys()):
        full_url = None
        domain_url = None
        if len(domain.split('/')) > 1:
            full_url = domain
            domain_url = domain.split('/')[0].split(':')[0]

        if full_url:
            aggregated_trials['urls'][full_url] = aggregated_trials['domains'][domain]

            if domain_url not in aggregated_trials['domains']:
                aggregated_trials['domains'][domain_url] = aggregated_trials['domains'][full_url]
            else:
                aggregated_trials['domains'][domain_url]['engines'].union(aggregated_trials['domains'][full_url]['engines'])
                aggregated_trials['domains'][domain_url]['engines_count'] = len(aggregated_trials['domains'][domain_url]['engines'])

            del aggregated_trials['domains'][full_url]

    print("[i] update finished%s" % (40 * " "))

    if success:
        print("[i] trails stored to '%s'" % OUTPUT_FILE_PATH)

    return aggregated_trials


# update_trails()
