import os

UNICODE_ENCODING = "utf8"
TIMEOUT = 30
NAME = "Updater"
FEEDS_DIR = "./feeds/"
OUTPUT_FILE_PATH = "./out.csv"
# Disable (retrieval from) specified feeds (Note: respective .py files inside /trails/feeds;
# turris and ciarmy/cinsscore seem to be too "noisy" lately; policeman is old and produces lots of false positives)
DISABLED_FEEDS = ["turris", "ciarmy", "policeman", "myip"]
LOW_PRIORITY_INFO_KEYWORDS = ("reputation", "attacker", "spammer", "abuser", "malicious", "dnspod", "nicru", "crawler", "compromised", "bad history")
HIGH_PRIORITY_INFO_KEYWORDS = ("mass scanner", "ipinfo")
HIGH_PRIORITY_REFERENCES = ("bambenekconsulting.com", "github.com/stamparm/blackbook", "(static)", "(custom)")
WHITELIST = set()
WHITELIST_RANGES = set()
USER_WHITELIST = os.path.abspath(os.path.join(FEEDS_DIR, 'whitelist.txt'))
BAD_TRAIL_PREFIXES = ("127.", "192.168.", "localhost")
IS_WIN = "nt"
IP_TYPE = "ip_list"
ATTACKER_TYPE = "Known_Attacker"
DOMAIN_TYPE = "domain_list"
MALWARE_TYPE = "Malware"
CNC_TYPE = "CnC"
CRYPTO_MINING_TYPE = "Crypto_Mining"
SPAM_TYPE = "Spam"
CRAWLER_TYPE = "Crawler"
PHISHING_TYPE = "Phishing_Type"
PROXY_TYPE = "Proxy_Type"
RANSOM_TYPE = "Ransom_Type"
TOR_EXIT_NODE_TYPE = "Tor_Exit_Node_Type"
