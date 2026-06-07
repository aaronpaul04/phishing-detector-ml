"""
URL feature extraction for phishing detection.
Each function takes a URL string and returns a numeric feature.
"""

import re
from urllib.parse import urlparse
import math
from collections import Counter

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "password", "credential", "wallet",
    "paypal", "ebay", "amazon", "apple", "microsoft", "google",
    "facebook", "instagram", "support", "admin", "webscr"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "tiny.cc", "rebrand.ly"
]


def _safe_parse(url: str):
    """Make sure url has a scheme so urlparse works correctly. Tolerates malformed URLs."""
    if not isinstance(url, str):
        url = ""
    if not re.match(r"^https?://", url):
        url = "http://" + url
    try:
        return urlparse(url)
    except Exception:
        # Return an empty parse result for malformed URLs
        return urlparse("http://invalid.local")

def url_length(url): return len(url)
def num_dots(url): return url.count(".")
def num_hyphens(url): return url.count("-")
def num_underscores(url): return url.count("_")
def num_slashes(url): return url.count("/")
def num_qmarks(url): return url.count("?")
def num_equals(url): return url.count("=")
def num_at(url): return url.count("@")
def num_amp(url): return url.count("&")
def num_digits(url): return sum(c.isdigit() for c in url)
def num_letters(url): return sum(c.isalpha() for c in url)


def has_ip(url):
    """Check if URL uses an IP address instead of a domain."""
    return int(bool(re.search(r"\d{1,3}(\.\d{1,3}){3}", url)))


def has_https(url):
    return int(url.lower().startswith("https://"))


def domain_length(url):
    p = _safe_parse(url)
    return len(p.netloc)


def path_length(url):
    p = _safe_parse(url)
    return len(p.path)


def query_length(url):
    p = _safe_parse(url)
    return len(p.query)


def num_subdomains(url):
    p = _safe_parse(url)
    host = p.netloc.split(":")[0]
    return max(0, host.count(".") - 1)


def has_suspicious_word(url):
    low = url.lower()
    return int(any(w in low for w in SUSPICIOUS_WORDS))


def is_shortener(url):
    low = url.lower()
    return int(any(s in low for s in SHORTENERS))


def domain_entropy(url):
    """Shannon entropy of the domain. High entropy can mean random/generated."""
    p = _safe_parse(url)
    host = p.netloc.split(":")[0]
    if not host:
        return 0.0
    counts = Counter(host)
    total = len(host)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


FEATURES = [
    url_length, num_dots, num_hyphens, num_underscores, num_slashes,
    num_qmarks, num_equals, num_at, num_amp, num_digits, num_letters,
    has_ip, has_https, domain_length, path_length, query_length,
    num_subdomains, has_suspicious_word, is_shortener, domain_entropy
]


def extract_features(url: str) -> dict:
    """Extract all features for a single URL. Returns a dict. Safe against bad input."""
    if not isinstance(url, str) or not url:
        url = "http://invalid.local"
    out = {}
    for fn in FEATURES:
        try:
            out[fn.__name__] = fn(url)
        except Exception:
            out[fn.__name__] = 0
    return out


if __name__ == "__main__":
    # Quick test
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login.php",
        "https://paypa1-secure-verify-account.tk/signin?user=admin",
    ]
    for u in test_urls:
        print(u)
        print(extract_features(u))
        print()