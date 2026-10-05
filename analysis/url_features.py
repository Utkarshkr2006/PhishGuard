"""
PhishGuard 2.0 - Reproducible URL Feature Extractor
Module: analysis/url_features.py

Extracts deterministic, lexical security features from raw URL strings
without making external network calls or accessing remote servers.
"""

import math
import re
import ipaddress
from urllib.parse import urlparse
from collections import Counter

# Common high-risk/suspicious TLDs frequently used in phishing campaigns
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'gq', 'cf', 'ml', 'ga', 'buzz', 'fit', 'tk',
    'club', 'download', 'country', 'stream', 'kim', 'science', 'online',
    'site', 'website', 'space', 'tech', 'rest', 'icu'
}

# Common keywords targeted by phishing scams
SUSPICIOUS_KEYWORDS = {
    'login', 'verify', 'update', 'account', 'banking', 'secure', 'webscr',
    'signin', 'admin', 'confirm', 'paypal', 'wallet', 'credential', 'pay',
    'password', 'security', 'validation', 'support', 'service', 'billing'
}

# Known two-part TLD extensions for accurate subdomain counting
KNOWN_TWO_PART_TLDS = {
    'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'com.au', 'net.au', 'org.au',
    'co.jp', 'ne.jp', 'co.in', 'net.in', 'org.in', 'gov.in', 'co.nz'
}

def calculate_shannon_entropy(text: str) -> float:
    """
    Calculates the Shannon Entropy of a string to quantify randomness/obfuscation.
    Higher entropy values indicate complex, randomized, or encoded character distributions.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(float(entropy), 4)

def is_valid_ip(hostname: str) -> int:
    """
    Checks if hostname is a valid IPv4 or IPv6 address.
    Returns 1 if hostname is an IP, 0 otherwise.
    """
    if not hostname:
        return 0
    # Strip port if present
    clean_host = hostname.split(':')[0]
    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        return 0

def extract_url_features(url: str) -> dict:
    """
    Extracts 23 deterministic lexical features directly from a raw URL string.
    
    Parameters:
        url (str): The raw input URL string.
        
    Returns:
        dict: A dictionary mapping feature names to their extracted values.
    """
    # Safe input normalization
    if not isinstance(url, str):
        url = str(url) if url is not None else ""
    
    url = url.strip()
    
    # Calculate overall URL length and entropy on original raw string
    url_length = len(url)
    url_entropy = calculate_shannon_entropy(url)
    
    if url_length == 0:
        return {
            "url_length": 0, "domain_length": 0, "path_length": 0,
            "num_dots": 0, "num_subdomains": 0, "num_digits": 0,
            "num_letters": 0, "num_hyphens": 0, "num_special_chars": 0,
            "num_at_symbols": 0, "num_question_marks": 0, "num_equals": 0,
            "num_ampersands": 0, "num_slashes": 0, "is_https": 0,
            "is_domain_ip": 0, "has_suspicious_keywords": 0,
            "has_url_encoding": 0, "has_suspicious_tld": 0,
            "letter_ratio": 0.0, "digit_ratio": 0.0,
            "special_char_ratio": 0.0, "url_entropy": 0.0
        }
    
    # Determine HTTPS scheme check on original string
    is_https = 1 if url.lower().startswith('https://') else 0
    
    # Parse URL using urllib.parse
    # Prepend scheme if missing so urlparse extracts netloc/hostname properly
    working_url = url
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', working_url):
        working_url = 'http://' + working_url
        
    try:
        parsed = urlparse(working_url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
    except Exception:
        hostname = ""
        path = ""

    domain_length = len(hostname)
    path_length = len(path)
    
    # Character frequency counts
    num_dots = url.count('.')
    num_digits = sum(1 for c in url if c.isdigit())
    num_letters = sum(1 for c in url if c.isalpha())
    num_hyphens = url.count('-')
    num_special_chars = sum(1 for c in url if not c.isalnum())
    num_at_symbols = url.count('@')
    num_question_marks = url.count('?')
    num_equals = url.count('=')
    num_ampersands = url.count('&')
    num_slashes = url.count('/')
    
    # IP Address Check
    is_domain_ip = is_valid_ip(hostname)
    
    # Subdomain calculation
    num_subdomains = 0
    if hostname and not is_domain_ip:
        host_parts = hostname.lower().split('.')
        # Remove trailing empty strings if host ends with dot
        if host_parts and host_parts[-1] == '':
            host_parts.pop()
            
        if len(host_parts) > 1:
            # Check for known 2-part TLDs (e.g., co.uk)
            two_part = ".".join(host_parts[-2:])
            if two_part in KNOWN_TWO_PART_TLDS:
                num_subdomains = max(0, len(host_parts) - 3)
            else:
                num_subdomains = max(0, len(host_parts) - 2)

    # Suspicious keywords check
    url_lower = url.lower()
    has_suspicious_keywords = 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0
    
    # Percent encoding check (%xx)
    has_url_encoding = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
    
    # Suspicious TLD check
    has_suspicious_tld = 0
    if hostname and not is_domain_ip:
        parts = hostname.lower().split('.')
        if len(parts) > 1 and parts[-1] in SUSPICIOUS_TLDS:
            has_suspicious_tld = 1

    # Ratios
    letter_ratio = round(num_letters / url_length, 4)
    digit_ratio = round(num_digits / url_length, 4)
    special_char_ratio = round(num_special_chars / url_length, 4)

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "num_dots": num_dots,
        "num_subdomains": num_subdomains,
        "num_digits": num_digits,
        "num_letters": num_letters,
        "num_hyphens": num_hyphens,
        "num_special_chars": num_special_chars,
        "num_at_symbols": num_at_symbols,
        "num_question_marks": num_question_marks,
        "num_equals": num_equals,
        "num_ampersands": num_ampersands,
        "num_slashes": num_slashes,
        "is_https": is_https,
        "is_domain_ip": is_domain_ip,
        "has_suspicious_keywords": has_suspicious_keywords,
        "has_url_encoding": has_url_encoding,
        "has_suspicious_tld": has_suspicious_tld,
        "letter_ratio": letter_ratio,
        "digit_ratio": digit_ratio,
        "special_char_ratio": special_char_ratio,
        "url_entropy": url_entropy
    }
