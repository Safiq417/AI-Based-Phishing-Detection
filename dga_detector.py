import math
import re
from urllib.parse import urlparse
from collections import Counter

# Common popular/whitelisted domains to prevent false positives
WHITELISTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',
    'netflix.com', 'github.com', 'cloudflare.com', 'wordpress.org', 'yahoo.com',
    'bing.com', 'reddit.com', 'pinterest.com', 'ebay.com', 'paypal.com',
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'whatsapp.com',
    'zoom.us', 'dropbox.com', 'adobe.com', 'spotify.com', 'quora.com'
}

# Multi-part top-level domains for accurate SLD (Second-Level Domain) extraction
COMMON_MULTI_TLDS = {
    'co.in', 'gov.in', 'ac.in', 'net.in', 'org.in', 'res.in', 'edu.in',
    'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'me.uk', 'ltd.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'com.br', 'net.br', 'org.br', 'gov.br',
    'co.nz', 'net.nz', 'org.nz',
    'com.sg', 'edu.sg', 'gov.sg'
}

def calculate_shannon_entropy(text: str) -> float:
    """
    Calculates Shannon Entropy of a string: H(X) = -sum(P(x) * log2(P(x)))
    Higher entropy indicates greater randomness (characteristic of DGA).
    """
    if not text:
        return 0.0
    
    text = text.lower()
    length = len(text)
    counts = Counter(text)
    
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
        
    return round(entropy, 3)

def extract_sld(url_or_domain: str) -> dict:
    """
    Extracts the hostname and the core domain label (Second-Level Domain / SLD) from a URL or domain string.
    """
    url_str = url_or_domain.strip().lower()
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'http://' + url_str
        
    try:
        parsed = urlparse(url_str)
        hostname = (parsed.hostname or '').lower().strip()
    except Exception:
        hostname = url_or_domain.strip().lower().split('/')[0]

    # Remove standard prefixes like www or m
    clean_host = re.sub(r'^(www\d?|m)\.', '', hostname)
    
    parts = clean_host.split('.')
    if len(parts) <= 1:
        return {'hostname': hostname, 'sld': clean_host, 'registered_domain': hostname}

    # Check for multi-part TLD (e.g. example.co.in -> sld = example, registered = example.co.in)
    last_two_tld = f"{parts[-2]}.{parts[-1]}"
    if last_two_tld in COMMON_MULTI_TLDS and len(parts) >= 3:
        sld = parts[-3]
        registered_domain = f"{parts[-3]}.{last_two_tld}"
    else:
        sld = parts[-2]
        registered_domain = f"{parts[-2]}.{parts[-1]}"
        
    return {
        'hostname': hostname,
        'sld': sld,
        'registered_domain': registered_domain
    }

def analyze_dga(url_or_domain: str) -> dict:
    """
    Analyzes a URL or domain for Domain Generation Algorithm (DGA) characteristics.
    
    Returns:
    {
        'is_dga': bool,
        'dga_score': float (0.0 to 100.0),
        'confidence': str ('None', 'Low', 'Medium', 'High', 'Critical'),
        'entropy': float,
        'vowel_ratio': float,
        'consonant_cluster': int,
        'digit_ratio': float,
        'sld': str,
        'registered_domain': str,
        'reasons': list of str
    }
    """
    extracted = extract_sld(url_or_domain)
    sld = extracted['sld']
    registered_domain = extracted['registered_domain']
    hostname = extracted['hostname']
    
    # Check whitelist
    if registered_domain in WHITELISTED_DOMAINS or any(registered_domain.endswith('.' + d) for d in WHITELISTED_DOMAINS):
        return {
            'is_dga': False,
            'dga_score': 0.0,
            'confidence': 'None',
            'entropy': calculate_shannon_entropy(sld),
            'vowel_ratio': 0.0,
            'consonant_cluster': 0,
            'digit_ratio': 0.0,
            'sld': sld,
            'registered_domain': registered_domain,
            'reasons': []
        }
        
    if not sld or len(sld) < 4:
        return {
            'is_dga': False,
            'dga_score': 0.0,
            'confidence': 'None',
            'entropy': calculate_shannon_entropy(sld),
            'vowel_ratio': 0.0,
            'consonant_cluster': 0,
            'digit_ratio': 0.0,
            'sld': sld,
            'registered_domain': registered_domain,
            'reasons': []
        }

    reasons = []
    dga_penalty = 0.0
    
    # 1. Shannon Entropy
    entropy = calculate_shannon_entropy(sld)
    length = len(sld)
    
    if entropy >= 3.75:
        dga_penalty += 35.0
        reasons.append(f"High Shannon entropy ({entropy}) indicates pseudo-random character generation (DGA pattern)")
    elif entropy >= 3.4 and length >= 8:
        dga_penalty += 20.0
        reasons.append(f"Elevated character entropy ({entropy}) suggesting non-dictionary randomness")

    # 2. Vowel-to-Consonant Ratio
    vowels = set('aeiou')
    alpha_chars = [c for c in sld if c.isalpha()]
    total_alpha = len(alpha_chars)
    vowel_count = sum(1 for c in alpha_chars if c in vowels)
    vowel_ratio = (vowel_count / total_alpha) if total_alpha > 0 else 0.0
    
    if total_alpha >= 6:
        if vowel_ratio == 0.0:
            dga_penalty += 35.0
            reasons.append(f"Zero vowels detected in domain name ({vowel_count}/{total_alpha} letters) - unpronounceable DGA signature")
        elif vowel_ratio < 0.15:
            dga_penalty += 20.0
            reasons.append(f"Abnormally low vowel ratio ({vowel_ratio:.1%}) - characteristic of algorithmic generation")
        elif vowel_ratio > 0.70 and total_alpha >= 8:
            dga_penalty += 15.0
            reasons.append(f"Abnormally high vowel concentration ({vowel_ratio:.1%})")

    # 3. Consecutive Consonant / Digit Clusters
    consonant_clusters = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', sld)
    max_consonant_run = max([len(c) for c in consonant_clusters], default=0)
    if max_consonant_run >= 6:
        dga_penalty += 25.0
        reasons.append(f"Extreme consecutive consonant cluster ({max_consonant_run} consonants in a row: '{max(consonant_clusters, key=len)}')")
    elif max_consonant_run >= 4:
        dga_penalty += 15.0
        reasons.append(f"Suspicious consonant cluster ({max_consonant_run} consecutive consonants)")

    # 4. Digit Ratio & Numeric DGA Generation
    digit_count = sum(1 for c in sld if c.isdigit())
    digit_ratio = digit_count / length
    if sld.isdigit() and length >= 6:
        dga_penalty += 45.0
        reasons.append(f"Domain name is purely numeric ({length} digits) - numeric DGA generation pattern")
    elif digit_ratio > 0.40 and length >= 6:
        dga_penalty += 25.0
        reasons.append(f"High numeric density ({digit_ratio:.1%} digits in domain name)")
    
    # 5. Hexadecimal / Hash-like / Base-32 or Base-64 Randomness Pattern
    if (re.fullmatch(r'^[0-9a-f]{8,}$', sld) or re.fullmatch(r'^[0-9a-z]{12,}$', sld)) and not sld.isdigit():
        if entropy > 3.2:
            dga_penalty += 20.0
            reasons.append("Domain name matches algorithmic hash/hex/base pattern")

    # 6. Unusually Long Randomized Domain
    if length > 22 and entropy > 3.4:
        dga_penalty += 15.0
        reasons.append(f"Abnormally long high-entropy domain string ({length} characters)")

    # 7. Check for Repeated Substrings / Character transitions
    if length >= 10 and len(set(sld)) == length:
        dga_penalty += 10.0
        reasons.append("Every character in domain is unique (uniform random distribution)")

    dga_score = min(dga_penalty, 100.0)
    is_dga = dga_score >= 35.0

    if dga_score >= 70.0:
        confidence = 'Critical'
    elif dga_score >= 45.0:
        confidence = 'High'
    elif dga_score >= 25.0:
        confidence = 'Medium'
    elif dga_score > 0.0:
        confidence = 'Low'
    else:
        confidence = 'None'

    return {
        'is_dga': is_dga,
        'dga_score': dga_score,
        'confidence': confidence,
        'entropy': entropy,
        'vowel_ratio': round(vowel_ratio, 3),
        'consonant_cluster': max_consonant_run,
        'digit_ratio': round(digit_ratio, 3),
        'sld': sld,
        'registered_domain': registered_domain,
        'reasons': reasons
    }
