from dga_detector import analyze_dga, calculate_shannon_entropy, extract_sld

def run_tests():
    print("=" * 60)
    print("TESTING DGA DETECTION ENGINE")
    print("=" * 60)

    # Benign / Legitimate domains
    benign_domains = [
        "https://www.google.com",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://wikipedia.org/wiki/Phishing",
        "https://netbanking.hdfcbank.com",
        "https://www.paypal.com/signin",
        "https://retail.onlinesbi.sbi.co.in",
        "https://github.com/torvalds/linux",
        "https://cybersecuritynews.com"
    ]

    print("\n--- Testing Legitimate / Benign Domains ---")
    for url in benign_domains:
        res = analyze_dga(url)
        print(f"[BENIGN] URL: {url}")
        print(f"         SLD: {res['sld']} | Entropy: {res['entropy']} | DGA Score: {res['dga_score']}% | Is DGA: {res['is_dga']}")
        assert not res['is_dga'], f"False positive on legitimate domain: {url}"

    # DGA / Malware botnet domains
    dga_domains = [
        "http://x8kjw92lzk3q1a.biz",
        "https://qkwjebfzxcvn12.net/gate.php",
        "http://bcdfghjklmnpq.xyz/login",
        "https://1748923748923.biz/update",
        "http://ajskdfhlkajsdf.info",
        "http://oxpkwjebvfru.com/index.html"
    ]

    print("\n--- Testing Algorithmically Generated Domains (DGA) ---")
    for url in dga_domains:
        res = analyze_dga(url)
        print(f"[DGA MALWARE] URL: {url}")
        print(f"              SLD: {res['sld']} | Entropy: {res['entropy']} | DGA Score: {res['dga_score']}% | Confidence: {res['confidence']}")
        print(f"              Reasons: {res['reasons']}")
        assert res['is_dga'], f"Failed to detect DGA domain: {url}"

    print("\n[+] ALL DGA TESTS PASSED SUCCESSFULLY!")

if __name__ == '__main__':
    run_tests()
