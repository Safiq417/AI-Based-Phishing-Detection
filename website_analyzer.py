import socket
import ssl
import ipaddress
from urllib.parse import urlparse, urljoin
from datetime import datetime
import requests
from bs4 import BeautifulSoup

def is_ip_allowed_for_ssrf(ip_str):
    """
    SSRF Defense: Validates that target IP is a globally routable public IP.
    Blocks localhost, private LAN (10/8, 172.16/12, 192.168/16), link-local/cloud metadata (169.254/16),
    loopback (127/8), and IPv6 equivalents.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if (ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_link_local or 
            ip_obj.is_multicast or 
            ip_obj.is_reserved or 
            ip_obj.is_unspecified):
            return False
        # Specific block for AWS/GCP/Azure cloud metadata IP
        if ip_str == "169.254.169.254":
            return False
        return True
    except ValueError:
        return False

def resolve_and_check_ssrf(hostname):
    """
    Resolves hostname to IP addresses and ensures none point to internal networks.
    """
    if not hostname:
        return False, None, "Invalid hostname"
    
    # Check if raw hostname is already an IP
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if not is_ip_allowed_for_ssrf(str(ip_obj)):
            return False, str(ip_obj), "Target resolves to a restricted internal or private IP (SSRF Blocked)."
        return True, str(ip_obj), "Public IP verified"
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for entry in addr_info:
            ip_candidate = entry[4][0]
            if not is_ip_allowed_for_ssrf(ip_candidate):
                return False, ip_candidate, f"Hostname resolves to restricted private IP: {ip_candidate} (SSRF Blocked)."
        primary_ip = addr_info[0][4][0] if addr_info else None
        return True, primary_ip, "Public IP verified"
    except Exception as e:
        return False, None, f"DNS resolution failed: {str(e)}"

def get_ssl_telemetry(hostname, port=443):
    """
    Extracts SSL certificate details without downloading entire payload.
    """
    ssl_data = {
        "has_ssl": False,
        "issuer": "None",
        "subject": "None",
        "valid_from": "N/A",
        "valid_to": "N/A",
        "days_remaining": 0,
        "is_expired": False,
        "cipher": "N/A",
        "tls_version": "N/A",
        "error": None
    }
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((hostname, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                ssl_data["has_ssl"] = True
                ssl_data["tls_version"] = ssock.version()
                ssl_data["cipher"] = ssock.cipher()[0] if ssock.cipher() else "Unknown"
                
                # Issuer & Subject extraction
                issuer_parts = [val[0][1] for val in cert.get('issuer', []) if val]
                ssl_data["issuer"] = ", ".join(issuer_parts) if issuer_parts else "Verified Certificate Authority"
                
                subject_parts = [val[0][1] for val in cert.get('subject', []) if val]
                ssl_data["subject"] = ", ".join(subject_parts) if subject_parts else hostname
                
                # Expiry dates
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                if not_after:
                    dt_after = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    ssl_data["valid_to"] = dt_after.strftime("%Y-%m-%d")
                    days_left = (dt_after - datetime.utcnow()).days
                    ssl_data["days_remaining"] = days_left
                    ssl_data["is_expired"] = (days_left <= 0)
                if not_before:
                    dt_before = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                    ssl_data["valid_from"] = dt_before.strftime("%Y-%m-%d")
                    
    except ssl.SSLCertVerificationError as e:
        ssl_data["has_ssl"] = True
        ssl_data["error"] = f"SSL Verification Error (Self-Signed / Untrusted CA): {str(e)}"
    except Exception as e:
        ssl_data["error"] = f"SSL Handshake failed: {str(e)}"
        
    return ssl_data

def get_server_geolocation(ip_address):
    """
    Queries public geolocation & ASN for the resolved IP.
    """
    geo = {
        "ip": ip_address or "Unknown",
        "country": "Unknown",
        "country_code": "UN",
        "city": "Unknown",
        "isp": "Unknown",
        "asn": "Unknown"
    }
    if not ip_address:
        return geo
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,city,isp,as", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                geo["country"] = data.get("country", "Unknown")
                geo["country_code"] = data.get("countryCode", "UN")
                geo["city"] = data.get("city", "Unknown")
                geo["isp"] = data.get("isp", "Unknown")
                geo["asn"] = data.get("as", "Unknown")
    except Exception:
        pass
    return geo

def analyze_website(target_input):
    """
    Main passive website deep inspector with SSRF protection, DOM form analysis,
    security headers audit, SSL verification, and forensic risk scoring.
    """
    raw_input = target_input.strip()
    if not raw_input.startswith(('http://', 'https://')):
        url = 'https://' + raw_input
    else:
        url = raw_input

    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    
    report = {
        "target_url": url,
        "hostname": hostname,
        "scan_timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "is_safe": True,
        "threat_score": 0.0,
        "risk_level": "SAFE",
        "reasons": [],
        "ssrf_passed": False,
        "resolved_ip": None,
        "http_status": None,
        "final_url": url,
        "redirect_hops": 0,
        "response_time_ms": 0,
        "ssl": {},
        "security_headers": {},
        "dom_forensics": {
            "page_title": "",
            "total_forms": 0,
            "has_password_input": False,
            "insecure_password_forms": 0,
            "external_action_forms": 0,
            "total_iframes": 0,
            "hidden_iframes": 0,
            "total_scripts": 0,
            "external_scripts": 0,
            "forms_detail": []
        },
        "geolocation": {}
    }

    # 1. SSRF DEFENSE CHECK
    allowed, primary_ip, ssrf_msg = resolve_and_check_ssrf(hostname)
    report["resolved_ip"] = primary_ip
    report["ssrf_passed"] = allowed
    
    if not allowed:
        report["is_safe"] = False
        report["threat_score"] = 99.0
        report["risk_level"] = "CRITICAL COMPROMISE"
        report["reasons"].append(f"CRITICAL: {ssrf_msg}")
        return report

    # 2. SERVER GEOLOCATION
    report["geolocation"] = get_server_geolocation(primary_ip)

    # 3. SSL/TLS CERTIFICATE EXTRACTION
    if parsed.scheme == 'https':
        report["ssl"] = get_ssl_telemetry(hostname, port)
        if report["ssl"].get("error"):
            report["threat_score"] += 25.0
            report["reasons"].append(f"SSL Warning: {report['ssl']['error']}")
        elif report["ssl"].get("is_expired"):
            report["threat_score"] += 30.0
            report["reasons"].append("SSL Certificate is EXPIRED")
    else:
        report["threat_score"] += 15.0
        report["reasons"].append("Insecure connection (Plain HTTP without SSL/TLS encryption)")

    # 4. STRICT PASSIVE HTTP GET WITH REDIRECT LIMIT & TIMEOUT
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 PhishShieldBot/2.0'
    }

    try:
        session = requests.Session()
        session.max_redirects = 3
        start_time = datetime.utcnow()
        
        # Follow redirects manually or with strict timeout (5s)
        resp = session.get(url, headers=headers, timeout=5, allow_redirects=True)
        latency_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        report["http_status"] = resp.status_code
        report["final_url"] = resp.url
        report["redirect_hops"] = len(resp.history)
        report["response_time_ms"] = latency_ms

        # Validate final URL destination for SSRF as well!
        final_host = urlparse(resp.url).hostname
        if final_host and final_host != hostname:
            final_allowed, _, _ = resolve_and_check_ssrf(final_host)
            if not final_allowed:
                report["is_safe"] = False
                report["threat_score"] = 99.0
                report["risk_level"] = "CRITICAL COMPROMISE"
                report["reasons"].append("CRITICAL: Redirected to a restricted internal network address.")
                return report

        if resp.status_code >= 400:
            report["reasons"].append(f"Server returned error status code: {resp.status_code}")
            report["threat_score"] += 10.0

        # 5. SECURITY HEADERS AUDIT
        sec_headers = {
            "Content-Security-Policy": resp.headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security"),
            "X-Frame-Options": resp.headers.get("X-Frame-Options"),
            "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options"),
            "Referrer-Policy": resp.headers.get("Referrer-Policy")
        }
        report["security_headers"] = sec_headers

        missing_count = sum(1 for k, v in sec_headers.items() if not v)
        if missing_count >= 4:
            report["threat_score"] += 10.0
            report["reasons"].append("Missing crucial security headers (CSP, HSTS, X-Frame-Options)")

        # 6. DOM & HTML FORENSIC INSPECTION
        content_type = resp.headers.get('Content-Type', '')
        if 'text/html' in content_type:
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Title
            title_tag = soup.find('title')
            report["dom_forensics"]["page_title"] = title_tag.string.strip() if title_tag and title_tag.string else "No Title Found"

            # Forms inspection
            forms = soup.find_all('form')
            report["dom_forensics"]["total_forms"] = len(forms)

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                inputs = form.find_all('input')
                has_pw = any(inp.get('type', '').lower() == 'password' for inp in inputs)
                
                full_action_url = urljoin(resp.url, action)
                action_host = urlparse(full_action_url).hostname or hostname
                is_external = (action_host != hostname and action_host != '')
                is_insecure_submission = full_action_url.startswith('http://')

                if has_pw:
                    report["dom_forensics"]["has_password_input"] = True
                    if is_insecure_submission:
                        report["dom_forensics"]["insecure_password_forms"] += 1
                        report["threat_score"] += 45.0
                        report["reasons"].append("CRITICAL: Password input field submits over plaintext HTTP connection (Credential Interception Risk).")
                    if is_external:
                        report["dom_forensics"]["external_action_forms"] += 1
                        report["threat_score"] += 40.0
                        report["reasons"].append(f"HIGH RISK: Login password form submits data to external 3rd-party domain ({action_host}).")

                report["dom_forensics"]["forms_detail"].append({
                    "action": action or "Self-Page",
                    "method": method,
                    "has_password": has_pw,
                    "is_external": is_external,
                    "target_host": action_host
                })

            # Hidden Iframes check (Clickjacking / Malware dropping)
            iframes = soup.find_all('iframe')
            report["dom_forensics"]["total_iframes"] = len(iframes)
            hidden_iframes = 0
            for ifr in iframes:
                style = (ifr.get('style', '') or '').lower()
                width = ifr.get('width', '')
                height = ifr.get('height', '')
                if ('display:none' in style or 'visibility:hidden' in style or 
                    width == '0' or height == '0' or width == '1' or height == '1'):
                    hidden_iframes += 1
            
            report["dom_forensics"]["hidden_iframes"] = hidden_iframes
            if hidden_iframes > 0:
                report["threat_score"] += 25.0
                report["reasons"].append(f"Suspicious hidden iframes detected ({hidden_iframes} found) - Potential clickjacking vector.")

            # External scripts check
            scripts = soup.find_all('script')
            report["dom_forensics"]["total_scripts"] = len(scripts)
            ext_scripts = 0
            for sc in scripts:
                src = sc.get('src')
                if src and not src.startswith(('data:', 'javascript:')):
                    src_host = urlparse(urljoin(resp.url, src)).hostname
                    if src_host and src_host != hostname:
                        ext_scripts += 1
            report["dom_forensics"]["external_scripts"] = ext_scripts

    except requests.exceptions.SSLError as e:
        report["threat_score"] += 35.0
        report["reasons"].append(f"SSL Handshake Failure: {str(e)}")
    except requests.exceptions.Timeout:
        report["threat_score"] += 20.0
        report["reasons"].append("Connection timed out (> 5s). Server might be tarpitted or unreachable.")
    except requests.exceptions.TooManyRedirects:
        report["threat_score"] += 30.0
        report["reasons"].append("Too many redirects (> 3 hops). Redirection loop detected.")
    except requests.exceptions.RequestException as e:
        report["threat_score"] += 15.0
        report["reasons"].append(f"HTTP Connection error: {str(e)}")

    # 7. FINAL SCORE NORMALIZATION & RISK LEVEL
    report["threat_score"] = min(100.0, max(0.0, report["threat_score"]))
    
    if report["threat_score"] >= 75.0:
        report["risk_level"] = "Critical Risk"
        report["is_safe"] = False
    elif report["threat_score"] >= 45.0:
        report["risk_level"] = "High Risk"
        report["is_safe"] = False
    elif report["threat_score"] >= 20.0:
        report["risk_level"] = "Suspicious"
        report["is_safe"] = False
    else:
        report["risk_level"] = "Safe"
        report["is_safe"] = True

    return report
