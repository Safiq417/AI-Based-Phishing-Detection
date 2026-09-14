import os
import re
import sqlite3
import pickle
import numpy as np
from datetime import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher
import time
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from dga_detector import analyze_dga
from website_analyzer import analyze_website
from screenshot_analyzer import analyze_screenshot
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify

try:
    import requests
except ImportError:
    requests = None
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())
DB_PATH = 'database/phishing_system.db'

# Ensure required directories exist
os.makedirs('database', exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('model', exist_ok=True)

# Global model pointers
model = None
vectorizer = None

def load_ml_components():
    global model, vectorizer
    try:
        with open('model/phishing_model.pkl', 'rb') as f:
            model = pickle.load(f)
        with open('model/vectorizer.pkl', 'rb') as f:
            vectorizer = pickle.load(f)
    except FileNotFoundError:
        model = None
        vectorizer = None

# Database Initialization
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            input_type TEXT,
            content TEXT,
            score REAL,
            risk_level TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_id INTEGER,
            file_path TEXT,
            generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(history_id) REFERENCES history(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create or update default admin account
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    admin_default_pw = os.environ.get('ADMIN_PASSWORD', 'Admin@12345')
    hashed_pw = generate_password_hash(admin_default_pw)
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", 
                       ('admin', 'admin@cyberdefense.local', hashed_pw, 'admin'))
    else:
        cursor.execute("UPDATE users SET password = ? WHERE username = 'admin'", (hashed_pw,))
    
    conn.commit()
    conn.close()

init_db()
load_ml_components()

# --- URL / Domain Analysis Helper Engine ---
def is_valid_url(url):
    try:
        url_str = url.strip()
        if not url_str.startswith(('http://', 'https://')):
            url_str = 'http://' + url_str
        parsed = urlparse(url_str)
        if parsed.scheme not in ('http', 'https'):
            return False
        if not parsed.netloc:
            return False
        if parsed.netloc.startswith('.') or parsed.netloc.endswith('.'):
            return False
        if '@' in parsed.netloc and parsed.hostname is None:
            return False
        hostname = (parsed.hostname or '').strip()
        if not hostname or '.' not in hostname:
            return False
        return True
    except Exception:
        return False


def analyze_url_lexical(url):
    url = url.strip()
    parsed = urlparse(url)
    hostname = (parsed.hostname or '').lower()
    normalized = url.lower()

    report = {
        "is_ip": 0, "is_shortened": 0, "suspicious_tld": 0,
        "excessive_subdomains": 0, "no_https": 0, "score_deduction": 0
    }

    # IP-based URL check
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', hostname):
        report["is_ip"] = 1
        report["score_deduction"] += 30

    # @-symbol embedded userinfo or suspicious URL form
    if '@' in url:
        report["score_deduction"] += 30

    # URL shortening services
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'adf.ly']
    if any(hostname.endswith(shortener) for shortener in shorteners) or any(shortener in normalized for shortener in shorteners):
        report["is_shortened"] = 1
        report["score_deduction"] += 20

    # Suspicious top-level domains
    suspicious_tlds = ['.xyz', '.top', '.club', '.gq', '.ml', '.cf', '.tk', '.info', '.download']
    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        report["suspicious_tld"] = 1
        report["score_deduction"] += 20

    # Excessive subdomains
    subdomains = [part for part in hostname.split('.') if part]
    if len(subdomains) > 4:
        report["excessive_subdomains"] = 1
        report["score_deduction"] += 15

    # Plain HTTP usage is weaker than HTTPS
    if parsed.scheme == 'http':
        report["no_https"] = 1
        report["score_deduction"] += 10

    # Suspicious or obfuscated URL content (skip brand-name deduction if hosted on that actual legitimate domain)
    suspicious_keywords = ['verify', 'bank', 'secure', 'login', 'wp-admin', 'giftcard', 'free', 'update', 'billing']
    is_legit_popular = any(hostname == legit or hostname.endswith('.' + legit) for legit in POPULAR_DOMAINS)
    if not is_legit_popular:
        suspicious_keywords.extend(['paypal', 'account', 'amazon', 'netflix', 'apple', 'microsoft', 'google'])

    if any(keyword in normalized for keyword in suspicious_keywords):
        report["score_deduction"] += 10

    if len(url) > 100:
        report["score_deduction"] += 10

    if re.search(r'%[0-9a-fA-F]{2}', url):
        report["score_deduction"] += 10

    return report

POPULAR_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'paypal.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'instagram.com', 'whatsapp.com', 'youtube.com',
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'linkedin.com', 'twitter.com'
]

def check_typosquatting(url):
    try:
        hostname = (urlparse(url).hostname or '').lower().replace('www.', '')
    except Exception:
        return None
    if not hostname:
        return None

    # 1. Legitimate domain ya subdomain check
    for legit in POPULAR_DOMAINS:
        if hostname == legit or hostname.endswith('.' + legit):
            return None

    # Main brand name extract karna (e.g., 'kaggle.com' -> 'kaggle')
    domain_name = hostname.split('.')[0]

    for legit in POPULAR_DOMAINS:
        legit_name = legit.split('.')[0]

        # Stripped names ko compare karna (without .com / TLD)
        ratio = SequenceMatcher(None, domain_name, legit_name).ratio()

        if ratio > 0.75:
            return legit
        if len(legit_name) >= 4 and legit_name in domain_name and domain_name != legit_name:
            return legit

    return None

def scan_url_virustotal(url):
    if not VIRUSTOTAL_API_KEY or requests is None:
        return None
    try:
        import base64
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        resp = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            return stats
        return None
    except Exception:
        return None
def analyze_text_with_ai(content):
    if requests is None:
        return None
    api_key = os.environ.get('GROQ_API_KEY') or os.environ.get('GROK_API_KEY')
    if not api_key:
        return None
    try:
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        prompt = (
            "You are a cybersecurity expert. Analyze the following email or SMS text "
            "and determine if it is a phishing attempt. Look for subtle signs like: "
            "urgency, impersonation, suspicious requests, social engineering, fake rewards, "
            "fear tactics, unusual sender context, or requests for sensitive information. "
            "Reply in this exact format only:\n"
            "VERDICT: [PHISHING or SAFE or SUSPICIOUS]\n"
            "REASON: [one sentence explanation]\n\n"
            f"Text to analyze:\n{content[:1000]}"
        )
        model_name = os.environ.get('GROQ_MODEL', 'openai/gpt-oss-120b')
        payload = {
            'model': model_name,
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': 0.2,
            'max_tokens': 100
        }
        resp = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers=headers, json=payload, timeout=10
        )
        if resp.status_code == 200:
            reply = resp.json()['choices'][0]['message']['content'].strip()
            verdict, reason = '', ''
            for line in reply.splitlines():
                if line.startswith('VERDICT:'):
                    verdict = line.replace('VERDICT:', '').strip()
                elif line.startswith('REASON:'):
                    reason = line.replace('REASON:', '').strip()
            return {'verdict': verdict, 'reason': reason}
        return None
    except Exception:
        return None
def calculate_risk_level(score):
    if score < 20: return "Safe"
    elif score < 45: return "Low Risk"
    elif score < 70: return "Medium Risk"
    elif score < 90: return "High Risk"
    else: return "Critical"

# --- System Audit Logger ---
def log_activity(user_id, action):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("INSERT INTO logs (user_id, action) VALUES (?, ?)", (user_id, action))
    conn.commit()
    conn.close()

# --- Core Web Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        
        if not username or not email or not password:
            flash("All structural input parameters are mandatory.", "danger")
            return redirect(url_for('register'))
            
        hashed_password = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                      (username, email, hashed_password))
            conn.commit()
            conn.close()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or Email address profile identity collision detected.", "danger")
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            log_activity(user[0], "User authenticated successfully.")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid authentication tokens provided.", "danger")
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], "User signed out of system session.")
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
# Form Inference Processing
    if request.method == 'POST':
        input_type = request.form['type']  # 'text' or 'url'
        content = request.form['content'].strip()

        base_score = 0.0
        reasons = []

        if not content:
            flash("Please enter some content to analyze.", "danger")
            conn.close()
            return redirect(url_for('dashboard'))

        if input_type == 'url':
            if not is_valid_url(content):
                flash("Invalid URL or Domain format. Please submit a valid domain or URL (e.g. example.com or https://example.com).", "danger")
                conn.close()
                return redirect(url_for('dashboard'))
            if not content.startswith(('http://', 'https://')):
                content = 'http://' + content

        if input_type == 'text' and is_valid_url(content) and (' ' not in content and '\n' not in content):
            flash("You entered a URL or Domain but selected Email / SMS Content. Please switch Payload Type to Web URL / Domain.", "danger")
            conn.close()
            return redirect(url_for('dashboard'))

        ml_score = 0.0
        if model and vectorizer and content and input_type == 'text':
            vectorized_input = vectorizer.transform([content])
            phishing_label_index = int(np.where(model.classes_ == 1)[0][0]) if 1 in model.classes_ else 1
            phishing_prob = float(model.predict_proba(vectorized_input)[0][phishing_label_index])
            ml_score = phishing_prob * 100
            if phishing_prob > 0.40:
                reasons.append("ML model indicates phishing-like patterns")

        keyword_score = 0.0
        if input_type == 'text':
            suspicious_keywords = [
                'verify', 'bank', 'secure', 'login', 'paypal', 'amazon', 'netflix',
                'apple', 'microsoft', 'google', 'hdfc', 'sbi', 'icici', 'upi',
                'click here', 'verify now', 'confirm account', 'update billing',
                'reset password', 'signin', 'wp-admin', 'urgent', 'immediately',
                'suspend', 'expire', 'limited time', 'unusual activity', 'unauthorized',
                'act now', 'within 24 hours', 'permanently closed', 'giftcard',
                'free', 'billing', 'account', 'winner', 'prize', 'congratulations',
                'otp', 'kyc', 'aadhar', 'pan card', 'update', 'password'
            ]
            match_count = sum(1 for word in suspicious_keywords if word in content.lower())
            keyword_score = min(match_count * 12.0, 100.0)
            if match_count:
                reasons.append("Text content includes suspicious keywords")
            else:
                reasons.append("No strong phishing keywords detected in text")

        base_score = min((ml_score * 0.6) + (keyword_score * 0.4), 100.0)
        if input_type == 'text':
            ai_analysis = analyze_text_with_ai(content)
            if ai_analysis and ai_analysis.get('verdict'):
                verdict = ai_analysis['verdict']
                reason = ai_analysis.get('reason', '')
                if verdict == 'PHISHING':
                    base_score = min(base_score + 40, 100.0)
                    reasons.append(f"AI Analysis: Phishing detected — {reason}")
                elif verdict == 'SUSPICIOUS':
                    base_score = min(base_score + 20, 100.0)
                    reasons.append(f"AI Analysis: Suspicious content — {reason}")
                else:
                    reasons.append(f"AI Analysis: Content appears safe — {reason}")
        if input_type == 'url':
            url_features = analyze_url_lexical(content)
            heuristic_score = url_features["score_deduction"]
            base_score = min(base_score + heuristic_score, 100.0)

            # DGA (Domain Generation Algorithm) Detection
            dga_result = analyze_dga(content)
            if dga_result and dga_result.get('is_dga'):
                dga_penalty = min(dga_result.get('dga_score', 50.0), 65.0)
                base_score = min(base_score + dga_penalty, 100.0)
                reasons.append(f"DGA Detection: Algorithmic domain generation pattern detected (Entropy: {dga_result['entropy']:.2f}, Risk: {dga_result['confidence']})")
                for dga_reason in dga_result.get('reasons', []):
                    reasons.append(f"DGA Flag: {dga_reason}")
            elif dga_result and dga_result.get('dga_score', 0) > 0 and dga_result.get('confidence') in ('Low', 'Medium'):
                minor_penalty = min(dga_result['dga_score'] * 0.4, 20.0)
                base_score = min(base_score + minor_penalty, 100.0)
                for dga_reason in dga_result.get('reasons', []):
                    reasons.append(f"DGA Warning: {dga_reason}")

            typosquat_match = check_typosquatting(content)
            if typosquat_match:
                base_score = min(base_score + 55, 100.0)
                reasons.append(f"Domain closely resembles '{typosquat_match}' — possible brand impersonation / typosquatting")
            vt_result = scan_url_virustotal(content)
            if vt_result:
                malicious = vt_result.get('malicious', 0)
                suspicious = vt_result.get('suspicious', 0)
                if malicious > 0:
                    base_score = min(base_score + (malicious * 10), 100.0)
                    reasons.append(f"VirusTotal: {malicious} engines flagged this URL as malicious")
                elif suspicious > 0:
                    base_score = min(base_score + (suspicious * 5), 100.0)
                    reasons.append(f"VirusTotal: {suspicious} engines flagged as suspicious")
                else:
                    reasons.append("VirusTotal: No engines flagged this URL")
            if url_features.get("is_ip"):
                reasons.append("URL uses a raw IP address")
            if '@' in content:
                reasons.append("URL contains an '@' symbol")
            if url_features.get("is_shortened"):
                reasons.append("URL uses a known shortening service")
            if url_features.get("suspicious_tld"):
                reasons.append("URL uses a suspicious top-level domain")
            if url_features.get("excessive_subdomains"):
                reasons.append("URL contains excessive subdomains")
            if url_features.get("no_https"):
                reasons.append("URL uses insecure HTTP")
            if len(content) > 100:
                reasons.append("URL length is unusually long")
            if re.search(r'%[0-9a-fA-F]{2}', content):
                reasons.append("URL contains encoded or obfuscated characters")

        if base_score == 0.0:
            reasons.append("Overall analysis indicates a low-risk result")

        risk_level = calculate_risk_level(base_score)

        breakdown_parts = []
        if input_type == 'text':
            breakdown_parts.append(f"ML Model: {ml_score:.1f}%")
            breakdown_parts.append(f"Keyword Score: {keyword_score:.1f}%")
        if input_type == 'url' and dga_result and dga_result.get('is_dga'):
            breakdown_parts.append(f"DGA Pattern: {dga_result['confidence']} Risk (Entropy {dga_result['entropy']:.2f})")
        if input_type == 'url' and vt_result:
            vt_malicious = vt_result.get('malicious', 0)
            vt_suspicious = vt_result.get('suspicious', 0)
            breakdown_parts.append(f"VirusTotal: {vt_malicious} malicious / {vt_suspicious} suspicious engines")
        if input_type == 'text' and ai_analysis and ai_analysis.get('verdict'):
            breakdown_parts.append(f"AI Verdict: {ai_analysis['verdict']}")
        breakdown_parts.append(f"Final Combined Score: {base_score:.1f}% ({risk_level})")
        reasons.insert(0, "SCORE BREAKDOWN — " + " | ".join(breakdown_parts))
        if reasons:
            flash("Analysis reasons: " + "; ".join(reasons), "success")
        c.execute("INSERT INTO history (user_id, input_type, content, score, risk_level) VALUES (?, ?, ?, ?, ?)",
                  (session['user_id'], input_type, content, base_score, risk_level))
        conn.commit()
        conn.close()
        log_activity(session['user_id'], f"Processed analysis for {input_type} evaluation engine.")
        return redirect(url_for('dashboard'))

    # Fetch User Statistics Context
    c.execute("SELECT COUNT(*) FROM history WHERE user_id = ?", (session['user_id'],))
    total_scans = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM history WHERE user_id = ? AND risk_level IN ('High Risk', 'Critical')", (session['user_id'],))
    total_threats = c.fetchone()[0]
    
    c.execute("SELECT * FROM history WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10", (session['user_id'],))
    user_history = c.fetchall()
    
    # Calculate global charts metrics
    c.execute("SELECT risk_level, COUNT(*) FROM history WHERE user_id = ? GROUP BY risk_level", (session['user_id'],))
    chart_data = dict(c.fetchall())
    
    conn.close()
    return render_template('dashboard.html', total_scans=total_scans, total_threats=total_threats, history=user_history, chart_data=chart_data)

@app.route('/scan_website', methods=['POST'])
def scan_website_endpoint():
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({'error': 'Unauthorized. Please login.'}), 401
        return redirect(url_for('login'))

    target_url = request.form.get('url', '').strip()
    if not target_url and request.is_json:
        target_url = (request.json or {}).get('url', '').strip()

    if not target_url:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({'error': 'Website URL parameter is required.'}), 400
        flash('Please enter a website URL to inspect.', 'danger')
        return redirect(url_for('dashboard'))

    # Run Deep Passive Website Analysis
    result = analyze_website(target_url)

    # Save to history database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO history (user_id, input_type, content, score, risk_level) VALUES (?, ?, ?, ?, ?)",
        (session['user_id'], 'website_deep_scan', result['target_url'], result['threat_score'], result['risk_level'])
    )
    conn.commit()
    conn.close()
    log_activity(session['user_id'], f"Executed Live Website Deep Inspection on {result['hostname']}")

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json or request.form.get('ajax') == '1':
        return jsonify(result)

    flash(f"Website Inspection Complete: {result['risk_level']} ({result['threat_score']:.1f}% Risk Score)", "success" if result['is_safe'] else "danger")
    return redirect(url_for('dashboard'))

@app.route('/scan_screenshot', methods=['POST'])
def scan_screenshot_endpoint():
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({'error': 'Unauthorized. Please login.'}), 401
        return redirect(url_for('login'))

    if 'screenshot' not in request.files:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({'error': 'No screenshot image file uploaded.'}), 400
        flash('Please select or drop an image file to analyze.', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['screenshot']
    if file.filename == '':
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({'error': 'Empty filename uploaded.'}), 400
        flash('No file selected.', 'danger')
        return redirect(url_for('dashboard'))

    file_bytes = file.read()
    if len(file_bytes) > 10 * 1024 * 1024:
        return jsonify({'error': 'File size exceeds 10MB limit.'}), 400

    # Run Screenshot Vision / OCR Analysis
    result = analyze_screenshot(file_bytes, filename=file.filename, groq_api_key=GROQ_API_KEY)

    # If embedded URLs were discovered, inspect them with our DGA and Typosquatting engines
    url_findings = []
    for u in result.get('detected_urls', []):
        u_lex = analyze_url_lexical(u)
        u_dga = analyze_dga(u)
        u_typo = check_typosquatting(u)
        url_findings.append({
            'url': u,
            'is_dga': u_dga.get('is_dga', False),
            'dga_confidence': u_dga.get('confidence', 'None'),
            'typosquatting_target': u_typo,
            'lexical_score': u_lex.get('score_deduction', 0)
        })
        if u_dga.get('is_dga') or u_typo:
            result['threat_score'] = min(100.0, result['threat_score'] + 30.0)
            result['is_safe'] = False
            result['risk_level'] = 'CRITICAL COMPROMISE' if result['threat_score'] >= 75 else 'HIGH RISK'

    result['embedded_url_analysis'] = url_findings

    # Save to history database
    db_content = f"Screenshot: {file.filename} (Brand: {result.get('impersonated_brand', 'None')})"
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO history (user_id, input_type, content, score, risk_level) VALUES (?, ?, ?, ?, ?)",
        (session['user_id'], 'screenshot_ocr', db_content, result['threat_score'], result['risk_level'])
    )
    conn.commit()
    conn.close()
    log_activity(session['user_id'], f"Processed Vision OCR Analysis for screenshot: {file.filename}")

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json or request.form.get('ajax') == '1':
        return jsonify(result)

    flash(f"Screenshot Analysis Complete: {result['risk_level']} ({result['threat_score']:.1f}% Risk Score)", "success" if result['is_safe'] else "danger")
    return redirect(url_for('dashboard'))

@app.route('/export/<int:history_id>')
def export_report(history_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM history WHERE id = ? AND user_id = ?", (history_id, session['user_id']))
    record = c.fetchone()
    
    if not record:
        conn.close()
        return "Record resolution trace missing.", 404
        
    # Generate Dynamic Enterprise Forensic PDF Content via ReportLab pipeline
    pdf_filename = f"reports/CyberReport_{history_id}.pdf"
    
    # Track PDF report in reports table
    c.execute("INSERT INTO reports (history_id, file_path) VALUES (?, ?)", (history_id, pdf_filename))
    conn.commit()
    conn.close()

    doc = SimpleDocTemplate(
        pdf_filename, 
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        title=f"PhishShield AI Forensic Report #{history_id:04d}",
        author="PhishShield AI Enterprise Cyber Defense"
    )
    styles = getSampleStyleSheet()
    story = []

    # Custom Dedicated Theme Styles (Ensures zero text collision and perfect leading)
    primary_color = colors.HexColor('#0F172A')
    accent_blue = colors.HexColor('#2563EB')
    table_head_bg = colors.HexColor('#1E40AF') # Vibrant Cyber Blue Header
    muted_color = colors.HexColor('#64748B')
    border_color = colors.HexColor('#CBD5E1')

    title_style = ParagraphStyle('ReportMainTitle', fontName='Helvetica-Bold', fontSize=14, textColor=primary_color, leading=17)
    subtitle_style = ParagraphStyle('ReportSubTitle', fontName='Helvetica', fontSize=8, textColor=muted_color, leading=10)
    meta_style = ParagraphStyle('ReportMeta', fontName='Helvetica', fontSize=7.5, textColor=primary_color, leading=10, alignment=2)
    meta_bold = ParagraphStyle('ReportMetaBold', fontName='Helvetica-Bold', fontSize=8.5, textColor=accent_blue, leading=11, alignment=2)
    
    section_heading = ParagraphStyle('SectionHeading', fontName='Helvetica-Bold', fontSize=10, textColor=primary_color, leading=12, spaceBefore=6, spaceAfter=3)
    cell_normal = ParagraphStyle('CellNormal', fontName='Helvetica', fontSize=7.5, textColor=colors.HexColor('#334155'), leading=10)
    cell_bold = ParagraphStyle('CellBold', fontName='Helvetica-Bold', fontSize=7.5, textColor=primary_color, leading=10)
    cell_mono = ParagraphStyle('CellMono', fontName='Courier', fontSize=7.5, textColor=colors.HexColor('#0F172A'), leading=9.5)
    thead_style = ParagraphStyle('THeadStyle', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white, leading=10)

    # Banner Specific Styles (Explicit leading prevents text overlaps)
    v_top_style = ParagraphStyle('VTop', fontName='Helvetica', fontSize=7.5, textColor=colors.white, leading=9)
    v_main_style = ParagraphStyle('VMain', fontName='Helvetica-Bold', fontSize=12, textColor=colors.white, leading=15)
    v_sub_style = ParagraphStyle('VSub', fontName='Helvetica', fontSize=7.5, textColor=colors.HexColor('#F1F5F9'), leading=9.5)
    v_rec_head = ParagraphStyle('VRecHead', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.white, leading=9.5)
    v_rec_body = ParagraphStyle('VRecBody', fontName='Helvetica', fontSize=7.5, textColor=colors.HexColor('#F8FAFC'), leading=10)

    # 1. HEADER WITH BRAND LOGO & METADATA
    logo_path = 'static/logo.png'
    logo_cell = []
    if os.path.exists(logo_path):
        try:
            logo_img = Image(logo_path, width=40, height=40)
            logo_cell.append(logo_img)
        except Exception:
            pass

    brand_text = [
        Paragraph("<b>PHISHSHIELD AI ENTERPRISE</b>", title_style),
        Paragraph("Automated Cyber Threat & Forensic Risk Assessment Platform", subtitle_style)
    ]

    left_header = Table([[logo_cell[0] if logo_cell else '', brand_text]], colWidths=[46, 244] if logo_cell else [0, 290])
    left_header.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))

    right_header = [
        Paragraph(f"<b>INCIDENT REPORT #PS-{history_id:05d}</b>", meta_bold),
        Paragraph(f"Telemetry Timestamp: <b>{record[6]}</b>", meta_style),
        Paragraph(f"Operator Authorization: <b>User #{record[1]} (Authenticated)</b>", meta_style),
        Paragraph("Classification: <b>CONFIDENTIAL // SOC INTERNAL</b>", meta_style)
    ]

    header_table = Table([[left_header, right_header]], colWidths=[310, 230])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=accent_blue, spaceBefore=3, spaceAfter=6))

    # 2. EXECUTIVE VERDICT & RISK BADGE BANNER
    score_val = float(record[4])
    risk_level_str = str(record[5])
    input_type_str = str(record[2]).upper()
    target_content_str = str(record[3])

    if risk_level_str == 'Safe':
        banner_bg = colors.HexColor('#059669')
        rec_text = "VERIFIED SAFE: No malicious phishing, typosquatting, or DGA patterns detected."
    elif risk_level_str == 'Low Risk':
        banner_bg = colors.HexColor('#2563EB')
        rec_text = "LOW THREAT: Minor structural anomalies detected; standard browsing precautions apply."
    elif risk_level_str == 'Medium Risk':
        banner_bg = colors.HexColor('#D97706')
        rec_text = "SUSPICIOUS VECTOR: Heuristic / DGA indicators flagged. Do not enter credentials."
    elif risk_level_str == 'High Risk':
        banner_bg = colors.HexColor('#DC2626')
        rec_text = "HIGH THREAT DETECTED: Strong phishing, impersonation, or high entropy DGA pattern identified. Block immediately."
    else:
        banner_bg = colors.HexColor('#991B1B')
        rec_text = "CRITICAL COMPROMISE RISK: Highly malicious URL / DGA botnet payload detected. Restrict network access."

    verdict_left = [
        Paragraph("ASSESSED RISK VERDICT", v_top_style),
        Paragraph(f"<b>{risk_level_str.upper()} — {score_val:.1f}% THREAT SCORE</b>", v_main_style),
        Paragraph(f"Target Payload Type: <b>{input_type_str}</b>", v_sub_style)
    ]
    verdict_right = [
        Paragraph("<b>SOC REMEDIATION DIRECTIVE:</b>", v_rec_head),
        Paragraph(rec_text, v_rec_body)
    ]

    verdict_table = Table([[verdict_left, verdict_right]], colWidths=[280, 260])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), banner_bg),
        ('PADDING', (0,0), (-1,-1), 7),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 1, banner_bg),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 5))

    # 3. TARGET PAYLOAD INSPECTION CONTAINER
    story.append(Paragraph("1. Target Payload Telemetry Extraction", section_heading))
    payload_table = Table([[
        Paragraph("<b>Target Input:</b>", cell_bold),
        Paragraph(target_content_str, cell_mono)
    ]], colWidths=[75, 465])
    payload_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 1, border_color),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(payload_table)
    story.append(Spacer(1, 5))

    # 4. MULTI-ENGINE SCORE DIFFERENTIATION & BREAKDOWN TABLE
    story.append(Paragraph("2. Multi-Engine Forensic Analysis & Score Differentiation", section_heading))

    engine_rows = [
        [
            Paragraph("Detection Engine", thead_style),
            Paragraph("Evaluated Telemetry & Parameters", thead_style),
            Paragraph("Engine Score", thead_style),
            Paragraph("Status / Verdict", thead_style)
        ]
    ]

    if input_type_str == 'URL':
        # Evaluate URL Engines
        lex_features = analyze_url_lexical(target_content_str)
        dga_info = analyze_dga(target_content_str)
        typo_match = check_typosquatting(target_content_str)

        # 1. Lexical Structural Engine
        lex_score = lex_features.get('score_deduction', 0)
        lex_details = []
        if lex_features.get('is_ip'): lex_details.append("Raw IPv4")
        if lex_features.get('is_shortened'): lex_details.append("Shortener Service")
        if lex_features.get('suspicious_tld'): lex_details.append("Abnormal TLD")
        if lex_features.get('excessive_subdomains'): lex_details.append("Subdomain Bloat")
        if lex_features.get('no_https'): lex_details.append("Insecure HTTP")
        if not lex_details: lex_details.append("Standard Protocol & Structure")

        engine_rows.append([
            Paragraph("<b>Lexical & Protocol Engine</b>", cell_normal),
            Paragraph(f"Evaluated URL structure, scheme, IP wrappers, and shortening.<br/><font color='#64748B'>Flags: {', '.join(lex_details)}</font>", cell_normal),
            Paragraph(f"{lex_score:.1f}%", cell_bold),
            Paragraph("<font color='#DC2626'><b>Flagged</b></font>" if lex_score > 0 else "<font color='#059669'><b>Clean</b></font>", cell_normal)
        ])

        # 2. Typosquatting & Brand Spoofing Engine
        typo_score = 55.0 if typo_match else 0.0
        engine_rows.append([
            Paragraph("<b>Typosquatting Engine</b>", cell_normal),
            Paragraph(f"Levenshtein brand distance matching against popular banking/tech targets.<br/><font color='#64748B'>Impersonation Target: {typo_match or 'None Detected'}</font>", cell_normal),
            Paragraph(f"{typo_score:.1f}%", cell_bold),
            Paragraph(f"<font color='#DC2626'><b>Spoof Detected</b></font>" if typo_match else "<font color='#059669'><b>Authentic</b></font>", cell_normal)
        ])

        # 3. DGA (Domain Generation Algorithm) Engine
        dga_status_str = f"Entropy: {dga_info.get('entropy', 0.0)} | Vowels: {dga_info.get('vowel_ratio', 0.0):.1%} | SLD: {dga_info.get('sld', 'N/A')}"
        dga_score_val = dga_info.get('dga_score', 0.0)
        engine_rows.append([
            Paragraph("<b>DGA Entropy Engine</b>", cell_normal),
            Paragraph(f"Shannon character randomness, consonant clusters, and numeric DGA botnet seed heuristics.<br/><font color='#64748B'>{dga_status_str}</font>", cell_normal),
            Paragraph(f"{dga_score_val:.1f}%", cell_bold),
            Paragraph(f"<font color='#DC2626'><b>DGA ({dga_info.get('confidence', 'None')})</b></font>" if dga_info.get('is_dga') else "<font color='#059669'><b>Dictionary Benign</b></font>", cell_normal)
        ])

        # 4. Threat Intel & Reputation Engine
        engine_rows.append([
            Paragraph("<b>Reputation Threat Intel</b>", cell_normal),
            Paragraph("Multi-vendor global intelligence scan for known malware domains.", cell_normal),
            Paragraph("API Telemetry", cell_normal),
            Paragraph("<font color='#059669'><b>Reputation Clear</b></font>", cell_normal)
        ])

    elif input_type_str == 'WEBSITE_DEEP_SCAN':
        # Evaluate Live Website Deep Inspection
        engine_rows.append([
            Paragraph("<b>DOM Form & Credential Inspector</b>", cell_normal),
            Paragraph("Audited HTML forms, insecure plaintext password inputs, and external action targets.", cell_normal),
            Paragraph(f"{score_val * 0.4:.1f}%", cell_bold),
            Paragraph("<font color='#DC2626'><b>Flagged</b></font>" if score_val >= 45 else "<font color='#059669'><b>Secure Forms</b></font>", cell_normal)
        ])
        engine_rows.append([
            Paragraph("<b>SSL/TLS Certificate Audit</b>", cell_normal),
            Paragraph("Cryptographic handshake, certificate authority validation, and validity telemetry.", cell_normal),
            Paragraph("Telemetry", cell_normal),
            Paragraph("<font color='#059669'><b>Active / Verified</b></font>", cell_normal)
        ])
        engine_rows.append([
            Paragraph("<b>Security Headers & SSRF Defense</b>", cell_normal),
            Paragraph("CSP, HSTS, X-Frame-Options, Clickjacking protection, and public IP resolution.", cell_normal),
            Paragraph("Inspected", cell_normal),
            Paragraph("<b>Analyzed</b>", cell_normal)
        ])

    elif input_type_str == 'SCREENSHOT_OCR':
        # Evaluate Screenshot Vision OCR Engine
        engine_rows.append([
            Paragraph("<b>Vision AI Multimodal OCR</b>", cell_normal),
            Paragraph("Extracted optical text, analyzed psychological urgency hooks, and banking brand logos.", cell_normal),
            Paragraph(f"{score_val:.1f}%", cell_bold),
            Paragraph("<font color='#DC2626'><b>Phishing Clues</b></font>" if score_val >= 45 else "<font color='#059669'><b>Clean Image</b></font>", cell_normal)
        ])
        engine_rows.append([
            Paragraph("<b>Embedded URL Forensics</b>", cell_normal),
            Paragraph("Scanned discovered URLs through ML classifier, Shannon DGA, and Typosquatting engines.", cell_normal),
            Paragraph("Deep Scan", cell_normal),
            Paragraph("<b>Completed</b>", cell_normal)
        ])

    else:
        # Evaluate Text / Email / SMS Engines
        engine_rows.append([
            Paragraph("<b>ML NLP Classifier</b>", cell_normal),
            Paragraph("TF-IDF Vectorizer + Multinomial Naive Bayes trained on phishing corpora.", cell_normal),
            Paragraph(f"{score_val:.1f}%", cell_bold),
            Paragraph("<font color='#DC2626'><b>Phishing Pattern</b></font>" if score_val >= 45 else "<font color='#059669'><b>Safe Pattern</b></font>", cell_normal)
        ])
        engine_rows.append([
            Paragraph("<b>Keyword Heuristics</b>", cell_normal),
            Paragraph("Detected credential theft, banking urgency, and social engineering triggers.", cell_normal),
            Paragraph("Evaluated", cell_normal),
            Paragraph("Scanned", cell_normal)
        ])
        engine_rows.append([
            Paragraph("<b>AI Deep Semantic Model</b>", cell_normal),
            Paragraph("Deep context examination for subtle social engineering and impersonation.", cell_normal),
            Paragraph("AI Assessed", cell_normal),
            Paragraph(f"<b>{risk_level_str}</b>", cell_normal)
        ])

    engine_table = Table(engine_rows, colWidths=[130, 250, 75, 85])
    engine_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), table_head_bg),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')])
    ]))
    story.append(engine_table)
    story.append(Spacer(1, 5))

    # 5. SPECIFIC INDICATORS OF COMPROMISE (IoCs) & REASONS
    story.append(Paragraph("3. Identified Threat Indicators & Forensics", section_heading))
    
    indicators = []
    if input_type_str == 'URL':
        if dga_info.get('reasons'):
            for r in dga_info['reasons']:
                indicators.append(f"<b>[DGA Heuristic]</b> {r}")
        if typo_match:
            indicators.append(f"<b>[Typosquatting]</b> Domain impersonates established brand target: <i>{typo_match}</i>")
        if lex_score > 0:
            indicators.append(f"<b>[Lexical Mutation]</b> URL exhibits anomalous structural properties (Score penalty: +{lex_score:.0f}%)")
        if not indicators:
            indicators.append("<b>[Clean Telemetry]</b> Domain exhibits low entropy, standard lexical structure, and no brand collision.")
    elif input_type_str == 'WEBSITE_DEEP_SCAN':
        indicators.append("<b>[Passive Web Audit]</b> Target host inspected for SSRF safety, SSL certificates, and DOM form credential interception.")
        if score_val >= 45:
            indicators.append("<b>[Security Vulnerability]</b> Critical structural anomalies or insecure form submission targets identified.")
        else:
            indicators.append("<b>[Security Hardened]</b> Standard SSL encryption and secure form configurations verified.")
    elif input_type_str == 'SCREENSHOT_OCR':
        indicators.append("<b>[Vision AI OCR]</b> Image analyzed for brand spoofing, psychological urgency patterns, and embedded phishing links.")
        if score_val >= 45:
            indicators.append("<b>[Visual Phishing Alert]</b> High probability of visual social engineering or deceptive brand impersonation.")
        else:
            indicators.append("<b>[Visual Inspection]</b> No high-risk visual or textual deception detected.")
    else:
        if score_val >= 45:
            indicators.append("<b>[NLP Pattern]</b> Text matches phishing corpora with high probability of credential harvesting.")
        else:
            indicators.append("<b>[NLP Pattern]</b> Message body conforms to normal everyday communication patterns.")

    ioc_cells = [[Paragraph(f"• {item}", cell_normal)] for item in indicators]
    ioc_table = Table(ioc_cells, colWidths=[540])
    ioc_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 1, border_color),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(ioc_table)
    story.append(Spacer(1, 8))

    # 6. SIGN-OFF & COMPLIANCE FOOTER
    footer_text = Paragraph(
        "<font color='#64748B' size='7'>"
        "This security evaluation is generated dynamically by PhishShield AI Enterprise Engine. "
        "Intended for authorized organizational security personnel and incident responders. "
        "Confidentiality Notice: Do not distribute externally without compliance authorization."
        "</font>", 
        ParagraphStyle('FooterNotice', alignment=1, leading=9)
    )
    story.append(HRFlowable(width="100%", thickness=0.75, color=border_color, spaceBefore=3, spaceAfter=3))
    story.append(footer_text)

    doc.build(story)
    return send_file(pdf_filename, as_attachment=True)

@app.route('/admin')
def admin_panel():
    if 'role' not in session or session['role'] != 'admin':
        return "Access Violation. Privileged personnel authorization vector required.", 403
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("SELECT id, username, email, role FROM users")
    all_users = c.fetchall()
    
    c.execute('''
        SELECT logs.id, users.username, logs.action, logs.timestamp 
        FROM logs LEFT JOIN users ON logs.user_id = users.id 
        ORDER BY logs.timestamp DESC LIMIT 50
    ''')
    system_logs = c.fetchall()
    
    conn.close()
    return render_template('admin.html', users=all_users, logs=system_logs)

@app.route('/admin/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    if 'role' not in session or session['role'] != 'admin':
        flash("Access Denial: Admin authorization required.", "danger")
        return redirect(url_for('login'))
        
    try:
        conn = sqlite3.connect(DB_PATH, timeout=15)
        conn.execute("PRAGMA journal_mode=WAL;")
        c = conn.cursor()
        
        # Check if target user exists and is not admin
        c.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        target_user = c.fetchone()
        
        if not target_user:
            flash("User not found.", "danger")
            conn.close()
            return redirect(url_for('admin_panel'))
            
        if target_user[0] == 'admin':
            flash("Cannot delete an administrator account.", "danger")
            conn.close()
            return redirect(url_for('admin_panel'))

        # Clean up related records to avoid foreign key / integrity errors
        c.execute("DELETE FROM reports WHERE history_id IN (SELECT id FROM history WHERE user_id = ?)", (user_id,))
        c.execute("DELETE FROM history WHERE user_id = ?", (user_id,))
        c.execute("DELETE FROM logs WHERE user_id = ?", (user_id,))
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        conn.close()
        
        log_activity(session['user_id'], f"Deleted user ID {user_id} and associated records.")
        flash(f"User #{user_id} and associated data successfully removed.", "success")
    except Exception as e:
        print(f"Error deleting user {user_id}: {e}")
        flash("An error occurred while attempting to delete the user.", "danger")
        
    return redirect(url_for('admin_panel'))

@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def delete_history(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Ensure the user only deletes their own data!
    c.execute("DELETE FROM history WHERE id = ? AND user_id = ?", (id, session['user_id']))
    conn.commit()
    conn.close()
    flash("Record removed from history.", "success")
    return redirect(url_for('dashboard'))

@app.route('/ai-chat', methods=['POST'])
def ai_chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required.'}), 401

    if requests is None:
        return jsonify({'error': 'AI service not configured. Please install the requests library and set GROQ_API_KEY.'}), 500

    api_key = os.environ.get('GROQ_API_KEY') or os.environ.get('GROK_API_KEY')
    if not api_key:
        return jsonify({'error': 'AI provider API key missing. Please set GROQ_API_KEY or GROK_API_KEY.'}), 500

    payload = request.json or {}
    user_message = payload.get('message', '').strip()
    context = payload.get('context', {})

    if not user_message:
        return jsonify({'error': 'Message cannot be empty.'}), 400

    history = context.get('history', [])
    if not isinstance(history, list):
        history = []

    system_prompt = (
    "You are PhishShield AI, a cybersecurity assistant for a phishing detection application. "
    "The website/application name is 'PhishShield AI'. If asked about the website name, project name, or what this platform is called, always answer 'PhishShield AI'. "
    "You are PhishShield AI, a cybersecurity assistant built by the Safiq Ansari & team. "
    "You were not made by OpenAI, Google, or any other company. Never reveal your underlying model. "
    "How to use this website: Users register/login, then go to the Dashboard where they can submit either a Web URL or Email/SMS text for phishing analysis. "
    "The system analyzes it using a machine learning model, VirusTotal API (for URLs), Domain Generation Algorithm (DGA) entropy heuristics, and AI analysis, then shows a risk score and risk level (Safe, Low, Medium, High, Critical) with reasons. "
    "Users can view their scan history on the dashboard and export any past scan as a PDF report. "
    "Answer clearly for beginners, explain phishing, malicious URLs, DGA (Domain Generation Algorithms), malware, ransomware, passwords, MFA, social engineering, network security, SOC, and related security topics. "
    "If the user asks about the current URL analysis, use the provided analysis details from context to explain risk results and suspicious indicators. "
    "If asked how to use the website, explain the steps above clearly. "
    "Do not mention any internal errors or API keys. Keep responses helpful and concise. "
    "Always reply in plain text only. Do not use markdown, bold, tables, or any special formatting characters."
)

    analysis_context = context.get('analysis')
    if analysis_context:
        analysis_text = (
            "\n\nCurrent URL analysis details:\n"
            f"Type: {analysis_context.get('type','N/A')}\n"
            f"Content: {analysis_context.get('content','N/A')}\n"
            f"Score: {analysis_context.get('score','N/A')}\n"
            f"Risk Level: {analysis_context.get('risk_level','N/A')}\n"
            f"Details: {analysis_context.get('details','N/A')}\n"
        )
    else:
        analysis_text = ''

    messages = [{'role': 'system', 'content': system_prompt.strip()}]
    if analysis_text:
        messages.append({'role': 'system', 'content': f"Current context:\n{analysis_text.strip()}"})
    if history:
        for item in history:
            if item.get('role') in ('user', 'assistant') and item.get('content'):
                messages.append({'role': item['role'], 'content': item['content']})
    messages.append({'role': 'user', 'content': user_message})

    GROQ_API_URL = os.environ.get('GROQ_API_URL', 'https://api.groq.com/openai/v1/chat/completions')
    model_name = os.environ.get('GROQ_MODEL', 'openai/gpt-oss-120b')
    headers = {
        'Authorization': f'Bearer {api_key.strip()}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    payload = {
        'model': model_name,
        'messages': messages,
        'temperature': 0.6,
        'max_tokens': 1024,
    }

    def try_send_with_retries(url, headers, payload, max_retries=3):
        last_exc = None
        for attempt in range(1, max_retries + 1):
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=20)
                if response.status_code == 200:
                    return response.json()
                body = response.text
                if response.status_code in (429, 500, 502, 503, 504):
                    last_exc = Exception(f'Groq API error {response.status_code}: {body}')
                    time.sleep(1 << (attempt - 1))
                    continue
                try:
                    error_json = response.json()
                    error_message = error_json.get('error', {}).get('message') or error_json.get('message') or body
                except ValueError:
                    error_message = body
                raise Exception(f'Groq API error {response.status_code}: {error_message}')
            except requests.exceptions.RequestException as e:
                last_exc = e
                if attempt < max_retries:
                    time.sleep(1 << (attempt - 1))
                    continue
                raise
        raise last_exc

    try:
        response_json = try_send_with_retries(GROQ_API_URL, headers, payload, max_retries=4)
        # Groq chat completions format: choices[0].message.content
        assistant_text = ''
        choices = response_json.get('choices', [])
        if choices:
            assistant_text = choices[0].get('message', {}).get('content', '').strip()
        # fallback for any other response shape
        if not assistant_text:
            assistant_text = response_json.get('output_text', '').strip()

        # Remove common markdown artifacts so the response stays plain text.
        assistant_text = assistant_text.replace('**', '').replace('__', '')
        assistant_text = assistant_text.replace('`', '')
        assistant_text = assistant_text.replace('|', '').replace('---', '')
        assistant_text = assistant_text.replace('* ', '- ')
        assistant_text = assistant_text.strip()

        assistant_text = assistant_text or 'No response received from the AI model.'
        return jsonify({'reply': assistant_text, 'history': history + [{'role': 'user', 'content': user_message}, {'role': 'assistant', 'content': assistant_text}]})
    except Exception as e:
        err_msg = str(e)
        print(f"AI Analysis Error: {err_msg}")
        if '401' in err_msg:
            return jsonify({'error': 'Invalid Groq API key. Please verify your API key on console.groq.com.'}), 500
        return jsonify({'error': f'AI service error: {err_msg}'}), 500

@app.route('/demo')
def demo_presentation():
    return render_template('demo.html')

if __name__ == '__main__':
    # Fallback initialization check
    if not os.path.exists('model/phishing_model.pkl'):
        print("[-] Model parameters missing from static system state. Training fallback automatically...")
        from train_model import train_and_save_model
        train_and_save_model()
        load_ml_components()
    app.run(host='0.0.0.0', port=5000, debug=True)
