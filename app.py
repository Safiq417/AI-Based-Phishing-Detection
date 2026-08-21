import os
import re
import sqlite3
import pickle
import numpy as np
from datetime import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher
import time
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify

try:
    import requests
except ImportError:
    requests = None
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

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
    hashed_pw = generate_password_hash("Safiq#Team@7003")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", 
                       ('admin', 'admin@cyberdefense.local', hashed_pw, 'admin'))
    else:
        cursor.execute("UPDATE users SET password = ? WHERE username = 'admin'", (hashed_pw,))
    
    conn.commit()
    conn.close()

init_db()
load_ml_components()

# --- URL Analysis Helper Engine ---
def is_valid_url(url):
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ('http', 'https'):
            return False
        if not parsed.netloc:
            return False
        if parsed.netloc.startswith('.') or parsed.netloc.endswith('.'):
            return False
        if '@' in parsed.netloc and parsed.hostname is None:
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
        domain = (urlparse(url).hostname or '').lower().replace('www.', '')
    except Exception:
        return None
    if not domain:
        return None  # empty domain
    # If the domain is exactly a popular domain or a legitimate subdomain of one, it is authentic
    for legit in POPULAR_DOMAINS:
        if domain == legit or domain.endswith('.' + legit):
            return None
    for legit in POPULAR_DOMAINS:
        legit_name = legit.split('.')[0]
        ratio = SequenceMatcher(None, domain, legit).ratio()
        if ratio > 0.75:
            return legit
        if len(legit_name) >= 4 and legit_name in domain:
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
        model_name = os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile')
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

        if input_type == 'url' and not is_valid_url(content):
            flash("Invalid URL format. Please submit a full URL beginning with http:// or https://", "danger")
            conn.close()
            return redirect(url_for('dashboard'))

        if input_type == 'text' and is_valid_url(content):
            flash("You entered a URL but selected Email / SMS Content. Please switch Payload Type to Web URL.", "danger")
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
        
    # Generate Dynamic PDF Content via ReportLab pipeline
    pdf_filename = f"reports/CyberReport_{history_id}.pdf"
    
    # Track PDF report in reports table
    c.execute("INSERT INTO reports (history_id, file_path) VALUES (?, ?)", (history_id, pdf_filename))
    conn.commit()
    conn.close()

    doc = SimpleDocTemplate(
        pdf_filename, 
        pagesize=letter,
        title=f"PhishShield Security Report #{history_id}",
        author="PhishShield AI Enterprise"
    )
    styles = getSampleStyleSheet()
    story = []
    
    # Custom Theme Styling
    title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], textColor=colors.HexColor('#0F172A'), spaceAfter=20)
    normal_style = styles['Normal']
    
    story.append(Paragraph("AI-BASED PHISHING DETECTION SYSTEM RISK REPORT", title_style))
    story.append(Spacer(1, 15))
    
    report_data = [
        [Paragraph("<b>Metric Identification Field</b>", normal_style), Paragraph("<b>Evaluated Extraction Logs</b>", normal_style)],
        [Paragraph("Analysis Vector Domain Type", normal_style), Paragraph(str(record[2]).upper(), normal_style)],
        [Paragraph("Payload Target String Content", normal_style), Paragraph(str(record[3]), normal_style)],
        [Paragraph("Calculated Threat Score Profile", normal_style), Paragraph(f"{record[4]:.2f}%", normal_style)],
        [Paragraph("Assigned Classification Level Matrix", normal_style), Paragraph(str(record[5]), normal_style)],
        [Paragraph("System Telemetry Timestamp", normal_style), Paragraph(str(record[6]), normal_style)]
    ]
    
    t = Table(report_data, colWidths=[200, 300])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (1,0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0,0), (1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')])
    ]))
    story.append(t)
    
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
    "The system analyzes it using a machine learning model, VirusTotal API (for URLs), and AI analysis, then shows a risk score and risk level (Safe, Low, Medium, High, Critical) with reasons. "
    "Users can view their scan history on the dashboard and export any past scan as a PDF report. "
    "Answer clearly for beginners, explain phishing, malicious URLs, malware, ransomware, passwords, MFA, social engineering, network security, SOC, and related security topics. "
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
    model_name = os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile')
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

if __name__ == '__main__':
    # Fallback initialization check
    if not os.path.exists('model/phishing_model.pkl'):
        print("[-] Model parameters missing from static system state. Training fallback automatically...")
        from train_model import train_and_save_model
        train_and_save_model()
        load_ml_components()
    app.run(host='0.0.0.0', port=5000, debug=True)