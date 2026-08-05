import os
import re
import sqlite3
import pickle
import numpy as np
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = Flask(__name__)
app.secret_key = 'CYBERSECURITY_SECRET_KEY_2026_PROJ'
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
    
    # Create default admin account if not present
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        hashed_pw = generate_password_hash("admin123")
        cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", 
                       ('admin', 'admin@cyberdefense.local', hashed_pw, 'admin'))
    
    conn.commit()
    conn.close()

init_db()
load_ml_components()

# --- URL Analysis Helper Engine ---
def analyze_url_lexical(url):
    # ---------------------------------------------------------
    # 1. ENTERPRISE TRUSTED DOMAIN WHITELIST
    # ---------------------------------------------------------
    clean_url = url.lower().strip()
    trusted_domains = ['youtube.com', 'google.com', 'github.com', 'linkedin.com', 'wikipedia.org', 'https://ai-based-phishing-detection-el4j.onrender.com/dashboard', 'https://chatgpt.com/', 'https://gemini.google.com/', 'https://dashboard.render.com/', 'https://www.instagram.com/', 'https://github.com/']
    domain_part = clean_url.replace('https://', '').replace('http://', '').split('/')[0]
    
    for safe_domain in trusted_domains:
        if safe_domain in domain_part:
            return {
                "is_ip": 0, "is_shortened": 0, "suspicious_tld": 0,
                "excessive_subdomains": 0, "no_https": 0, 
                "score_deduction": 0,
                "is_whitelisted": True  # Custom bypass flag for the route
            }
    # ---------------------------------------------------------

    # 2. Your core lexical analysis rules continue here
    report = {
        "is_ip": 0, "is_shortened": 0, "suspicious_tld": 0,
        "excessive_subdomains": 0, "no_https": 0, "score_deduction": 0
    }
    
    # Check IP-based URLs
    ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    if ip_pattern.match(url):
        report["is_ip"] = 1
        report["score_deduction"] += 30
        
    # Check Shortening Services
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'adf.ly']
    if any(s in url.lower() for s in shorteners):
        report["is_shortened"] = 1
        report["score_deduction"] += 25
        
    # Check Suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.club', '.gq', '.ml', '.cf', '.tk', '.info', '.download']
    if any(url.lower().endswith(tld) or tld + '/' in url.lower() for tld in suspicious_tlds):
        report["suspicious_tld"] = 1
        report["score_deduction"] += 20
        
    # Check Excessive Subdomains
    clean_url_parts = url.replace("https://", "").replace("http://", "")
    domain_part = clean_url_parts.split('/')[0]
    subdomains = domain_part.split('.')
    if len(subdomains) > 4:
        report["excessive_subdomains"] = 1
        report["score_deduction"] += 15
        
    # Check HTTPS usage
    if url.lower().startswith("http://"):
        report["no_https"] = 1
        report["score_deduction"] += 10
        
    return report


def calculate_risk_level(score):
    if score < 20: return "Safe"
    elif score < 45: return "Low Risk"
    elif score < 70: return "Medium Risk"
    elif score < 90: return "High Risk"
    else: return "Critical"

# --- System Audit Logger ---
def log_activity(user_id, action):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
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

            # --- START OF THE NEW CODE YOU PASTE ---
            trusted_domains = ['youtube.com', 'google.com', 'github.com', 'linkedin.com', 'wikipedia.org']
            is_whitelisted = False
            
            if input_type == 'url':
                for domain in trusted_domains:
                    if domain in content.lower():
                        is_whitelisted = True
                        break

            base_score = 0.0
            
            if is_whitelisted:
                base_score = 0.0
                risk_level = "Safe"
            else:
                if model and vectorizer and content:
                    vectorized_input = vectorizer.transform([content])
                    base_score = float(model.predict_proba(vectorized_input)[0][1] * 100)
                else:
                    suspicious_keywords = ['verify', 'bank', 'secure', 'login', 'wp-admin', 'paypal', 'giftcard', 'free']
                    match_count = sum(1 for word in suspicious_keywords if word in content.lower())
                    base_score = min(match_count * 25.0, 100.0)

                if input_type == 'url':
                    url_features = analyze_url_lexical(content)
                    base_score = min(base_score + url_features["score_deduction"], 100.0)

                risk_level = calculate_risk_level(base_score)
            # --- END OF THE NEW CODE ---

            # Save into processing history pipeline (Your original code continues here)
            c.execute("INSERT INTO history (user_id, input_type, content, score, risk_level) VALUES (?, ?, ?, ?, ?)",
                      (session['user_id'], input_type, content, base_score, risk_level))
            conn.commit()
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
    c.execute("SELECT * FROM history WHERE id = ?", (history_id,))
    record = c.fetchone()
    conn.close()
    
    if not record:
        return "Record resolution trace missing.", 404
        
    # Generate Dynamic PDF Content via ReportLab pipeline
    pdf_filename = f"reports/CyberReport_{history_id}.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
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

@app.route('/admin/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'role' not in session or session['role'] != 'admin':
        return "Access Denial Matrix Activated.", 403
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/delete/<int:id>')
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
if __name__ == '__main__':
    # Fallback initialization check
    if not os.path.exists('model/phishing_model.pkl'):
        print("[-] Model parameters missing from static system state. Training fallback automatically...")
        from train_model import train_and_save_model
        train_and_save_model()
        load_ml_components()
    app.run(host='0.0.0.0', port=5000, debug=True)
