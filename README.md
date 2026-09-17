# 🛡️ PhishShield AI
**Next-Generation Phishing Detection & Digital Forensics Platform**

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-black)
![AI](https://img.shields.io/badge/AI-Groq%20%7C%20Qwen-orange)
![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-brightgreen)
![Status](https://img.shields.io/badge/Status-Active-success)

PhishShield AI is an intelligent cyber defense application that utilizes multimodal machine learning architectures, Domain Generation Algorithm (DGA) detection, and automated heuristic parsing to defend against zero-day phishing attacks, malicious URLs, and deceptive screenshots.

---

## ✨ Core Features

### 🔍 Multimodal Vision OCR (AI Screenshot Analyzer)
* **Image Forensics:** Upload screenshots of suspicious emails, SMS messages, or fake login pages.
* **Deep OCR:** Leverages the **Qwen-3.8-27b Vision Model** (via Groq) to extract embedded text.
* **Threat Recognition:** Automatically detects deceptive urgency ("Account Suspended!"), impersonated brands (e.g., SBI, PayPal), and hidden malicious URLs directly from pixels.

### 🌐 Advanced Website Inspector
* **DGA Engine:** Evaluates Shannon entropy, vowel-to-consonant ratios, and unusual consonant clusters to flag Algorithmically Generated Domains used by botnets.
* **Lexical Mutation Parsing:** Detects IP-based routing, URL shortening abuse, excessive subdomains, and obfuscated paths.
* **Passive SSL & Geo-IP Recon:** Safely extracts SSL certificate validity, server geolocations, and hosting ASN data without directly risking the client.

### 🤖 Intelligent Cyber Assistant (AI Chat)
* Features an embedded, context-aware cybersecurity chatbot.
* Analyzes your recent scan results, explains phishing concepts, and provides actionable defensive advice in real-time using high-speed LLMs.

### 📊 Enterprise Dashboards & PDF Reporting
* **Interactive Dashboard:** Beautiful glassmorphism UI offering real-time threat statistics, scan history, and role-based access.
* **1-Click PDF Reports:** Instantly generate professional, structured PDF forensic reports for any scan (built with ReportLab).
* **Admin Control Center:** Manage users, monitor live system audit logs, and trigger emergency data wipes if compromised.

---

## 🔒 Security Architecture
* **Protection Mechanisms:** Fully integrated CSRF tokens (Flask-WTF), Rate Limiting, strict Content Security Policies (CSP), XSS sanitization, and SQL Injection prevention.
* **Concurrency Safe:** Utilizes SQLite WAL (Write-Ahead Logging) to ensure zero database deadlocks during multi-user concurrent traffic.
* **SSRF Prevention:** Implements strict timeouts to prevent self-scraping deadlocks and tarpitting.

---

## 🚀 Local Deployment Instructions

### 1. Clone & Initialize Virtual Environment
```bash
git clone https://github.com/Safiq417/AI-Based-Phishing-Detection.git
cd AI-Based-Phishing-Detection

# Create and activate virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API Keys
Create a `.env` file in the root directory (or export them to your system environment) and add the following keys:
```env
# Required for Vision AI & Chatbot
GROQ_API_KEY=your_groq_api_key_here
# Fallback/Dedicated Vision Key (Optional)
PhishShield_Vision_OCR=your_groq_vision_key_here

# Recommended for Deep File Scanning
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Flask App Secret (Generate a secure random string)
SECRET_KEY=your_super_secret_key
# Default Admin Password
ADMIN_PASSWORD=your_secure_password
```

### 4. Run the Application
```bash
python app.py
```
*The server will start at `http://127.0.0.1:5000`.*

---

## 👨‍💻 Developer & Team
Built by **Safiq Ansari & Team**. 
*Designed to demonstrate the integration of Modern LLMs with classical cybersecurity heuristics.*