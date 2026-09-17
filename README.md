# 🛡️ PhishShield AI
**Enterprise-Grade Phishing Detection, Browser Security & Digital Forensics Platform**

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-black)
![AI](https://img.shields.io/badge/AI-Groq%20%7C%20Qwen-orange)
![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-brightgreen)
![Status](https://img.shields.io/badge/Status-Active-success)

PhishShield AI is an intelligent cyber defense ecosystem that utilizes multimodal machine learning architectures, real-time DOM forensics, and Generative AI to defend against zero-day phishing attacks, deceptive URLs, and malicious screenshots.

---

## 🚀 Core Features

### 🧩 1. The Chrome Extension (Real-Time Endpoint Protection)
* **Live Browser Scanning:** Scan any webpage you visit with a single click.
* **DOM Forensics:** Deeply analyzes the page source to find Hidden iFrames (Clickjacking), external password forms, and deceptive patterns.
* **Smart Caching:** Built-in memory caching allows instantly returning results for known URLs without overloading the server.
* **Beautiful UI:** Modern Glassmorphism UI that integrates smoothly with your browser.

### 👁️ 2. Multimodal Vision OCR (AI Screenshot Analyzer)
* **Image Forensics:** Upload screenshots of suspicious emails, SMS messages, or fake login pages.
* **Deep OCR:** Leverages the **Qwen-3.8-27b Vision Model** (via Groq) to extract embedded text.
* **Threat Recognition:** Automatically detects deceptive urgency ("Account Suspended!"), impersonated brands (e.g., SBI, PayPal), and hidden malicious URLs directly from pixels.

### 🌐 3. Tri-Layer Website Inspector
* **Lexical Mutation Parsing:** Detects IP-based routing, URL shortening abuse, excessive subdomains, and obfuscated paths.
* **Machine Learning:** Evaluates Shannon entropy, vowel-to-consonant ratios, and unusual consonant clusters to flag Algorithmically Generated Domains (DGA) used by botnets.
* **Passive SSL & Geo-IP Recon:** Safely extracts SSL certificate validity and server geolocations without directly risking the client.

### 🤖 4. Intelligent Cyber Assistant (AI Chat)
* Features an embedded, context-aware cybersecurity chatbot in the dashboard.
* Analyzes your recent scan results, explains phishing concepts, and provides actionable defensive advice in real-time.

### 📊 5. Enterprise Dashboards & PDF Reporting
* **Interactive Dashboard:** Dark/Light mode glassmorphism UI offering real-time threat statistics and history.
* **1-Click PDF Reports:** Instantly generate professional, structured PDF forensic reports for any scan.

---

## 🔒 Security & Scalability Architecture
* **API Protection:** The extension API is fortified with Rate Limiting (Flask-Limiter) to prevent DDoS and spam.
* **Memory Caching:** 1-hour TTL caching for URLs ensures zero-latency responses for repeated scans.
* **Protection Mechanisms:** Fully integrated CSRF tokens (Flask-WTF), strict Content Security Policies (CSP), XSS sanitization, and SQL Injection prevention.
* **Concurrency Safe:** Utilizes SQLite WAL (Write-Ahead Logging) to ensure database stability.

---

## 💻 Local Deployment Instructions

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

### 4. Run the Backend Server
```bash
python app.py
```
*The server will start at `http://127.0.0.1:5000`.*

---

## 🧩 How to Install the Chrome Extension

1. Open Google Chrome and go to `chrome://extensions/`.
2. Turn on **"Developer mode"** (toggle in the top right corner).
3. Click on **"Load unpacked"**.
4. Select the `chrome_extension` folder located inside this project repository.
5. Pin the **PhishShield AI** icon to your toolbar and start scanning!

*(Note: Ensure the backend server is running or deployed live for the extension to communicate).*

---

## 👨‍💻 Developer & Team
Built by **Safiq Ansari & Team**. 
*Designed to demonstrate the integration of Modern LLMs with classical cybersecurity heuristics and real-time browser protection.*
