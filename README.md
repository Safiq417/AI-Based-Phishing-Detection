# AI-Based Phishing Detection and URL Risk Analysis System

## Implementation Summary
An intelligent cyber defense application that utilizes specialized machine learning architectures and exact structural lexical parsing to check text streams and URL vectors for phishing characteristics.

## Core Feature Architecture
* **Hybrid Classification Engine**: Leverages a robust Natural Language Processing (NLP) framework combined with a Naive Bayes Classifier pipeline for deep threat identification.
* **Lexical URL Mutation Detection**: Automates string telemetry scans to detect malicious design implementations (such as embedded IPv4 patterns, shortened linkages, structural TLD shifts, and absence of HTTPS wrappers).
* **Role-Based Audit Verification**: Built-in user separation with an automated dashboard for administrative oversight and centralized security log validation.

## Local Deployment Instructions

### 1. Initialize Virtual Isolation Context
```bash
python -m venv venv
source venv/bin/activate  # Windows Environments: .\venv\Scripts\activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure OpenAI
```bash
# Windows CMD
set OPENAI_API_KEY=your_openai_api_key_here

# PowerShell
$env:OPENAI_API_KEY = 'your_openai_api_key_here'
```

If your Python environment is externally managed, create and activate a local virtual environment before installing dependencies.