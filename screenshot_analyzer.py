import os
import re
import io
import json
import base64
import requests
from PIL import Image
from urllib.parse import urlparse

DEFAULT_VISION_MODELS = [
    os.environ.get("GROQ_VISION_MODEL", "llama-3.2-90b-vision-preview"),
    "llama-3.2-11b-vision-preview",
    "qwen/qwen3.6-27b",
    "meta-llama/llama-4-scout-17b-16e-instruct"
]

SUSPICIOUS_IMAGE_KEYWORDS = [
    "account suspended", "kyc pending", "urgent verification", "unauthorized login",
    "click here", "lottery winner", "income tax refund", "debit card blocked",
    "otp", "update pan", "security alert", "password expired", "limited time",
    "claim reward", "verify identity", "bank alert", "unusual activity"
]

def optimize_image_for_vision(image_bytes, max_size=(1280, 1280)):
    """
    Validates, strips metadata, resizes if needed, and returns base64 string.
    """
    img = Image.open(io.BytesIO(image_bytes))
    if img.mode in ('RGBA', 'LA', 'P'):
        img = img.convert('RGB')
    
    img.thumbnail(max_size, Image.Resampling.LANCZOS)
    
    buf = io.BytesIO()
    img.save(buf, format='JPEG', quality=85)
    optimized_bytes = buf.getvalue()
    b64_str = base64.b64encode(optimized_bytes).decode('utf-8')
    return b64_str, img.size

def extract_urls_from_text(text):
    """
    Extracts URLs, web domains, and IP addresses from OCR / vision output text.
    """
    url_pattern = r'(?:https?:\/\/|www\.)[^\s<>"\'\(\)]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/[^\s<>"\'\(\)]*)?'
    found = re.findall(url_pattern, text)
    cleaned = []
    for raw in found:
        u = raw.strip('.,;:!?)"\'')
        if len(u) > 3 and not u.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
            cleaned.append(u)
    return list(dict.fromkeys(cleaned))

def get_vision_api_key():
    if os.path.exists('.env'):
        try:
            with open('.env', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        k = k.strip()
                        v = v.strip().strip('"\'')
                        if k and v:
                            os.environ[k] = v
        except Exception:
            pass
    return os.environ.get('PhishShield_Vision_OCR') or os.environ.get('PhishShield_Visio') or os.environ.get('VISION_API_KEY') or os.environ.get('GROQ_VISION_KEY') or os.environ.get('GROQ_API_KEY') or os.environ.get('GROK_API_KEY') or os.environ.get('XAI_API_KEY') or ''

def call_groq_vision_api(base64_image, groq_api_key):
    """
    Calls Vision endpoint (Groq or xAI Grok) to forensically inspect screenshot.
    """
    headers = {
        "Authorization": f"Bearer {groq_api_key.strip()}",
        "Content-Type": "application/json"
    }

    prompt = (
        "You are an expert Cyber Threat & Digital Forensics Analyst inspecting an uploaded screenshot (e.g. email, SMS, fake login page, or QR code).\n"
        "Extract all readable text, analyze social engineering tactics, look for brand impersonation (e.g. SBI, HDFC, PayPal, Netflix, Google), and identify any suspicious URLs or phone numbers.\n\n"
        "Respond ONLY in valid JSON matching this exact schema:\n"
        "{\n"
        '  "extracted_text": "Full text transcript found in the image",\n'
        '  "is_phishing_detected": true/false,\n'
        '  "confidence_score": 0 to 100,\n'
        '  "impersonated_brand": "Brand Name or None",\n'
        '  "threat_indicators": ["List of suspicious cues found in image"],\n'
        '  "extracted_urls": ["List of URLs found"],\n'
        '  "summary_verdict": "Clear 2-sentence explanation of the forensic findings."\n'
        "}"
    )

    if groq_api_key.startswith('xai-'):
        endpoint = "https://api.x.ai/v1/chat/completions"
        candidate_models = ["grok-2-vision-1212"]
    else:
        endpoint = "https://api.groq.com/openai/v1/chat/completions"
        candidate_models = DEFAULT_VISION_MODELS

    for model_name in candidate_models:
        payload = {
            "model": model_name,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{base64_image}"
                            }
                        }
                    ]
                }
            ],
            "temperature": 0.1,
            "max_tokens": 1000,
            "response_format": {"type": "json_object"}
        }

        try:
            resp = requests.post(endpoint, headers=headers, json=payload, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return json.loads(content), model_name
            else:
                # Print the actual API error (e.g. model_decommissioned, invalid_api_key,
                # rate_limit_exceeded) instead of silently moving on -- this is the
                # single most useful line for debugging "OCR not working".
                print(f"[-] Vision model {model_name} returned HTTP {resp.status_code}: {resp.text[:500]}. Trying next...")
                continue
        except Exception as e:
            print(f"[-] Vision model {model_name} failed: {e}. Trying next...")
            continue

    return None, None

def analyze_screenshot(image_bytes, filename="", groq_api_key=None):
    """
    Master screenshot forensic analyzer:
    1. Image optimization
    2. Vision AI multimodal inspection (or heuristic fallback)
    3. URL extraction & threat scoring
    """
    if not groq_api_key:
        groq_api_key = get_vision_api_key()
    report = {
        "filename": filename or "screenshot.jpg",
        "image_size": [0, 0],
        "analysis_engine": "Local Heuristic Vision Fallback",
        "extracted_text": "",
        "detected_urls": [],
        "impersonated_brand": "None",
        "threat_indicators": [],
        "threat_score": 0.0,
        "risk_level": "SAFE",
        "is_safe": True,
        "summary": "No malicious indicators detected in image."
    }

    try:
        b64_img, img_dimensions = optimize_image_for_vision(image_bytes)
        report["image_size"] = list(img_dimensions)
        report["thumbnail_base64"] = b64_img
    except Exception as e:
        report["is_safe"] = False
        report["threat_score"] = 50.0
        report["risk_level"] = "SUSPICIOUS"
        report["threat_indicators"].append(f"Image parsing error: {str(e)}")
        return report

    # Check if Groq Vision is available
    vision_result = None
    used_model = None
    if groq_api_key:
        vision_result, used_model = call_groq_vision_api(b64_img, groq_api_key)

    if vision_result:
        report["analysis_engine"] = f"Multimodal AI Engine ({used_model})"
        report["extracted_text"] = vision_result.get("extracted_text", "No text detected.")
        report["impersonated_brand"] = vision_result.get("impersonated_brand", "None")
        report["detected_urls"].extend(vision_result.get("extracted_urls", []))
        if not report["detected_urls"]:
            report["detected_urls"] = extract_urls_from_text(report["extracted_text"])
        report["threat_indicators"].extend(vision_result.get("threat_indicators", []))
        report["summary"] = vision_result.get("summary_verdict", "")
        report["ai_analysis_available"] = True

        base_score = float(vision_result.get("confidence_score", 0.0))
        if vision_result.get("is_phishing_detected"):
            base_score = max(base_score, 75.0)
        report["threat_score"] = base_score

    else:
        # Fallback heuristic analysis (e.g. when offline or API key missing)
        report["analysis_engine"] = "Local Heuristic Pattern Engine"
        report["extracted_text"] = "Image processed via local heuristic parser (Vision API Key missing, invalid, or rate-limited)."
        report["ai_analysis_available"] = False
        
        # Check image metadata / dimensions / aspect ratio
        w, h = img_dimensions
        if h > w * 1.8:
            report["threat_indicators"].append("Mobile SMS / WhatsApp screenshot aspect ratio format detected.")

    # Check suspicious keywords in extracted text
    text_lower = report["extracted_text"].lower()
    for kw in SUSPICIOUS_IMAGE_KEYWORDS:
        if kw in text_lower and kw not in [ti.lower() for ti in report["threat_indicators"]]:
            report["threat_indicators"].append(f"Urgent Psychological Hook: '{kw.title()}'")
            report["threat_score"] += 15.0

    # Normalize score & risk level
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