"""
VirusTotal Accuracy Evaluation Script
--------------------------------------
Tests VirusTotal's detection accuracy against a labeled set of known
phishing and known safe URLs, and prints accuracy/precision/recall.

Usage:
    1. Set your VIRUSTOTAL_API_KEY as an environment variable, or paste it below.
    2. Run: python evaluate_virustotal.py
"""

import os
import time
import requests

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "932833c0dceb0cf188690693ac2db5dfd128eca3ece93d5c6a4e42b5798f21b1")
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"

# --- Labeled test set ---
# label: 1 = known phishing/malicious, 0 = known safe
# Replace/expand this list with your own verified samples
# (e.g. recent verified entries from https://phishtank.org for phishing,
#  and well-known legitimate sites for safe)
test_urls = [
    # Known SAFE
    {"url": "https://www.google.com", "label": 0},
    {"url": "https://www.github.com", "label": 0},
    {"url": "https://www.wikipedia.org", "label": 0},
    {"url": "https://www.microsoft.com", "label": 0},
    {"url": "https://www.amazon.com", "label": 0},

    # Known PHISHING (fresh from PhishTank, Aug 12 2026)
    {"url": "https://firststepfloors.com/", "label": 1},
    {"url": "https://headshotsandcorporate.com/", "label": 1},
    {"url": "https://uhk-c-z.weebly.com", "label": 1},
    {"url": "https://outloowba.netlify.app", "label": 1},
    {"url": "https://bhd660bf367144d4ac0b5e290f.xo.je", "label": 1},
]


def scan_url(url):
    headers = {"x-apikey": API_KEY}
    # Submit the URL
    resp = requests.post(VT_URL_SCAN, headers=headers, data={"url": url})
    resp.raise_for_status()
    analysis_id = resp.json()["data"]["id"]

    # Poll for the analysis result
    result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(10):
        time.sleep(2)
        r = requests.get(result_url, headers=headers)
        r.raise_for_status()
        data = r.json()["data"]["attributes"]
        if data["status"] == "completed":
            stats = data["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return 1 if (malicious > 0 or suspicious > 0) else 0
    return None  # timed out


def main():
    if API_KEY == "PASTE_YOUR_KEY_HERE":
        print("Set your VIRUSTOTAL_API_KEY first.")
        return

    tp = tn = fp = fn = 0
    print(f"{'URL':<45} {'True':<8} {'VT Verdict':<12}")
    print("-" * 70)

    for item in test_urls:
        url, true_label = item["url"], item["label"]
        try:
            pred = scan_url(url)
        except Exception as e:
            print(f"{url:<45} ERROR: {e}")
            continue

        pred_str = "Malicious" if pred == 1 else "Clean"
        true_str = "Phishing" if true_label == 1 else "Safe"
        print(f"{url:<45} {true_str:<8} {pred_str:<12}")

        if pred == 1 and true_label == 1: tp += 1
        elif pred == 0 and true_label == 0: tn += 1
        elif pred == 1 and true_label == 0: fp += 1
        elif pred == 0 and true_label == 1: fn += 1

        time.sleep(15)  # free-tier VT API rate limit: 4 requests/min

    total = tp + tn + fp + fn
    if total == 0:
        print("No results collected.")
        return

    accuracy = (tp + tn) / total * 100
    precision = (tp / (tp + fp) * 100) if (tp + fp) else 0
    recall = (tp / (tp + fn) * 100) if (tp + fn) else 0

    print("\n--- VirusTotal Detection Performance ---")
    print(f"Total tested : {total}")
    print(f"Accuracy     : {accuracy:.2f}%")
    print(f"Precision    : {precision:.2f}%")
    print(f"Recall       : {recall:.2f}%")
    print(f"TP={tp}  TN={tn}  FP={fp}  FN={fn}")


if __name__ == "__main__":
    main()
