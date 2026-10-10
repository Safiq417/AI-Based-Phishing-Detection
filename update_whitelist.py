import os
import requests
import zipfile
import io

def download_tranco_list():
    print("[*] Downloading Tranco Top 1M list...")
    # The daily Tranco list URL
    url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        
        print("[*] Extracting and processing domains...")
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            filename = z.namelist()[0]
            with z.open(filename) as f:
                domains = set()
                # We'll take the top 100,000 to keep memory footprint low but still vastly better than 30
                for i, line in enumerate(f):
                    if i >= 100000:
                        break
                    # Line format: "1,google.com"
                    domain = line.decode('utf-8').strip().split(',')[1]
                    domains.add(domain)
        
        os.makedirs('database', exist_ok=True)
        with open('database/tranco_whitelist.txt', 'w', encoding='utf-8') as f:
            for domain in domains:
                f.write(domain + '\n')
                
        print(f"[+] Successfully saved {len(domains)} domains to database/tranco_whitelist.txt")
        
    except Exception as e:
        print(f"[-] Failed to download Tranco list: {e}")

if __name__ == '__main__':
    download_tranco_list()
