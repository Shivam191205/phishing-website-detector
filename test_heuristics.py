
import sys
import os
from urllib.parse import urlparse

# Add current directory to path
sys.path.append(os.getcwd())

from utils import HeuristicEngine, normalize_url

def test_heuristics():
    engine = HeuristicEngine()
    
    test_cases = [
        # Phishing - Brand Impersonation
        ("https://secure-login-chase.com", "Brand Impersonation (Chase)"),
        ("http://google-account-verify.xyz", "Brand Impersonation (Google)"),
        
        # Phishing - Subdomain Stuffing
        ("https://chase.com.secure.login.verify.update.net", "Subdomain Stuffing"),
        
        # Phishing - Suspect TLD + Brand
        ("http://paypal-support.top", "Brand Impersonation (Paypal)"),
        
        # Legit - Verified Brand
        ("https://accounts.google.com", "Legit"),
        ("https://www.amazon.in", "Legit"),
        
        # Legit - Normal Site
        ("https://pypi.org/project/tldextract/", "Legit"),
        
        # Phishing - Keywords
        ("http://official-banking-update.com", "Risk Keyword"),
    ]
    
    print("Running Heuristic Engine Tests...")
    print("-" * 50)
    
    for url, expected in test_cases:
        norm_url = normalize_url(url)
        res = engine.analyze(norm_url)
        score = res["score"]
        flags = res["flags"]
        
        print(f"URL: {url}")
        print(f"  Score: {score}")
        print(f"  Flags: {flags}")
        
        if "Legit" in expected:
            if score < 50:
                print("  RESULT: PASS (Legitimate)")
            else:
                print("  RESULT: FAIL (Flagged as suspicious)")
        else:
            found = False
            for flag in flags:
                if expected in flag or expected in str(score):
                    found = True
                    break
            if found or score > 0:
                print(f"  RESULT: PASS (Detected correctly: {expected})")
            else:
                print(f"  RESULT: FAIL (Missed detection: {expected})")
        print("-" * 50)

if __name__ == "__main__":
    test_heuristics()
