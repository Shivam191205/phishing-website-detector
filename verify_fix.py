
import sys
import os
from urllib.parse import urlparse
import requests

# Add current directory to path
sys.path.append(os.getcwd())

from URLFeatureExtraction import *
from utils import normalize_url, rule_based_check

def test_system(url, expected_label="Legitimate"):
    print(f"Testing URL: {url}")
    
    # 1. Normalize
    norm_url = normalize_url(url)
    print(f"  Normalized URL: {norm_url}")
    
    # 2. Rule-based check
    rule_res = rule_based_check(norm_url)
    if rule_res == 0:
        print(f"  Rule-based: Legitimate (CORRECT)")
    elif rule_res == 1:
        print(f"  Rule-based: Phishing")
    else:
        print(f"  Rule-based: None (Passed to Model)")
        
    # 3. Feature extraction (for those that pass to model)
    if rule_res is None:
        try:
            response = requests.get(norm_url, timeout=5)
        except:
            response = ""
            
        feat_iframe = iframe(response)
        feat_traffic = web_traffic(norm_url)
        print(f"  IFrame Feature: {feat_iframe} (Expected 0 for most legit)")
        print(f"  Traffic Feature: {feat_traffic} (Expected 0 for most legit)")

if __name__ == "__main__":
    test_system("www.google.com")
    print("-" * 30)
    test_system("https://www.google.com")
    print("-" * 30)
    test_system("google.com")
    print("-" * 30)
    test_system("https://github.com")
    print("-" * 30)
    test_system("http://suspicious-site.com/login")
