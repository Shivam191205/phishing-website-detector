
import sys
import os
from urllib.parse import urlparse

# Add current directory to path
sys.path.append(os.getcwd())

from URLFeatureExtraction import *

def test_url(url):
    print(f"Testing URL: {url}")
    parsed = urlparse(url)
    print(f"Parsed netloc: '{parsed.netloc}'")
    
    features = []
    features.append(("havingIP", havingIP(url)))
    features.append(("haveAtSign", haveAtSign(url)))
    features.append(("getLength", getLength(url)))
    features.append(("getDepth", getDepth(url)))
    features.append(("redirection", redirection(url)))
    features.append(("httpDomain", httpDomain(url)))
    features.append(("tinyURL", tinyURL(url)))
    features.append(("prefixSuffix", prefixSuffix(url)))
    
    import requests
    try:
        response = requests.get(url, timeout=5)
    except Exception as e:
        print(f"Request failed: {e}")
        response = ""
        
    features.append(("iframe", iframe(response)))
    features.append(("mouseOver", mouseOver(response)))
    features.append(("rightClick", rightClick(response)))
    features.append(("forwarding", forwarding(response)))
    
    for name, val in features:
        print(f"  - {name}: {val}")

if __name__ == "__main__":
    test_url("https://www.google.com")
    print("-" * 20)
    test_url("www.google.com")
