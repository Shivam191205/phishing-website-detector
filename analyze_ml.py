import pickle
import sys
import os
from urllib.parse import urlparse
import requests
import whois

# Add current directory to path
sys.path.append(os.getcwd())

from URLFeatureExtraction import *
from utils import normalize_url

def fix_features(features):
    return [-1 if f == 0 else f for f in features]

def get_features(url):
    features = []
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    # DNS & Domain features
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1
    
    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))

    try:
        response = requests.get(url, timeout=5)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features

# Load model
model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))

test_urls = [
    "http://paypal.verify-account.example.com",
    "http://google.com"
]

feature_names = [
    "IP", "At", "Length", "Depth", "Redir", "HTTPS_Dom", "Tiny", "PreSuf",
    "DNS", "Traffic", "Age", "End", "iFrame", "Mouse", "Right", "Forward"
]

for url in test_urls:
    print(f"\nAnalyzing: {url}")
    f = get_features(url)
    ff = fix_features(f)
    pred = model.predict([ff])[0]
    prob = model.predict_proba([ff])[0]
    print(f"Prediction: {'Phishing' if pred == 1 else 'Legitimate'}")
    print(f"Confidence: {max(prob)*100:.2f}%")
    print("Features:")
    for name, val in zip(feature_names, f):
        print(f"  {name}: {val}")
