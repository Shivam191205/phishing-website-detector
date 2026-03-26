import pickle
from urllib.parse import urlparse
import requests
import whois

# import your feature file
from URLFeatureExtraction import *

# load model
model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))

def get_features(url):
    features = []

    # Address bar features
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    # Domain features
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))

    # HTML features
    try:
        response = requests.get(url)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features


# 🔥 MAIN
url = input("Enter URL: ")

features = get_features(url)

result = model.predict([features])

if result[0] == 1:
    print("⚠️ Phishing Website")
else:
    print("✅ Legitimate Website")