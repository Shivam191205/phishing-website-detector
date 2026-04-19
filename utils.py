
from urllib.parse import urlparse

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def rule_based_check(url):
    domain = urlparse(url).netloc.lower()

    # Common phishing tricks
    if "@" in url:
        return 1
    
    # Trusted domains
    trusted_domains = [
        "google.com", "github.com", "wikipedia.org", "microsoft.com", 
        "amazon.in", "amazon.com", "stackoverflow.com", "apple.com",
        "netflix.com", "twitter.com", "linkedin.com", "facebook.com",
        "unb.ca", "phishtank.com", "google.co.in"
    ]

    for site in trusted_domains:
        if domain == site or domain.endswith("." + site):
            return 0

    return None
