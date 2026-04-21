
import tldextract
import re
from urllib.parse import urlparse

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # Prepend www. if it's a naked domain
    try:
        ext = tldextract.extract(url)
        if not ext.subdomain and ext.domain and ext.suffix:
            # We use tldextract info to safely prepend www.
            # Example: google.com -> www.google.com
            parsed = urlparse(url)
            # Reconstruct the URL with www.
            netloc = f"www.{ext.domain}.{ext.suffix}"
            url = f"{parsed.scheme}://{netloc}{parsed.path}"
            if parsed.query: url += f"?{parsed.query}"
    except:
        pass # If anything goes wrong, keep the original normalized URL
        
    return url

# ---------------- HEURISTIC ENGINE ----------------
class HeuristicEngine:
    def __init__(self):
        # Major brands frequently targeted by phishing
        self.trusted_brands = {
            "google": ["google.com", "google.co.in", "google.co.uk", "gmail.com"],
            "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
            "facebook": ["facebook.com", "fb.com"],
            "apple": ["apple.com", "icloud.com"],
            "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
            "netflix": ["netflix.com"],
            "paypal": ["paypal.com"],
            "github": ["github.com"],
            "linkedin": ["linkedin.com"],
            "twitter": ["twitter.com", "x.com"],
            "instagram": ["instagram.com"],
            "whatsapp": ["whatsapp.com"],
            "chase": ["chase.com"],
            "wellsfargo": ["wellsfargo.com"],
            "bankofamerica": ["bankofamerica.com"],
            "adobe": ["adobe.com"],
            "dropbox": ["dropbox.com"],
            "zoom": ["zoom.us"],
            "steam": ["steampowered.com"],
            "rakuten": ["rakuten.co.jp"],
            "alibaba": ["alibaba.com"],
            "ebay": ["ebay.com"]
        }
        
        # Keywords often used in phishing URLs
        self.suspicious_keywords = [
            "login", "verify", "secure", "account", "update", "banking", 
            "wallet", "crypto", "official", "support", "billing", "signin",
            "validation", "compliance", "confirm"
        ]
        
        # TLDs often used for phishing or low-reputation sites
        self.suspicious_tlds = [
            "xyz", "top", "win", "club", "loan", "biz", "info", "online", 
            "site", "website", "pw", "cc", "run", "icu"
        ]
        
        # Whitelisted technical TLDs (documentation and testing)
        self.tech_whitelist = ["example", "test", "localhost", "invalid"]

    def analyze(self, url):
        ext = tldextract.extract(url)
        subdomain = ext.subdomain.lower()
        domain = ext.domain.lower()
        suffix = ext.suffix.lower()
        full_domain = f"{domain}.{suffix}"
        
        flags = []
        score = 0
        
        # 0. Technical Whitelist Check
        # tldextract may move the tech TLD to 'domain' if it doesn't recognize it as a suffix
        if suffix in self.tech_whitelist or domain in self.tech_whitelist:
            return {
                "score": 0,
                "flags": ["Safe Technical TLD/Domain (%s)" % (suffix if suffix else domain)],
                "domain_info": {
                    "subdomain": subdomain,
                    "domain": domain,
                    "suffix": suffix,
                    "full": full_domain
                }
            }
        
        # 1. Brand Impersonation Check (Improved)
        for brand, domains in self.trusted_brands.items():
            # Check if brand is a distinct part of domain/subdomain (e.g. brand-login or paypal.verify)
            # This avoids flagging "google-analytics" as easily if it's not a clear attempt to impersonate
            brand_pattern = rf"(^|[.\-])({brand})([.\-]|$)"
            is_brand_present = re.search(brand_pattern, f"{subdomain}.{domain}")
            
            if is_brand_present and full_domain not in domains:
                # Special case: allow subdomains of official domains (e.g., accounts.google.com)
                is_sub_of_official = False
                for official in domains:
                    if full_domain == official:
                        is_sub_of_official = True
                        break
                
                if not is_sub_of_official:
                    flags.append(f"Potential Brand Impersonation ({brand.capitalize()})")
                    score += 45 # Slightly reduced from 50

        # 2. Subdomain Stuffing
        dots = subdomain.count('.')
        if dots >= 3:
            flags.append(f"Subdomain Stuffing ({dots} subdomains)")
            score += 30
        
        # 3. Suspicious TLD
        if suffix in self.suspicious_tlds:
            flags.append(f"Suspicious TLD (.{suffix})")
            score += 20
            
        # 4. Keyword Risk (Capped)
        kw_score = 0
        for kw in self.suspicious_keywords:
            if kw in subdomain or kw in domain:
                flags.append(f"Risk Keyword: '{kw}'")
                kw_score += 15 # Reduced from 25
        
        score += min(kw_score, 45) # Cap keyword risk at 45

        # 5. Excessive Dashes
        dashes = domain.count('-') + subdomain.count('-')
        if dashes >= 3:
            flags.append(f"Excessive Dashes ({dashes})")
            score += 15

        return {
            "score": score,
            "flags": flags,
            "domain_info": {
                "subdomain": subdomain,
                "domain": domain,
                "suffix": suffix,
                "full": full_domain
            }
        }

# ---------------- RULE SYSTEM (UPGRADED) ----------------
engine = HeuristicEngine()

def rule_based_check(url):
    norm_url = normalize_url(url)
    h_result = engine.analyze(norm_url)
    
    # 1. Whitelist (Known Safe)
    # If the score is 0 and it's a very common domain, trust it
    if h_result["score"] == 0:
        # Check if it's an official brand domain
        for brand, domains in engine.trusted_brands.items():
            if h_result["domain_info"]["full"] in domains:
                return 0, h_result

    # 2. High Confidence Malicious (Heuristic)
    # Increased threshold to 90 to allow ML model more room for nuanced cases
    if h_result["score"] >= 90:
        return 1, h_result
    
    # Otherwise, return None to pass to the model
    return None, h_result
