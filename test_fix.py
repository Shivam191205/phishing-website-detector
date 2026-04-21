import sys
import os
import tldextract

# Add current directory to path
sys.path.append(os.getcwd())

from utils import engine, normalize_url

test_urls = [
    "http://login-example.com.secure-auth.test",
    "http://paypal.verify-account.example.com",
    "http://secure-update.bank-login.example",
    "http://amazon.security-alert.example.com",
    "http://google-authentication.fake-login.test",
    "https://google.com"
]

print(f"{'URL':<50} | {'Score':<5} | {'Suffix':<10} | {'Flags'}")
print("-" * 110)

for url in test_urls:
    norm_url = normalize_url(url)
    ext = tldextract.extract(norm_url)
    h_result = engine.analyze(norm_url)
    flags_str = ", ".join(h_result["flags"]) if h_result["flags"] else "None"
    print(f"{url:<50} | {h_result['score']:<5} | {ext.suffix:<10} | {flags_str}")
