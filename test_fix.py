import sys
import os

# Add current directory to path so we can import utils
sys.path.append(os.getcwd())

from utils import engine, normalize_url

test_urls = [
    "http://login-example.com.secure-auth.test",
    "http://paypal.verify-account.example.com",
    "http://secure-update.bank-login.example",
    "http://amazon.security-alert.example.com",
    "http://google-authentication.fake-login.test",
    "http://microsoft.verify-user.example",
    "http://account-update.example-login.test",
    "http://secure.paytm-login.example",
    "http://appleid.confirm-details.example",
    "http://netflix.billing-update.example",
    "https://google.com",
    "https://google-analytics.com",
    "https://support.google.com"
]

print(f"{'URL':<50} | {'Score':<5} | {'Flags'}")
print("-" * 100)

for url in test_urls:
    norm_url = normalize_url(url)
    h_result = engine.analyze(norm_url)
    flags_str = ", ".join(h_result["flags"]) if h_result["flags"] else "None"
    print(f"{url:<50} | {h_result['score']:<5} | {flags_str}")
