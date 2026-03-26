import streamlit as st
import pickle
from urllib.parse import urlparse
import requests
import whois

from URLFeatureExtraction import *


st.markdown("""
<style>

/* 🌌 Premium Background */
.stApp {
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    background-size: 200% 200%;
    animation: gradientBG 20s ease infinite;
    color: white;
}

/* 🎥 Smooth gradient */
@keyframes gradientBG {
    0% {background-position: 0% 50%;}
    50% {background-position: 100% 50%;}
    100% {background-position: 0% 50%;}
}

/* 🧊 Glassmorphism Card */
.glass {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 15px;
    padding: 20px;
    backdrop-filter: blur(10px);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
}

/* 🔘 Buttons */
.stButton>button {
    background: linear-gradient(90deg, #00c6ff, #0072ff);
    border-radius: 12px;
    color: white;
    padding: 10px 20px;
    font-size: 16px;
    transition: 0.3s;
}
.stButton>button:hover {
    transform: scale(1.08);
    background: linear-gradient(90deg, #ff512f, #dd2476);
}

/* 🧾 Input */
.stTextInput input {
    border-radius: 12px;
    padding: 10px;
}

/* 🟢 Legit Animation */
.success-box {
    padding: 25px;
    border-radius: 15px;
    background: rgba(0,255,0,0.08);
    box-shadow: 0 0 30px rgba(0,255,0,0.5);
    animation: fadeIn 0.8s ease-in-out;
}

/* 🔴 Phishing Animation */
.error-box {
    padding: 25px;
    border-radius: 15px;
    background: rgba(255,0,0,0.08);
    box-shadow: 0 0 30px rgba(255,0,0,0.5);
    animation: shake 0.4s ease-in-out;
}

/* ✨ Fade */
@keyframes fadeIn {
    from {opacity:0; transform: translateY(20px);}
    to {opacity:1; transform: translateY(0);}
}

/* ⚡ Shake effect */
@keyframes shake {
    0% { transform: translateX(0); }
    25% { transform: translateX(-5px); }
    50% { transform: translateX(5px); }
    75% { transform: translateX(-5px); }
    100% { transform: translateX(0); }
}

/* 📊 Sidebar */
section[data-testid="stSidebar"] {
    background: rgba(0,0,0,0.4);
}

/* ✨ Headings glow */
h1, h2, h3 {
    color: #00ffd5;
    text-shadow: 0 0 10px rgba(0,255,255,0.5);
}

</style>
""", unsafe_allow_html=True)

st.sidebar.title("🧠 Dashboard")

st.sidebar.markdown("""
### 🔍 About
This system detects phishing websites using:
- Machine Learning
- URL Analysis
- Rule-based detection

### ⚡ Features
✔ Real-time detection  
✔ Risk scoring  
✔ Explanation system  
✔ Secure analysis  
""")

st.sidebar.markdown("---")
st.sidebar.write("🔒 Cybersecurity Project")

# Load model
model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))

# ---------------- RULE SYSTEM ----------------
def rule_based_check(url):
    domain = urlparse(url).netloc.lower()

    if "@" in url:
        return 1
    if "-" in domain:
        return 1
    if "login" in url or "verify" in url or "secure" in url:
        return 1

    trusted_domains = [
        "google.com", "github.com", "wikipedia.org",
        "microsoft.com", "amazon.in", "amazon.com", "stackoverflow.com"
    ]

    for site in trusted_domains:
        if domain.endswith(site):
            return 0

    return None


# ---------------- FEATURE FIX ----------------
def fix_features(features):
    return [-1 if f == 0 else f for f in features]


# ---------------- FEATURE EXTRACTION ----------------
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

    features.append(0)
    features.append(web_traffic(url))
    features.append(0)
    features.append(0)

    try:
        response = requests.get(url, timeout=5)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features


# ---------------- EXPLANATION ----------------
def explain_result(url):
    reasons = []
    domain = urlparse(url).netloc.lower()

    if "@" in url:
        reasons.append("Contains '@' symbol (redirect trick)")
    if "-" in domain:
        reasons.append("Suspicious '-' in domain")
    if "login" in url:
        reasons.append("Contains 'login' keyword")
    if "verify" in url:
        reasons.append("Contains 'verify' keyword")
    if "secure" in url:
        reasons.append("Contains 'secure' keyword")

    return reasons


# ---------------- UI DESIGN ----------------
st.markdown("""
<h1 style='text-align:center;'>🔐 Phishing Website Detection</h1>
<p style='text-align:center; font-size:18px; color:lightgray;'>
AI-powered system to detect malicious websites in real-time
</p>
""", unsafe_allow_html=True)

# 🌈 Custom styling
st.markdown("""
<style>
.stApp {
    background: linear-gradient(to right, #0f2027, #203a43, #2c5364);
    color: white;
}
h1, h2, h3 {
    color: #00ffd5;
}
</style>
""", unsafe_allow_html=True)


st.markdown("""
---
### 🚀 Features of this System
✔ Real-time phishing detection  
✔ Hybrid AI + Rule-based system  
✔ Risk scoring & explanation  
✔ Feature-level analysis  

---
""")

url = st.text_input("🔗 Enter Website URL")

# ---------------- MAIN LOGIC ----------------
if st.button("🚀 Analyze Website"):
    if url:
        with st.spinner("Analyzing website..."):

            rule_result = rule_based_check(url)

            if rule_result is not None:
                result = rule_result
            else:
                features = get_features(url)
                features = fix_features(features)
                result = model.predict([features])[0]
                prob = model.predict_proba([features])[0]

        # ---------------- RESULT ----------------
        st.subheader("🔍 Result")

        if result == 0:
            st.markdown("""
            <div class='success-box'>
            <h2>✅ Legitimate Website</h2>
            <p>This website is safe and trusted.</p>
            </div>
            """, unsafe_allow_html=True)
            risk = 20
        else:
            st.markdown("""
            <div class='error-box'>
            <h2>⚠️ Phishing Website Detected!</h2>
            <p>This website may steal sensitive data.</p>
            </div>
            """, unsafe_allow_html=True)
            risk = 90

        # ---------------- RISK METER ----------------
        st.markdown("### 📊 Risk Meter")

        st.progress(risk)

        if risk > 70:
            st.markdown("<h3 style='color:red;'>🔴 HIGH RISK</h3>", unsafe_allow_html=True)
        elif risk > 40:
            st.markdown("<h3 style='color:orange;'>🟠 MEDIUM RISK</h3>", unsafe_allow_html=True)
        else:
            st.markdown("<h3 style='color:lightgreen;'>🟢 LOW RISK</h3>", unsafe_allow_html=True)

        # ---------------- CONFIDENCE ----------------
        if rule_result is not None:
            st.write("Confidence: High (Rule-based)")
        else:
            confidence = max(prob)
            st.write(f"Confidence: {confidence*100:.2f}%")

        # ---------------- WHY PHISHING ----------------
        if result == 1:
            reasons = explain_result(url)
            if reasons:
                st.subheader("⚠️ Why this is phishing?")
                for r in reasons:
                    st.write(f"🔹 {r}")

        # ---------------- WEBSITE INFO ----------------
        st.subheader("🌐 Website Info")
        parsed = urlparse(url)
        st.write(f"Domain: {parsed.netloc}")
        st.write(f"Path Depth: {parsed.path.count('/')}")

        # ---------------- FEATURES ----------------
        if rule_result is None:
            st.subheader("🔬 Feature Analysis")

            feature_names = [
                "IP Address", "Has @", "URL Length", "Depth",
                "Redirection", "HTTPS Domain", "TinyURL",
                "Prefix/Suffix", "DNS", "Traffic",
                "Domain Age", "Domain End",
                "iFrame", "MouseOver", "RightClick", "Forwarding"
            ]

            for name, val in zip(feature_names, features):
                st.write(f"🔹 {name}: {val}")

    else:
        st.warning("Please enter a URL")

# ---------------- FOOTER ----------------
st.markdown("""
---
<p style='text-align:center; color:gray;'>
🔒 Built for Cybersecurity Project | Machine Learning Powered
</p>
""", unsafe_allow_html=True)