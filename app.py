from pyexpat import features
from unittest import result
import warnings
warnings.filterwarnings("ignore")

from flask import Flask, render_template, request
import pickle
import numpy as np
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "bank", "payment", "signin", "confirm", "password"
]


app = Flask(__name__)

# Load trained ML model
model = pickle.load(open("phishing_model.pkl", "rb"))

# Feature explanations (only for features we auto-detect)
FEATURE_DESCRIPTIONS = {
    0: "URL uses an IP address instead of a domain name",
    1: "URL is unusually long",
    2: "URL uses a shortening service",
    3: "URL contains '@' symbol which can redirect users",
    4: "URL contains multiple '//' redirects",
    5: "Domain contains prefix or suffix separated by '-'",
    6: "URL has multiple subdomains",
    7: "Website does not properly use HTTPS"
}

# ---------------- FEATURE EXTRACTION ---------------- #
def extract_url_features(url):
    """
    Extracts phishing-related features from a URL.
    Returns a list of 30 features (rest filled with safe defaults).
    """
    features = [0] * 30

    # 0. Using IP address
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        features[0] = 1

    # 1. Long URL
    if len(url) > 75:
        features[1] = 1

    # 2. Shortened URL
    shortening_services = ["bit.ly", "tinyurl", "goo.gl", "t.co"]
    if any(service in url for service in shortening_services):
        features[2] = 1

    # 3. '@' symbol
    if "@" in url:
        features[3] = 1

    # 4. Redirecting //
    if url.count("//") > 1:
        features[4] = 1

    parsed = urlparse(url)
    domain = parsed.netloc

    # 5. Prefix/Suffix '-'
    if "-" in domain:
        features[5] = 1

    # 6. Subdomains
    if domain.count(".") > 2:
        features[6] = 1

    # 7. HTTPS
    if not url.startswith("https"):
        features[7] = 1

    # 8. Suspicious keyword detection (basic NLP)
    url_lower = url.lower()
    if any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS):
        features[8] = 1


    return features

def highlight_url(url):
    highlighted = url

    # Highlight IP addresses
    highlighted = re.sub(
        r"(\d+\.\d+\.\d+\.\d+)",
        r"<span class='highlight-ip'>\1</span>",
        highlighted
    )

    # Highlight suspicious keywords
    for word in SUSPICIOUS_KEYWORDS:
        highlighted = re.sub(
            rf"({re.escape(word)})",
            r"<span class='highlight-keyword'>\1</span>",
            highlighted,
            flags=re.IGNORECASE
        )

    # Highlight hyphen in domain
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if "-" in domain:
            safe_domain = domain.replace("-", "<span class='highlight-hyphen'>-</span>")
            highlighted = highlighted.replace(domain, safe_domain)
    except:
        pass

    return highlighted

# ---------------- FLASK ROUTE ---------------- #
@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None
    reasons = []
    risk_level = None
    confidence = None
    highlighted_url = None
    safe_message = ""

    if request.method == "POST":
        url = request.form.get("url")
        highlighted_url = highlight_url(url)
        features = extract_url_features(url)
        
        # Generate explanation
        for i, value in enumerate(features):
            if value == 1 and i in FEATURE_DESCRIPTIONS:
                reasons.append(FEATURE_DESCRIPTIONS[i])

        features = np.array(features).reshape(1, -1)

        # ML Prediction
        result = model.predict(features)[0]
        proba = model.predict_proba(features)[0]

        # Probability confidence
        phishing_confidence = round(proba[1] * 100, 2)
        legit_confidence = round(proba[0] * 100, 2)

        prediction = "⚠️ Phishing Website" if result == 1 else "✅ Legitimate Website"
        confidence = phishing_confidence if result == 1 else legit_confidence   
        
        # ML-based override
        if result == 1 and len(reasons) >= 2:
            risk_level = "High Risk 🔴"
        elif len(reasons) >= 2:
            risk_level = "Medium Risk 🟡"
        else:
            risk_level = "Low Risk 🟢"

        #safe message logic
        if prediction == "✅ Legitimate Website":
            if "Medium" in risk_level:
                safe_message = (
                    "This website appears mostly safe, but some suspicious patterns were detected. Proceed with caution.")
            else:
                safe_message = ("This website appears safe based on the analyzed URL features.")



    return render_template(
        "index.html",
        prediction=prediction,
        risk_level=risk_level,
        reasons=reasons,
        confidence=confidence,
        highlighted_url=highlighted_url,
        safe_message=locals().get("safe_message", "")

    )

# ---------------- RUN APP ---------------- #
if __name__ == "__main__":
    app.run()
