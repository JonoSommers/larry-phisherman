# detector.py
# Core phishing detection engine for Larry Phisherman

import re


# --- Configuration / rule data ------------------------------------------------

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "t.co",
    "is.gd",
    "buff.ly",
    "adf.ly",
]

DANGEROUS_EXTENSIONS = [
    ".exe",
    ".zip",
    ".rar",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".scr",
    ".msi",
]

TRUSTED_DOMAINS = {
    "amazon": ["amazon.com", "amazonaws.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "google": ["google.com", "gmail.com", "googleapis.com"],
}

LOOK_ALIKES = {
    "0": "o",
    "1": "l",
    "3": "e",
    "@": "a",
    "5": "s",
}

IP_PATTERN = r"\d+\.\d+\.\d+\.\d+"
TLD_PATTERN = r"http[s]?://[^\s]+?\.(?:xyz|ru|tk|top|click)"


def get_threat_level(score):
    """
    Convert a numeric score to a human-readable threat level.

    This is a pure function - given the same input, it always returns
    the same output. No side effects.
    """
    if score >= 90:
        return "critical"       # Auto-block territory
    elif score >= 70:
        return "dangerous"      # High confidence phishing
    elif score >= 50:
        return "likely_phishing"
    elif score >= 20:
        return "suspicious"
    else:
        return "safe"


def score_email(sender, subject, body):
    """
    Analyze an email and return a phishing risk assessment.

    Args:
        sender: Email address of the sender (e.g., "support@amaz0n.com")
        subject: Subject line of the email
        body: Full body text of the email

    Returns:
        Dictionary containing:
        - score: Numeric risk score (0-100+)
        - threat_level: Human-readable threat category
        - indicators: List of triggered detection rules
    """
    # Normalize once for easier matching
    subject_lower = subject.lower()
    body_lower = body.lower()
    sender_domain = sender.split("@")[-1].lower()

    # We'll collect all indicators that fire
    indicators = []
    indicators.extend(check_for_urgency(subject_lower))

    found_shorteners = []
    found_brands = []
    found_files = []

    # --- Rule 1: Urgency / scammy buzzwords in subject ------------------------
def check_for_urgency(subject_lower):
    found_indicators = []
    if "urgent" in subject_lower:
        found_indicators.append({
            "name": "Common Scammer Buzzwords",
            "description": "The email subject contains buzzwords commonly used by scammers (e.g., 'urgent').",
            "points": 10,
        })
    return found_indicators

    # --- Rule 2: Suspicious link patterns (IP + sketchy TLDs) -----------------
    ip_matches = re.findall(IP_PATTERN, body_lower)
    tld_matches = re.findall(TLD_PATTERN, body_lower)
    pattern_matches = ip_matches + tld_matches

    if pattern_matches:
        indicators.append({
            "name": "Suspicious Link Pattern",
            "description": "The email contains links with patterns commonly used by scammers (IP addresses or sketchy domains).",
            "suspicious_patterns": pattern_matches,
            "points": 15,
        })

    # --- Rule 3: URL shorteners in body ---------------------------------------
    for shortener in SHORTENERS:
        if shortener in body_lower:
            found_shorteners.append(shortener)

    if found_shorteners:
        indicators.append({
            "name": "Common URL Shortener",
            "description": "The email body contains URL shorteners commonly used to hide malicious links.",
            "shorteners_detected": found_shorteners,
            "points": 20,
        })

    # --- Rule 4: Suspicious sender domain / brand impersonation ---------------
    normalized_domain = sender_domain
    for fake_char, real_char in LOOK_ALIKES.items():
        normalized_domain = normalized_domain.replace(fake_char, real_char)

    for brand, real_domains in TRUSTED_DOMAINS.items():
        if brand in normalized_domain and sender_domain not in real_domains:
            found_brands.append(brand)

    if found_brands:
        indicators.append({
            "name": "Suspicious Domain Sender",
            "description": "The sender's domain appears to impersonate a trusted brand.",
            "sender_domain": sender_domain,
            "brands_impersonated": found_brands,
            "points": 25,
        })

    # --- Rule 5: Dangerous file extensions mentioned --------------------------
    for ext in DANGEROUS_EXTENSIONS:
        if ext in body_lower:
            found_files.append(ext)

    if found_files:
        indicators.append({
            "name": "Dangerous File Type",
            "description": "The email body references file extensions commonly used to deliver malware.",
            "dangerous_files_found": found_files,
            "points": 30,
        })

    # Calculate total score from all indicators
    total_score = sum(indicator["points"] for indicator in indicators)

    # Build and return our result
    return {
        "score": total_score,
        "threat_level": get_threat_level(total_score),
        "indicators": indicators,
    }


# This block only runs when you execute this file directly
# (not when it's imported by another file)
if __name__ == "__main__":
    # Quick test
    result = score_email(
        sender="test@amaz0n.com",
        subject="URGENT: Your account needs attention.",
        body="Visit http://192.168.1.1/login and http://amazon-verify.xyz now!"
            " Also check this link: abcdefg.bit.ly and open invoice.rar"
    )
    print(result)
