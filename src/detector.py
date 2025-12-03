# detector.py
# Core phishing detection engine for Larry Phisherman

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
    # We'll collect all indicators that fire
    indicators = []
    found = []
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly"]
    
    # TODO: We'll add detection rules here, one by one!
    # Each rule will check for something suspicious and 
    # append to the indicators list if triggered.
    
    if "urgent" in subject.lower():
        indicators.append({
            "name": "Common Scammer Buzzwords",
            "description": "The email subject or body contains buzzwords commonly used by scammers.",
            "points": 20
        })
    
    for item in shorteners:
        if item in body.lower():
            found.append(item)
    if found:
        indicators.append({
            "name" : "Common URL Shortener",
            "description": "The email subject or body contains a URL shortener commonly used by scammers.",
            "shorteners detected": found,
            "points": 40
        })    
    # Calculate total score from all indicators
    total_score = sum(indicator["points"] for indicator in indicators)
    
    # Build and return our result
    return {
        "score": total_score,
        "threat_level": get_threat_level(total_score),
        "indicators": indicators
    }


# This block only runs when you execute this file directly
# (not when it's imported by another file)
if __name__ == "__main__":
    # Quick test
    result = score_email(
        sender="test@example.com",
        subject="URGENT: Your account needs attention.",
        body="Just a friendly email! Use this link: abcdefg.bit.ly or abcdefg.tinyurl.com"
    )
    print(result)
