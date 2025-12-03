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
    elif score >= 76:
        return "dangerous"      # High confidence phishing
    elif score >= 51:
        return "likely_phishing"
    elif score >= 21:
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
    
    # TODO: We'll add detection rules here, one by one!
    # Each rule will check for something suspicious and 
    # append to the indicators list if triggered.
    
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
        subject="Hello",
        body="Just a friendly email!"
    )
    print(result)
