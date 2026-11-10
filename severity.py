def classify_severity(attempts: int) -> str | None:
    if attempts < 5:
        return None
    elif attempts < 10:
        return "LOW"
    elif attempts < 20:
        return "MEDIUM"
    else:
        return "HIGH"