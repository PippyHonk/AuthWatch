import ipaddress
from datetime import datetime

def parse_log_line(line: str, year: int = 2026) -> dict | None:
    words = line.split()

    if "from" not in words or "for" not in words or "password" not in words:
        return None
    from_check = words.index("from")
    for_check = words.index("for")
    pass_check = words.index("password")

    ip = words[from_check + 1]

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    username = words[from_check-1]
    timestamp = " ".join(words[0:3])
    try:
        parsed_time= datetime.strptime(
            f"{year} {timestamp}",
            "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None

    if words[pass_check - 1] == "Failed":
        event_type = "FAILED"
    elif words[pass_check - 1] == "Success":
        event_type = "SUCCESS"
    else:
        return None

    parse = {"timestamp": timestamp, "username": username, "ip": ip, "event_type": event_type}

    return parse