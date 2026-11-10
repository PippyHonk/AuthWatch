from datetime import datetime

def detect_brute_force(parsed, threshold=5, window_seconds=60):
    dates = {}
    alerts = {}
    for things in parsed:
        if things["event_type"] != "FAILED":
            continue
        timestamp = things["timestamp"]
        ip = things["ip"]
        parsed_time = datetime.strptime("2026 " + timestamp, "%Y %b %d %H:%M:%S")
        if ip not in dates:
            dates[ip] = []
        dates[ip].append(parsed_time)

    for ip, times in dates.items():
        times.sort()
        left = 0

        for right in range(len(times)):

            while (times[right] - times[left]).total_seconds() > window_seconds:
                left += 1

            attempts = right - left + 1

            if attempts >= threshold:
                if ip not in alerts:
                    alerts[ip] = attempts
                else:
                    alerts[ip] = max(alerts[ip], attempts)

    return alerts

