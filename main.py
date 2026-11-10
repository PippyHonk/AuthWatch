from pathlib import Path
from parser import parse_log_line
from detector import detect_brute_force
from severity import classify_severity
from reporter import export_csv

auth_path = Path(__file__).parent / "sample.logs" / "auth.log"
parsed = []
with auth_path.open("r", encoding = "utf-8") as file:
    for line in file:
        event = parse_log_line(line)

        if event is not None:
            parsed.append(event)

parsed = detect_brute_force(parsed)


print("AUTHWATCH SECURITY REPORT \n"
      "-------------------------------")

for ip, count in parsed.items():
    sev = classify_severity(count)

    print(f"IP: {ip}\n"
          f"Failed Attempts: {count}\n"
          f"Severity: {sev}\n"
          "-------------------------------")
