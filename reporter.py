import csv
from severity import classify_severity

def export_csv(alerts: dict, output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(["IP Address", "Failed Attempts", "Severity"])

        for ip, count in alerts.items():
            sev = classify_severity(count)
            writer.writerow([ip, count, sev])

