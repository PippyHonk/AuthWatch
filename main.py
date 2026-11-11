import argparse
from pathlib import Path
from datetime import datetime
from parser import parse_log_line
from detector import detect_brute_force
from severity import classify_severity
from reporter import export_csv
def main():
    parser = argparse.ArgumentParser(
        description="AuthWatch SSH Security Analyzer"
    )

    parser.add_argument(
        "--file",
        type=str,
        default="sample.logs/auth.log",
        help="File name used to get alerts"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Number of failed logins required for an alert"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Number of seconds the desired threshold must be hit for an alert"
    )

    parser.add_argument(
        "--output",
        type=str,
        default= "reports/alerts.csv",
        help="Output is a csv file containing alerts"
    )

    parser.add_argument(
        "--year",
        type=int,
        default= datetime.now().year,
        help="Set a year for the file being examined"
    )

    args = parser.parse_args()

    if args.threshold < 5:
        parser.error("--threshold must be at least 5")

    if args.window <= 0:
        parser.error("--window must be greater than 0")

    auth_path = Path(args.file)
    parsed = []

    with auth_path.open("r", encoding = "utf-8") as file:
        for line in file:
            event = parse_log_line(line, args.year)

            if event is not None:
                parsed.append(event)

    alerts = detect_brute_force(parsed, args.threshold, args.window, args.year)

    print("AUTHWATCH SECURITY REPORT \n"
          "-------------------------------")

    for ip, count in alerts.items():
        sev = classify_severity(count)

        print(f"IP: {ip}\n"
              f"Failed Attempts: {count}\n"
              f"Severity: {sev}\n"
              "-------------------------------")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    export_csv(alerts, str(output_path))

if __name__ == "__main__":
    main()