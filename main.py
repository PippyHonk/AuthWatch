import argparse
from pathlib import Path

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

    args = parser.parse_args()

    auth_path = Path(args.file)
    parsed = []

    with auth_path.open("r", encoding = "utf-8") as file:
        for line in file:
            event = parse_log_line(line)

            if event is not None:
                parsed.append(event)

    alerts = detect_brute_force(parsed, args.threshold, args.window)

    print(alerts)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    export_csv(alerts, str(output_path))

if __name__ == "__main__":
    main()