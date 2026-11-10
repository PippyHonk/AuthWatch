import unittest
import csv
import tempfile
from pathlib import Path
from reporter import export_csv


class TestReporter(unittest.TestCase):

    def test_csv_export(self):
        alerts = {
            "10.0.0.1": 5,
            "10.0.0.2": 12,
            "10.0.0.3": 22
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "alerts.csv"

            export_csv(alerts, str(output))

            # Your task:
            with open(output, "r", newline="", encoding="utf-8") as file:
                rows = list(csv.reader(file))

        self.assertEqual(rows[0], ["IP Address", "Failed Attempts", "Severity"])
        self.assertEqual(rows[1], ["10.0.0.1", "5", "LOW"])
        self.assertEqual(len(rows), 4)

        self.assertIn(rows[1][2], ["LOW", "MEDIUM", "HIGH"])
            # 2. Use csv.reader() to read its contents.

            # 3. Verify the header row.
            # 4. Verify all three IPs and their severity levels.
