import unittest
import tempfile
from pathlib import Path
import subprocess
import sys
import csv


class TestIntegration(unittest.TestCase):

    def test_full_pipeline(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            temp_path = Path(temp_dir)

            input_path = temp_path / "auth.log"
            output_path = temp_path / "alerts.csv"

            print("Input location:", input_path)
            print("Output location:", output_path)

            input_path.write_text(
                """Nov  7 10:15:22 server sshd[1234]: Failed password for root from 203.0.113.42 port 51234 ssh2
                    Nov  7 10:15:25 server sshd[1235]: Failed password for root from 203.0.113.42 port 51235 ssh2
                    Nov  7 10:15:28 server sshd[1236]: Failed password for root from 203.0.113.42 port 51236 ssh2
                    Nov  7 10:15:31 server sshd[1237]: Failed password for root from 203.0.113.42 port 51237 ssh2
                    Nov  7 10:15:34 server sshd[1238]: Failed password for root from 203.0.113.42 port 51238 ssh2
                    Nov  7 10:16:10 server sshd[1239]: Accepted password for andrew from 192.0.2.15 port 49152 ssh2
                    Nov  7 10:16:11 server sshd[1240]: Failed password for andrew from 192.0.2.15 port 49152 ssh2
                    Nov  7 10:16:12 server sshd[1241]: Failed password for andrew from 192.0.2.15 port 49152 ssh2
                    Nov  7 10:16:13 server sshd[1242]: Failed password for andrew from 192.0.2.15 port 49152 ssh2
                    Nov  7 10:16:14 server sshd[1243]: Failed password for andrew from 192.0.2.15 port 49152 ssh2
                    Nov  7 10:17:02 server sshd[1244]: Failed password for invalid user admin from 198.51.100.23 port 53121 ssh2
                """
            )

            project_root = Path(__file__).resolve().parent.parent
            main_file = project_root / "main.py"

            result = subprocess.run(
                [
                    sys.executable,
                    str(main_file),
                    "--file", str(input_path),
                    "--threshold", "5",
                    "--window", "60",
                    "--year", "2026",
                    "--output", str(output_path)
                ],
                capture_output=True,
                text=True
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output_path.exists())

            with open(output_path, "r", newline="", encoding= "utf-8") as file:
                rows = list(csv.reader(file))

            self.assertEqual(rows[1][0], "203.0.113.42")
            self.assertEqual(rows[0], ["IP Address", "Failed Attempts", "Severity"])
            self.assertEqual(rows[1][1], "5")
            self.assertEqual(rows[1][2], "LOW")
            self.assertEqual(len(rows), 2)




if __name__ == "__main__":
    unittest.main()



# file = Path("sample.logs") / "auth.log"
#
# if file.exists():
#     print("File Already Exists")
#
# file.parent.mkdir(parents=True, exist_ok=True)
#
# with open(file, "w", encoding="utf-8") as file:
#     file.write("Example log entry")
#


# from pathlib import Path
#
# log_path = Path("practice_files") / "test.log"
#
# log_path.parent.mkdir(parents=True, exist_ok=True)
#
# with open(log_path, "w", encoding="utf-8") as file:
#     file.write("Failed password for root")


