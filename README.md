# AuthWatch

AuthWatch is a Python-based security tool that analyzes Linux SSH authentication logs to identify potential brute-force login attempts.

It uses a sliding-window algorithm to detect repeated failed logins from individual IP addresses within a specified time period.

Features:
- Parses SSH authentication logs and validates IP addresses.
- Detects suspicious login activity using time-based thresholds, checking for validity of dates.
- Classifies detected activity as LOW, MEDIUM, or HIGH severity.
- Generates CSV security reports.
- Includes automated unit tests.
- Supports command-line arguments and a built-in help menu.

Tech Used

Python 3.12, Git, GitHub, and Python's standard libraries.

Usage Information

In the terminal run:
git clone https://github.com/PippyHonk/AuthWatch.git
cd AuthWatch
python main.py

The current version analyzes the sample log file configured in `main.py`.

Testing File

python -m unittest discover -s tests -v

Note:
Detection thresholds are rule-based and may produce false positives or miss certain attack patterns.

Andrew Pliscofsky — University of Florida, Computer Science
