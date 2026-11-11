import unittest
from parser import parse_log_line

def test_invalid_timestamp(self):
    line = (
        "Nov 35 25:99:99 server sshd[1234]: "
        "Failed password for root from 203.0.113.42 "
        "port 51234 ssh2"
    )

    self.assertIsNone(parse_log_line(line))

def test_invalid_leap_day(self):
    line = (
        "Feb 29 10:15:22 server sshd[1234]: "
        "Failed password for root from 203.0.113.42 "
        "port 51234 ssh2"
    )

    self.assertIsNone(parse_log_line(line, year=2025))
    self.assertIsNotNone(parse_log_line(line, year=2024))