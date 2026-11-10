import unittest
from detector import detect_brute_force
from parser import parse_log_line

class TestBruteForceDetector(unittest.TestCase):
    def make_event(self, ip, timestamp, status="FAILED"):
        return {
            "ip": ip,
            "timestamp": timestamp,
            "event_type": status,
            "username": "test_user"
        }

    def test_five_attempts_within_window(self):
        events = [
            self.make_event("10.0.0.1", "Nov 7 10:15:22"),
            self.make_event("10.0.0.1", "Nov 7 10:15:25"),
            self.make_event("10.0.0.1", "Nov 7 10:15:28"),
            self.make_event("10.0.0.1", "Nov 7 10:15:31"),
            self.make_event("10.0.0.1", "Nov 7 10:15:34")
        ]

        result = detect_brute_force(events)

        self.assertEqual(result, {"10.0.0.1": 5})

    def test_five_attempts_outside_window(self):
        events = [
            self.make_event("10.0.0.1", "Nov 7 10:15:22"),
            self.make_event("10.0.0.1", "Nov 7 10:15:25"),
            self.make_event("10.0.0.1", "Nov 7 10:15:28"),
            self.make_event("10.0.0.1", "Nov 7 10:16:31"),
            self.make_event("10.0.0.1", "Nov 7 10:17:34")
        ]

        self.assertEqual(detect_brute_force(events), {})

    def test_mixed_logins(self):
        events = [
            self.make_event("10.0.0.1", "Nov 7 10:15:22", "SUCCESS"),
            self.make_event("10.0.0.1", "Nov 7 10:15:25"),
            self.make_event("10.0.0.1", "Nov 7 10:15:28"),
            self.make_event("10.0.0.1", "Nov 7 10:15:31"),
            self.make_event("10.0.0.1", "Nov 7 10:15:34"),
            self.make_event("10.0.0.1", "Nov 7 10:15:36"),
            self.make_event("10.0.0.1", "Nov 7 10:15:39")
        ]

        self.assertEqual(detect_brute_force(events), {"10.0.0.1": 6})

    def test_ips(self):
        events = [
            self.make_event("10.0.0.1", "Nov 7 10:15:22"),
            self.make_event("10.0.0.1", "Nov 7 10:15:25"),
            self.make_event("10.0.0.2", "Nov 7 10:15:28"),
            self.make_event("10.0.0.1", "Nov 7 10:15:31"),
            self.make_event("10.0.0.3", "Nov 7 10:15:34"),
            self.make_event("10.0.0.1", "Nov 7 10:15:36"),
            self.make_event("10.0.0.5", "Nov 7 10:15:39")
        ]

        self.assertEqual(detect_brute_force(events), {})

    def test_unsorted(self):
        events = [
            self.make_event("10.0.0.1", "Nov 7 10:15:22"),
            self.make_event("10.0.0.1", "Nov 7 10:15:25"),
            self.make_event("10.0.0.1", "Nov 7 10:16:02"),
            self.make_event("10.0.0.1", "Nov 7 10:15:31"),
            self.make_event("10.0.0.1", "Nov 7 10:16:00"),
            self.make_event("10.0.0.1", "Nov 7 10:15:36"),
        ]

        self.assertEqual(detect_brute_force(events), {"10.0.0.1": 6})


    def test_jumbled_mess(self):
        events = [
            self.make_event("10.0.0.1", "Nov 7 10:15:22"),
            self.make_event("10.0.0.1", "Nov 7 10:15:25", "SUCCESS"),
            self.make_event("10.0.0.2", "Nov 7 10:15:28"),
            self.make_event("10.0.0.1", "Nov 7 10:15:31"),
            self.make_event("10.0.0.3", "Nov 7 10:16:00"),
            self.make_event("10.0.0.1", "Nov 7 10:15:36", "FAILED"),
            self.make_event("10.0.0.5", "Nov 7 10:15:39"),
            self.make_event("10.0.0.1", "Nov 7 10:16:20", "SUCCESS"),
            self.make_event("10.0.0.3", "Nov 7 10:15:34"),
            self.make_event("10.0.0.1", "Nov 7 10:15:36"),
            self.make_event("10.0.0.5", "Nov 7 10:16:22"),
            self.make_event("10.0.0.1", "Nov 7 10:15:36"),
            self.make_event("10.0.0.1", "Nov 7 10:16:22"),
        ]

        self.assertEqual(detect_brute_force(events), {"10.0.0.1": 6})

    def test_multiple_fails(self):
        events = [
            self.make_event("10.0.0.1", "Nov 7 10:15:22"),
            self.make_event("10.0.0.3", "Nov 7 10:15:28"),
            self.make_event("10.0.0.1", "Nov 7 10:15:31"),
            self.make_event("10.0.0.3", "Nov 7 10:16:00"),
            self.make_event("10.0.0.1", "Nov 7 10:15:36", "FAILED"),
            self.make_event("10.0.0.1", "Nov 7 10:16:20", "SUCCESS"),
            self.make_event("10.0.0.3", "Nov 7 10:15:34"),
            self.make_event("10.0.0.1", "Nov 7 10:15:36"),
            self.make_event("10.0.0.3", "Nov 7 10:16:22"),
            self.make_event("10.0.0.1", "Nov 7 10:15:36"),
            self.make_event("10.0.0.3", "Nov 7 10:16:22"),
        ]

        self.assertEqual(detect_brute_force(events), {"10.0.0.1": 5, "10.0.0.3": 5})

class TestParserInput(unittest.TestCase):
    def test_valid_failed(self):
        line = (
            "Nov  7 10:15:22 server sshd[1234]: "
            "Failed password for root from 203.0.113.42 "
            "port 51234 ssh2"
        )
        result = parse_log_line(line)

        self.assertEqual(result["ip"], "203.0.113.42")
        self.assertEqual(result["username"], "root")
        self.assertEqual(result["event_type"], "FAILED")
        self.assertEqual(result["timestamp"], "Nov 7 10:15:22")

    def test_invalid_ip(self):
        line = (
            "Nov  7 10:15:22 server sshd[1234]: "
            "Failed password for root from 999.999.999.999 "
            "port 51234 ssh2"
        )

        self.assertIsNone(parse_log_line(line))

    def test_timestamp(self):
        line = (
            "Nov 3 10:22222:24 server sshd[22]: "
            "Failed password for root from 0.999.999.16 "
            "552ssh2"
        )

        self.assertIsNone(parse_log_line(line))

    def test_success(self):
        line = (
            "Nov 5 10:13:22 server sshd[1234]: "
            "Accepted password for Andrew from 183.1.2.15 "
            "port 51234 ssh2"
        )

        self.assertIsNone(parse_log_line(line))

    def test_confusing_success(self):
        line = (
            "Nov 5 10:13:22 server sshd[1234]: "
            "Accepted password for bringme from "
            "port 51234 ssh2"
        )

        self.assertIsNone(parse_log_line(line))

    def test_invalid_user(self):
        line = (
            "Nov 5 10:13:22 server sshd[1234]: "
            "Failed password for invalid user admin from 192.0.1.15 "
            "port 51234 ssh2"
        )

        result = parse_log_line(line)

        self.assertEqual(result["ip"], "192.0.1.15")
        self.assertEqual(result["username"], "admin")
        self.assertEqual(result["event_type"], "FAILED")
        self.assertEqual(result["timestamp"], "Nov 5 10:13:22")

    def test_no_ip(self):
        line = (
            "Nov 5 10:13:22 server sshd[1234]: "
            "Failed password for marcus from "
            "port 51234 ssh2"
        )

        self.assertIsNone(parse_log_line(line))

if __name__ == "__main__":
    unittest.main()