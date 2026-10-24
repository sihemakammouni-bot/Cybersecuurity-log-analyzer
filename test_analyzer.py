

import unittest
from datetime import datetime

from analyzer import parse_log_line, analyze_logs, create_report


class TestLogAnalyzer(unittest.TestCase):

    def test_parse_valid_line(self):
        line = (
            "2026-10-24 10:00:00 "
            "LOGIN FAILED IP=203.0.113.25"
        )
        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["status"], "FAILED")
        self.assertEqual(event["ip"], "203.0.113.25")
        self.assertEqual(
            event["timestamp"],
            datetime(2026, 10, 24, 10, 0, 0),
        )

    def test_reject_invalid_line(self):
        self.assertIsNone(parse_log_line("INVALID LOG ENTRY"))

    def test_detect_repeated_failures(self):
        lines = [
            "2026-10-24 10:00:00 LOGIN FAILED IP=203.0.113.25",
            "2026-10-24 10:00:10 LOGIN FAILED IP=203.0.113.25",
            "2026-10-24 10:00:20 LOGIN FAILED IP=203.0.113.25",
        ]

        results = analyze_logs(lines)

        self.assertEqual(results["failed_logins"], 3)
        self.assertEqual(results["suspicious_ips"]["203.0.113.25"], 3)
        self.assertEqual(len(results["window_alerts"]), 1)

    def test_count_invalid_lines(self):
        results = analyze_logs([
            "INVALID LOG ENTRY",
            "2026-10-24 10:00:00 LOGIN SUCCESS IP=192.168.1.10",
        ])

        self.assertEqual(results["invalid_lines"], 1)
        self.assertEqual(results["total_events"], 1)

    def test_create_report(self):
        results = analyze_logs([
            "2026-10-24 10:00:00 LOGIN SUCCESS IP=192.168.1.10",
        ])

        report = create_report(results)

        self.assertIn("CYBERSECURITY LOG ANALYZER", report)
        self.assertIn("Successful logins: 1", report)


if __name__ == "__main__":
    unittest.main()
