import unittest
from datetime import datetime, timedelta, timezone
from detect_logon_incidents import detect, load_events
from pathlib import Path


class DetectionTests(unittest.TestCase):
    def test_fixture_produces_correlated_and_noncorrelated_alerts(self):
        records = load_events(Path(__file__).with_name("sample_events.csv"))
        alerts = detect(records)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["category"], "success_after_repeated_failures")
        self.assertEqual(alerts[1]["severity"], "MEDIUM")
        self.assertIsNone(alerts[1]["success_at"])

    def test_events_outside_window_do_not_trigger(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [dict(timestamp=start + timedelta(minutes=12 * n),
                       event_id="4625", username="user", source_ip="198.51.100.1")
                  for n in range(8)]
        self.assertEqual(detect(events), [])

    def test_different_account_does_not_trigger_correlation(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [dict(timestamp=start + timedelta(minutes=n),
                       event_id="4625", username="user", source_ip="198.51.100.1")
                  for n in range(5)]
        events.append(dict(timestamp=start + timedelta(minutes=6),
                           event_id="4624", username="different", source_ip="198.51.100.1"))
        self.assertEqual(detect(events)[0]["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
