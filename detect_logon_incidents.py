#!/usr/bin/env python3
"""Correlate Windows logon events exported to CSV from a controlled Splunk lab.

Accepts a CSV with timestamp,event_id,username,source_ip columns (common field
aliases also accepted), correlates Event ID 4625 failures followed by Event ID
4624 success, and writes a JSON alert log plus a Markdown incident report.

This is an offline detection prototype, not proof that an account was compromised.
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

FIELD_ALIASES = {
    "timestamp": ("timestamp", "_time", "TimeCreated", "time"),
    "event_id": ("event_id", "EventCode", "EventID", "eventcode"),
    "username": ("username", "TargetUserName", "Account_Name", "user"),
    "source_ip": ("source_ip", "IpAddress", "Source_Network_Address", "src_ip", "src"),
}


def parse_time(value: str) -> datetime:
    """Convert epoch seconds or ISO-style time to a UTC-aware datetime."""
    raw = value.strip()
    try:
        if raw and raw.replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"Unrecognized timestamp {value!r}") from exc
    if dt.tzinfo is None:
        # Splunk CSV _time can be local; export UTC explicitly for reliable results.
        # This example assumes timezone-free strings are UTC.
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_events(csv_path: Path) -> list[dict]:
    with csv_path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("The CSV has no header row")
        found = {}
        for desired, options in FIELD_ALIASES.items():
            match = next((name for name in options if name in reader.fieldnames), None)
            if not match:
                raise ValueError(
                    f"Missing {desired!r} field. Accepted CSV headings: {', '.join(options)}"
                )
            found[desired] = match
        events = []
        for line_number, row in enumerate(reader, 2):
            event_code = (row[found["event_id"]] or "").strip()
            if event_code not in {"4624", "4625"}:
                continue
            try:
                when = parse_time(row[found["timestamp"]] or "")
            except ValueError as exc:
                raise ValueError(f"CSV line {line_number}: {exc}") from exc
            ip = (row[found["source_ip"]] or "").strip()
            username = (row[found["username"]] or "").strip()
            # Events without a source IP or account cannot support this correlation.
            if not ip or ip == "-" or not username or username == "-":
                continue
            events.append({"timestamp": when, "event_id": event_code,
                           "username": username, "source_ip": ip})
    return sorted(events, key=lambda x: x["timestamp"])


def detect(events: list[dict], threshold: int = 5,
           window_minutes: int = 10, success_minutes: int = 15) -> list[dict]:
    if threshold < 2 or window_minutes < 1 or success_minutes < 1:
        raise ValueError("threshold must be >= 2 and time windows must be >= 1 minute")

    window = timedelta(minutes=window_minutes)
    success_window = timedelta(minutes=success_minutes)
    failed_by_key = defaultdict(deque)
    active = {}
    alerts = []

    for event in sorted(events, key=lambda x: x["timestamp"]):
        key = (event["source_ip"], event["username"])
        now = event["timestamp"]
        failures = failed_by_key[key]
        max_window = max(window, success_window)
        while failures and now - failures[0] > max_window:
            failures.popleft()

        if event["event_id"] == "4625":
            failures.append(now)
            recent = [time for time in failures if now - time <= window]
            if len(recent) < threshold:
                continue
            latest = active.get(key)
            if latest and now - datetime.fromisoformat(latest["last_failed_at"]) <= window:
                latest["failure_count"] += 1
                latest["last_failed_at"] = now.isoformat()
            else:
                alert = {
                    "severity": "MEDIUM", "category": "repeated_failed_logons",
                    "source_ip": key[0], "username": key[1],
                    "failure_count": len(recent),
                    "first_failed_at": recent[0].isoformat(),
                    "last_failed_at": now.isoformat(),
                    "success_at": None,
                    "explanation": "Repeated failed logons warrant investigation; they do not prove an attack.",
                }
                alerts.append(alert)
                active[key] = alert
        elif event["event_id"] == "4624":
            latest = active.get(key)
            if latest:
                last_failed = datetime.fromisoformat(latest["last_failed_at"])
                if timedelta(0) <= now - last_failed <= success_window:
                    latest["severity"] = "HIGH"
                    latest["category"] = "success_after_repeated_failures"
                    latest["success_at"] = now.isoformat()
                    latest["explanation"] = (
                        "A successful logon followed repeated failures for the same "
                        "source/account. Investigate; compromise is not confirmed."
                    )
                active.pop(key, None)
            failures.clear()

    return alerts


def write_results(alerts: list[dict], destination: Path, analyzed_count: int) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    payload = {"events_analyzed": analyzed_count, "alert_count": len(alerts),
               "alerts": alerts}
    (destination / "alerts.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    report = ["# Windows Logon Detection Report", "",
              f"Events analyzed: **{analyzed_count}**  ",
              f"Alerts generated: **{len(alerts)}**", "",
              "**Scope:** Automated triage of exported lab events. An alert is not proof of compromise.", ""]
    if not alerts:
        report.append("No matching suspicious patterns found at the selected thresholds.\n")
    for i, a in enumerate(alerts, 1):
        report.extend([
            f"## Alert {i}: {a['severity']} - {a['category']}", "",
            f"- Source IP: `{a['source_ip']}`",
            f"- Account: `{a['username']}`",
            f"- Failed logons recorded in alert: {a['failure_count']}",
            f"- First failure: {a['first_failed_at']}",
            f"- Last failure: {a['last_failed_at']}",
            f"- Subsequent successful logon: {a['success_at'] or 'Not observed'}",
            f"- Interpretation: {a['explanation']}", "",
        ])
    report += ["## Suggested analyst follow-up", "",
               "1. Verify timestamps, account context, and whether events are expected.",
               "2. Check login type, workstation, MFA outcomes, and nearby events if available.",
               "3. Escalate through your lab's incident-response process if warranted.", ""]
    (destination / "incident_report.md").write_text("\n".join(report), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="CSV export from your Splunk lab")
    parser.add_argument("--output", type=Path, default=Path("reports"), help="Report directory")
    parser.add_argument("--threshold", type=int, default=5, help="Failed logons to trigger alert")
    parser.add_argument("--window", type=int, default=10, help="Failed-logon window in minutes")
    parser.add_argument("--success-window", type=int, default=15,
                        help="Minutes after failure to correlate a success")
    args = parser.parse_args()
    try:
        events = load_events(args.input)
        alerts = detect(events, args.threshold, args.window, args.success_window)
        write_results(alerts, args.output, len(events))
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Processed {len(events)} logon events; generated {len(alerts)} alerts.")
    print(f"Results: {args.output / 'alerts.json'} and {args.output / 'incident_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
