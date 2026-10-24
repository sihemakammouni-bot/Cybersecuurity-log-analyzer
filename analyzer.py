

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import re

SUSPICIOUS_THRESHOLD = 3
TIME_WINDOW_MINUTES = 1

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"LOGIN (?P<status>SUCCESS|FAILED) "
    r"IP=(?P<ip>\S+)$"
)


def parse_log_line(line):
    """Parse a log line. Return None when the format is invalid."""
    match = LOG_PATTERN.fullmatch(line.strip())

    if not match:
        return None

    try:
        timestamp = datetime.strptime(
            match.group("timestamp"),
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "status": match.group("status"),
        "ip": match.group("ip"),
    }


def analyze_logs(lines):
    """Analyze log events and identify repeated failed logins."""
    events = []
    invalid_lines = 0

    for line in lines:
        if not line.strip():
            continue

        event = parse_log_line(line)

        if event is None:
            invalid_lines += 1
        else:
            events.append(event)

    events.sort(key=lambda event: event["timestamp"])

    failed_events = [
        event for event in events
        if event["status"] == "FAILED"
    ]

    failed_counts = Counter(
        event["ip"] for event in failed_events
    )

    suspicious_ips = {
        ip: count
        for ip, count in failed_counts.items()
        if count >= SUSPICIOUS_THRESHOLD
    }

    events_by_ip = defaultdict(list)

    for event in failed_events:
        events_by_ip[event["ip"]].append(event["timestamp"])

    window_alerts = []
    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for ip, timestamps in events_by_ip.items():
        timestamps.sort()
        left = 0

        for right, timestamp in enumerate(timestamps):
            while timestamps[right] - timestamps[left] > window:
                left += 1

            count = right - left + 1

            if count >= SUSPICIOUS_THRESHOLD:
                window_alerts.append({
                    "ip": ip,
                    "count": count,
                    "start": timestamps[left],
                    "end": timestamp,
                })
                break

    return {
        "events": events,
        "total_events": len(events),
        "successful_logins": sum(
            event["status"] == "SUCCESS" for event in events
        ),
        "failed_logins": len(failed_events),
        "failed_counts": failed_counts,
        "suspicious_ips": suspicious_ips,
        "window_alerts": window_alerts,
        "invalid_lines": invalid_lines,
    }


def create_report(results):
    """Generate a readable text report."""
    report = [
        "CYBERSECURITY LOG ANALYZER",
        "=" * 32,
        "",
        f"Total valid events: {results['total_events']}",
        f"Successful logins: {results['successful_logins']}",
        f"Failed logins: {results['failed_logins']}",
        f"Invalid lines: {results['invalid_lines']}",
        "",
        "FAILED ATTEMPTS BY IP",
        "-" * 24,
    ]

    if results["failed_counts"]:
        for ip, count in sorted(
            results["failed_counts"].items(),
            key=lambda item: (-item[1], item[0])
        ):
            report.append(f"{ip}: {count}")
    else:
        report.append("No failed login attempts.")

    report.extend(["", "SUSPICIOUS IP ADDRESSES", "-" * 24])

    if results["suspicious_ips"]:
        for ip, count in sorted(
            results["suspicious_ips"].items(),
            key=lambda item: (-item[1], item[0])
        ):
            report.append(
                f"ALERT: {ip} recorded {count} failed logins."
            )
    else:
        report.append("No IP reached the configured threshold.")

    report.extend([
        "",
        f"FAILURES WITHIN {TIME_WINDOW_MINUTES} MINUTE(S)",
        "-" * 32,
    ])

    if results["window_alerts"]:
        for alert in results["window_alerts"]:
            report.append(
                f"ALERT: {alert['ip']} recorded "
                f"{alert['count']} failures from "
                f"{alert['start']} to {alert['end']}."
            )
    else:
        report.append("No time-window alert detected.")

    report.extend([
        "",
        "Note: Alerts are indicators for investigation,",
        "not proof of a cyberattack.",
        "",
    ])

    return "\n".join(report)
