"""
Log Attack Detector
-------------------
Reads a Linux SSH authentication log (like /var/log/auth.log), finds
brute-force login attempts, and writes a short report plus charts.

How it works:
1. parse_line() turns each log line into a LoginEvent (time, IP, user, success).
2. find_brute_force() slides a time window over each IP's failed logins and
   flags the IP if it fails too many times inside that window.
3. find_compromised() flags IPs that failed many times and then succeeded,
   which can mean an attacker guessed the password.
4. make_charts() draws failed attempts over time and the top attacking IPs.

Usage:
    python detector.py sample_logs/auth.log
    python detector.py sample_logs/auth.log --threshold 5 --window 60 --charts
"""

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

# Example lines this regex matches:
#   Oct  6 14:02:11 server sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2
#   Oct  6 14:02:11 server sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52211 ssh2
#   Oct  6 14:05:40 server sshd[1240]: Accepted password for rayhan from 192.168.1.20 port 50100 ssh2
LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"\S+\ssshd\[\d+\]:\s"
    r"(?P<result>Failed|Accepted) (?:password|publickey) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)


@dataclass
class LoginEvent:
    timestamp: datetime
    ip: str
    user: str
    success: bool


def parse_line(line, year=None):
    """Turn one log line into a LoginEvent, or return None if it isn't a login line."""
    match = LOG_PATTERN.search(line)
    if not match:
        return None
    # auth.log lines don't include the year, so we supply one.
    year = year or datetime.now().year
    stamp = f"{year} {match['month']} {match['day']} {match['time']}"
    return LoginEvent(
        timestamp=datetime.strptime(stamp, "%Y %b %d %H:%M:%S"),
        ip=match["ip"],
        user=match["user"],
        success=match["result"] == "Accepted",
    )


def parse_log(path, year=None):
    """Read a whole log file and return a list of LoginEvents."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line, year)
            if event:
                events.append(event)
    return events


def find_brute_force(events, threshold=5, window_seconds=60):
    """
    Return {ip: max_failures_in_window} for every IP that failed at least
    `threshold` times within any `window_seconds` period.

    Uses a sliding window: for each IP, keep the start pointer behind the
    end pointer so the window never covers more than window_seconds.
    """
    failures = defaultdict(list)
    for e in events:
        if not e.success:
            failures[e.ip].append(e.timestamp)

    window = timedelta(seconds=window_seconds)
    flagged = {}
    for ip, times in failures.items():
        times.sort()
        start = 0
        worst = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            worst = max(worst, end - start + 1)
        if worst >= threshold:
            flagged[ip] = worst
    return flagged


def find_compromised(events, flagged_ips):
    """
    Return {ip: [users]} for flagged IPs that later logged in successfully.
    A successful login right after a brute-force run is the most serious alert.
    """
    first_failure = {}
    hits = defaultdict(list)
    for e in sorted(events, key=lambda e: e.timestamp):
        if e.ip not in flagged_ips:
            continue
        if not e.success:
            first_failure.setdefault(e.ip, e.timestamp)
        elif e.ip in first_failure:
            hits[e.ip].append(e.user)
    return dict(hits)


def summarize(events, flagged, compromised):
    """Build the text report as a string."""
    failed = [e for e in events if not e.success]
    targeted_users = Counter(e.user for e in failed)
    lines = [
        "=" * 50,
        "SSH LOG ANALYSIS REPORT",
        "=" * 50,
        f"Login events parsed : {len(events)}",
        f"Failed logins       : {len(failed)}",
        f"Successful logins   : {len(events) - len(failed)}",
        f"Unique source IPs   : {len({e.ip for e in events})}",
        "",
        f"Brute-force IPs flagged: {len(flagged)}",
    ]
    for ip, count in sorted(flagged.items(), key=lambda x: -x[1]):
        lines.append(f"  {ip:<16} {count} failures in one window")

    lines.append("")
    if compromised:
        lines.append("!! POSSIBLE COMPROMISE: flagged IP later logged in successfully")
        for ip, users in compromised.items():
            lines.append(f"  {ip:<16} accepted as: {', '.join(sorted(set(users)))}")
    else:
        lines.append("No successful logins from flagged IPs.")

    lines += ["", "Most targeted usernames:"]
    for user, count in targeted_users.most_common(5):
        lines.append(f"  {user:<16} {count}")
    return "\n".join(lines)


def make_charts(events, flagged, out_prefix="report"):
    """Save two PNG charts: failures per minute, and top attacking IPs."""
    import matplotlib
    matplotlib.use("Agg")  # draw to files, no window needed
    import matplotlib.pyplot as plt

    failed = [e for e in events if not e.success]
    if not failed:
        return []

    per_minute = Counter(e.timestamp.replace(second=0) for e in failed)
    # Include every minute in the range (with 0 for quiet minutes) so the
    # line drops to zero between attacks instead of drawing a false slope.
    first, last = min(per_minute), max(per_minute)
    times = [first + timedelta(minutes=i) for i in range(int((last - first).total_seconds() // 60) + 1)]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(times, [per_minute[t] for t in times], color="#c0392b", linewidth=1.5)
    ax.set_title("Failed SSH logins per minute")
    ax.set_ylabel("Failed attempts")
    ax.grid(alpha=0.3)
    fig.autofmt_xdate()
    timeline = f"{out_prefix}_timeline.png"
    fig.savefig(timeline, dpi=120, bbox_inches="tight")
    plt.close(fig)

    by_ip = Counter(e.ip for e in failed).most_common(10)
    fig, ax = plt.subplots(figsize=(8, 4))
    ips = [ip for ip, _ in by_ip][::-1]
    counts = [c for _, c in by_ip][::-1]
    colors = ["#c0392b" if ip in flagged else "#7f8c8d" for ip in ips]
    ax.barh(ips, counts, color=colors)
    ax.set_title("Top source IPs by failed logins (red = flagged)")
    ax.set_xlabel("Failed attempts")
    top_ips = f"{out_prefix}_top_ips.png"
    fig.savefig(top_ips, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return [timeline, top_ips]


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attacks in auth logs.")
    parser.add_argument("logfile", help="path to auth.log")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failures inside the window needed to flag an IP (default 5)")
    parser.add_argument("--window", type=int, default=60,
                        help="window size in seconds (default 60)")
    parser.add_argument("--charts", action="store_true", help="save PNG charts")
    args = parser.parse_args()

    events = parse_log(args.logfile)
    flagged = find_brute_force(events, args.threshold, args.window)
    compromised = find_compromised(events, flagged)
    print(summarize(events, flagged, compromised))

    if args.charts:
        for path in make_charts(events, flagged):
            print(f"Chart saved: {path}")


if __name__ == "__main__":
    main()
