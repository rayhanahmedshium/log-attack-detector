import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detector import LoginEvent, find_brute_force, find_compromised, parse_line

BASE = datetime(2026, 10, 6, 12, 0, 0)


def fail(ip, seconds, user="root"):
    return LoginEvent(BASE + timedelta(seconds=seconds), ip, user, False)


def ok(ip, seconds, user="root"):
    return LoginEvent(BASE + timedelta(seconds=seconds), ip, user, True)


def test_parse_failed_line():
    e = parse_line("Oct  6 14:02:11 srv sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2", 2026)
    assert e.ip == "203.0.113.5"
    assert e.user == "root"
    assert e.success is False
    assert e.timestamp == datetime(2026, 10, 6, 14, 2, 11)


def test_parse_invalid_user_line():
    e = parse_line("Oct  6 14:02:11 srv sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 1 ssh2", 2026)
    assert e.user == "admin"


def test_parse_accepted_line():
    e = parse_line("Oct 16 09:00:00 srv sshd[1]: Accepted publickey for rayhan from 10.0.0.1 port 1 ssh2", 2026)
    assert e.success is True


def test_ignores_unrelated_lines():
    assert parse_line("Oct  6 14:02:11 srv sshd[1]: Connection closed by 1.2.3.4 port 22", 2026) is None
    assert parse_line("", 2026) is None


def test_flags_fast_attack():
    events = [fail("1.1.1.1", s) for s in range(0, 10)]  # 10 failures in 10s
    assert find_brute_force(events, threshold=5, window_seconds=60) == {"1.1.1.1": 10}


def test_ignores_slow_spread_out_failures():
    events = [fail("2.2.2.2", s * 120) for s in range(10)]  # one every 2 min
    assert find_brute_force(events, threshold=5, window_seconds=60) == {}


def test_successes_do_not_count_as_failures():
    events = [ok("3.3.3.3", s) for s in range(20)]
    assert find_brute_force(events) == {}


def test_compromise_detected_after_attack():
    events = [fail("4.4.4.4", s) for s in range(10)] + [ok("4.4.4.4", 15, "deploy")]
    flagged = find_brute_force(events)
    assert find_compromised(events, flagged) == {"4.4.4.4": ["deploy"]}


def test_no_compromise_for_unflagged_ip():
    events = [fail("5.5.5.5", 0), ok("5.5.5.5", 5)]  # one typo, then success
    assert find_compromised(events, find_brute_force(events)) == {}
