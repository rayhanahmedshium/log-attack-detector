"""
Generates a realistic fake auth.log for testing the detector.
All IPs come from documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
or private ranges, so none of them belong to real people.

Usage:
    python generate_sample_log.py > sample_logs/auth.log
"""

import random
from datetime import datetime, timedelta

random.seed(42)  # same output every run

START = datetime(2026, 10, 6, 8, 0, 0)
NORMAL_USERS = ["rayhan", "deploy", "backup"]
GUESSED_USERS = ["root", "admin", "test", "oracle", "ubuntu", "pi", "guest"]
LEGIT_IPS = ["192.168.1.20", "192.168.1.35", "10.0.0.12"]


def line(ts, ok, user, ip, invalid=False):
    pid = random.randint(1000, 9999)
    port = random.randint(40000, 65000)
    word = "Accepted" if ok else "Failed"
    inv = "invalid user " if invalid else ""
    return f"{ts:%b %d %H:%M:%S} webserver sshd[{pid}]: {word} password for {inv}{user} from {ip} port {port} ssh2"


def main():
    out = []

    # Normal daytime traffic: mostly successes, an occasional typo.
    t = START
    for _ in range(60):
        t += timedelta(minutes=random.randint(3, 12))
        ip = random.choice(LEGIT_IPS)
        user = random.choice(NORMAL_USERS)
        if random.random() < 0.15:
            out.append((t, line(t, False, user, ip)))
            t += timedelta(seconds=random.randint(5, 20))
        out.append((t, line(t, True, user, ip)))

    # Attack 1: fast dictionary attack from one IP, never gets in.
    t = START + timedelta(hours=2, minutes=14)
    for _ in range(80):
        t += timedelta(seconds=random.uniform(0.5, 2.5))
        user = random.choice(GUESSED_USERS)
        out.append((t, line(t, False, user, "203.0.113.45", invalid=user != "root")))

    # Attack 2: slower attack that eventually succeeds (the compromise case).
    t = START + timedelta(hours=5, minutes=3)
    for _ in range(25):
        t += timedelta(seconds=random.uniform(2, 6))
        out.append((t, line(t, False, "deploy", "198.51.100.77")))
    t += timedelta(seconds=4)
    out.append((t, line(t, True, "deploy", "198.51.100.77")))

    # Background noise: scattered single failures from many IPs (not an attack).
    for i in range(30):
        t = START + timedelta(minutes=random.randint(0, 600))
        ip = f"192.0.2.{random.randint(1, 254)}"
        out.append((t, line(t, False, random.choice(GUESSED_USERS), ip, invalid=True)))

    # Some unrelated sshd lines the parser should ignore.
    for i in range(10):
        t = START + timedelta(minutes=random.randint(0, 600))
        out.append((t, f"{t:%b %d %H:%M:%S} webserver sshd[{random.randint(1000,9999)}]: "
                       f"Connection closed by 192.0.2.{random.randint(1,254)} port 22 [preauth]"))

    for _, text in sorted(out):
        print(text)


if __name__ == "__main__":
    main()
