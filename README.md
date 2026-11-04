# CyberShield Security Monitor

A menu-driven security toolkit for the terminal, written in Python. It puts a few everyday checks in one program (password strength, port checks, log analysis, an internet check) and records everything it does in a log file.

It uses file handling, sockets and logging together, and the only third-party library is `requests`.

## What it can do

| Option | Feature | What it does |
|---|---|---|
| 1 | Password Strength Checker | Rates a password WEAK, MEDIUM or STRONG |
| 2 | IP & Port Security Checker | Validates an IPv4 address and a port, then checks whether that TCP port accepts a connection |
| 3 | Security Log Analyzer | Counts the events recorded in the log |
| 4 | Automated Port Monitor | Checks ports 21, 22, 80 and 443 on a target and saves the results |
| 5 | View Security Logs | Prints the whole log |
| 6 | Check Internet Connectivity | Calls `api.ipify.org` to confirm there's a connection and show the public IP |
| 7 | Exit | Closes the program |

## Getting started

You need Python 3.6 or newer (the code uses f-strings) and the `requests` library.

```
pip install -r requirements.txt
python cyber_shield.py
```

On the first run it creates `security_log.txt` and `scan_results.txt` next to the script.

## Screenshots

**Password checker.** `abc@123` is rejected for being under 8 characters, and `Abc@123345` is rated STRONG.

![Password strength checker](./screenshots/01-password-strength-checker.png)

**IP & port checker.** Port 80 on `127.0.0.1` comes back CLOSED and the event is logged.

![IP and port checker](./screenshots/02-ip-and-port-checker.png)

**Automated port monitor.** All four ports on `127.0.0.1` are checked, and the results are saved to `scan_results.txt`.

![Automated port monitor](./screenshots/03-automated-port-monitor.png)

**Log analyzer.** It reports 3 port checks and 4 password checks, 7 events in total.

![Security log analyzer](./screenshots/04-security-log-analyzer.png)

**Security log.** The full log: password checks, port checks and automated scans, each with a timestamp.

![Security logs](./screenshots/05-security-logs.png)

**Internet check.** Connection available, plus the public IP. I've covered the IP, because it has no business being on GitHub.

![Internet connectivity check](./screenshots/06-internet-connectivity-check.png)

**Exit.**

![Clean exit](./screenshots/07-clean-exit.png)

The first screenshot comes from an earlier version of the script, so the menu and exit wording differ a little from the current one. The others match the current version.

## How it works

### Password rating

- Under 8 characters is WEAK straight away.
- Otherwise it looks for four kinds of character: uppercase, lowercase, digits, and anything else. All four is STRONG, two or three is MEDIUM, and one is WEAK.
- The password itself is never written to the log. Only the strength is.

| Password | Result | Why |
|---|---|---|
| `abc@123` | WEAK | only 7 characters |
| `abcdefgh` | WEAK | one kind of character |
| `abcdefg1` | MEDIUM | two kinds |
| `Abc@123345` | STRONG | all four kinds, 10 characters |

### Port checks

- The IP is validated with `socket.inet_aton()`, and the port has to be a whole number from 1 to 65535.
- The checker tries a TCP connection with `connect_ex()`. A result of `0` means the connection was accepted, so the port is OPEN. Anything else is reported as CLOSED.
- The single-port check waits up to 2 seconds. The automated monitor waits up to 1 second per port (21 FTP, 22 SSH, 80 HTTP, 443 HTTPS), so one scan takes at most about 4 seconds.
- Each result is logged, and the automated monitor also appends a timestamped block to `scan_results.txt`.

### Logging

Everything goes through one small function that appends a timestamped line to the log:

```python
def log_event(event):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as file:
        file.write(f"[{timestamp}] {event}\n")
```

A few lines from a real run:

```
[2026-09-17 13:34:35] PASSWORD CHECK - Strength: MEDIUM
[2026-09-17 13:39:36] PORT CHECK - IP: 127.0.0.1 - Port: 80 - Status: CLOSED
[2026-09-17 13:42:24] AUTOMATED SCAN - IP: 127.0.0.1 - Port: 21 - Status: CLOSED
```

The log files are created with `"w"` only if they don't exist yet, new events are added with `"a"`, and the viewer and analyzer read with `"r"`. That means the log survives between runs.

### Internet check

It sends a GET request to `https://api.ipify.org?format=json` with a 5-second timeout. If it works, it prints and logs the public IP. If it doesn't (no connection, DNS failure, timeout), the error is caught, printed and logged, and the program carries on.

**The log files are in `.gitignore` on purpose.** After option 6 the log contains the public IP, and it also records every address that was scanned, so those files shouldn't end up on GitHub.

## Things I'd improve

- **The analyzer only knows five kinds of event, and each log line is counted once.** It checks for `ERROR`, `WARNING`, `FAILED LOGIN`, `PORT CHECK` and `PASSWORD CHECK`, in that order:

  ```python
  if "ERROR" in line:
      error_count += 1
  elif "WARNING" in line:
      warning_count += 1
  elif "FAILED LOGIN" in line:
      failed_login_count += 1
  elif "PORT CHECK" in line:
      port_check_count += 1
  elif "PASSWORD CHECK" in line:
      password_check_count += 1
  ```

  That has some side effects:
  - `AUTOMATED SCAN` and `INTERNET CHECK` events are logged but never counted. After two automated scans (8 new log lines) the total didn't change.
  - Matching is case-sensitive, so `failed login` in lowercase is missed.
  - A port check that ends in `Status: ERROR` is counted as an ERROR, not as a port check, and a line containing both `ERROR` and `WARNING` counts only as an ERROR.
  - The app never writes `WARNING` or `FAILED LOGIN` itself, so those two counters only move if such lines are added to the log by hand.
- **"CLOSED" really means "didn't accept the connection".** A port that refuses, a firewalled port and an address with no device behind it all look the same.
- **IP validation is loose.** `inet_aton()` also accepts shorthand such as `127.1`, which then gets logged exactly as typed.
- **The password is visible while typing.** `input()` echoes it, and `getpass` would hide it. Also, the rating measures variety, not guessability: `Password1!` comes out STRONG.
- **`import sys` is never used.**

Next steps I'd try: count the scan and internet events, make the log matching case-insensitive, check passwords against a list of common ones, and let the monitor scan a range of ports.

## Responsible use

This only checks whether TCP ports accept a connection, but it's still a scanner. Only run it against machines you own or have permission to test. The scans in the screenshots only target `127.0.0.1` and a private `192.168.x.x` address.

## Project structure

```
CyberShield-Security-Monitor/
├── cyber_shield.py     the program
├── requirements.txt    third-party library (requests)
├── .gitignore          keeps the generated log files out of Git
├── README.md
└── screenshots/
```
