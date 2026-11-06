import socket
import datetime
import os
import sys
import requests


LOG_FILE = "security_log.txt"
SCAN_FILE = "scan_results.txt"


# -------------------- FILE HANDLING --------------------

def initialize_files():
    """Create required files if they do not exist."""

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as file:
            file.write("=== CyberShield Security Log ===\n")

    if not os.path.exists(SCAN_FILE):
        with open(SCAN_FILE, "w") as file:
            file.write("=== CyberShield Scan Results ===\n")


def log_event(event):
    """Append a security event to the log file."""

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as file:
        file.write(f"[{timestamp}] {event}\n")


def view_logs():
    """Read and display security logs."""

    print("\n========== SECURITY LOGS ==========")

    try:
        with open(LOG_FILE, "r") as file:
            data = file.read()

            if data.strip():
                print(data)
            else:
                print("No security logs available.")

    except FileNotFoundError:
        print("Security log file not found.")


# -------------------- PASSWORD CHECKER --------------------

def check_password_strength():
    """Check password strength."""

    password = input("\nEnter password: ")

    if len(password) < 8:
        print("\nPassword Strength: WEAK")
        print("Reason: Minimum 8 characters required.")
        log_event("PASSWORD CHECK - Weak password detected.")
        return "WEAK"

    has_upper = False
    has_lower = False
    has_digit = False
    has_special = False

    for char in password:

        if char.isupper():
            has_upper = True

        elif char.islower():
            has_lower = True

        elif char.isdigit():
            has_digit = True

        else:
            has_special = True

    score = sum([
        has_upper,
        has_lower,
        has_digit,
        has_special
    ])

    if score == 4:
        strength = "STRONG"

    elif score >= 2:
        strength = "MEDIUM"

    else:
        strength = "WEAK"

    print(f"\nPassword Strength: {strength}")

    if strength == "STRONG":
        print("Password meets the recommended security conditions.")

    elif strength == "MEDIUM":
        print("Password should be improved.")

    else:
        print("Password is weak and should be improved.")

    log_event(f"PASSWORD CHECK - Strength: {strength}")

    return strength


# -------------------- IP AND PORT CHECKER --------------------

def validate_ip(ip):
    """Validate an IPv4 address."""

    try:
        socket.inet_aton(ip)
        return True

    except socket.error:
        return False


def check_ip_port():
    """Check whether a specific TCP port is open or closed."""

    ip = input("\nEnter target IP address: ").strip()

    if not validate_ip(ip):
        print("Invalid IP address.")
        return

    port_input = input("Enter port number: ").strip()

    if not port_input.isdigit():
        print("Invalid port. Enter a number between 1 and 65535.")
        return

    port = int(port_input)

    if port < 1 or port > 65535:
        print("Invalid port. Enter a value between 1 and 65535.")
        return

    print(f"\nChecking {ip}:{port}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    try:
        result = sock.connect_ex((ip, port))

        if result == 0:
            status = "OPEN"
            print(f"Port {port}: OPEN")

        else:
            status = "CLOSED"
            print(f"Port {port}: CLOSED")

    except socket.error as error:
        status = "ERROR"
        print(f"Network error: {error}")

    finally:
        sock.close()

    log_event(
        f"PORT CHECK - IP: {ip} - Port: {port} - Status: {status}"
    )

    print("Security event logged.")

    return status


# -------------------- LOG ANALYZER --------------------

def analyze_logs():
    """Analyze security log events."""

    error_count = 0
    warning_count = 0
    failed_login_count = 0
    port_check_count = 0
    password_check_count = 0

    try:
        with open(LOG_FILE, "r") as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

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

    except FileNotFoundError:
        print("Security log file not found.")
        return

    total_events = (
        error_count
        + warning_count
        + failed_login_count
        + port_check_count
        + password_check_count
    )

    print("\n========== SECURITY LOG ANALYSIS ==========")
    print(f"ERROR           : {error_count}")
    print(f"WARNING         : {warning_count}")
    print(f"FAILED LOGIN    : {failed_login_count}")
    print(f"PORT CHECKS     : {port_check_count}")
    print(f"PASSWORD CHECKS : {password_check_count}")
    print("--------------------------------------------")
    print(f"TOTAL EVENTS    : {total_events}")

    if total_events == 0:
        print("Status: No security events detected.")

    else:
        print("Status: Security events detected.")


# -------------------- AUTOMATED PORT MONITOR --------------------

def automated_port_monitor():
    """Automatically scan common TCP ports."""

    ip = input("\nEnter target IP address: ").strip()

    if not validate_ip(ip):
        print("Invalid IP address.")
        return

    ports = [21, 22, 80, 443]

    print("\n========== AUTOMATED PORT MONITOR ==========")
    print(f"Target IP: {ip}")
    print("Scanning ports: 21, 22, 80, 443\n")

    results = []

    for port in ports:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((ip, port))

            if result == 0:
                status = "OPEN"

            else:
                status = "CLOSED"

        except socket.error:
            status = "ERROR"

        finally:
            sock.close()

        results.append((port, status))

        print(f"Port {port}: {status}")

        log_event(
            f"AUTOMATED SCAN - IP: {ip} - Port: {port} - Status: {status}"
        )

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(SCAN_FILE, "a") as file:

        file.write(f"\n[{timestamp}] Automated scan for {ip}\n")

        for port, status in results:
            file.write(f"Port {port}: {status}\n")

    print("\nAutomated scan completed.")
    print("Results saved to scan_results.txt")


# -------------------- INTERNET CONNECTIVITY --------------------

def check_internet():
    """Check internet connectivity using requests."""

    print("\nChecking internet connectivity...")

    try:
        response = requests.get(
            "https://api.ipify.org?format=json",
            timeout=5
        )

        if response.status_code == 200:

            data = response.json()
            public_ip = data.get("ip")

            print("Internet connection: AVAILABLE")
            print(f"Public IP: {public_ip}")

            log_event(
                f"INTERNET CHECK - Connection available - Public IP: {public_ip}"
            )

        else:

            print("Internet connection check failed.")

            log_event(
                "INTERNET CHECK - Connection check failed."
            )

    except requests.RequestException as error:

        print(f"Connection error: {error}")

        log_event(
            f"INTERNET CHECK - Error: {error}"
        )


# -------------------- MAIN MENU --------------------

def show_banner():
    print("\n" + "=" * 55)
    print("          CYBERSHIELD SECURITY MONITOR")
    print("=" * 55)
    print(" Python-Based Cybersecurity Monitoring Toolkit")
    print("=" * 55)


def show_menu():
    print("\n\n\n\n--------------- MAIN MENU ---------------")
    print("1. Password Strength Checker")
    print("2. IP & Port Security Checker")
    print("3. Security Log Analyzer")
    print("4. Automated Port Monitor")
    print("5. View Security Logs")
    print("6. Check Internet Connectivity")
    print("7. Exit")
    print("------------------------------------------")


def main():

    initialize_files()

    show_banner()

    while True:

        show_menu()

        choice = input("Enter your choice (1-7): ").strip()

        if choice == "1":

            check_password_strength()

        elif choice == "2":

            check_ip_port()

        elif choice == "3":

            analyze_logs()

        elif choice == "4":

            automated_port_monitor()

        elif choice == "5":

            view_logs()

        elif choice == "6":

            check_internet()

        elif choice == "7":

            print("\nThank you for using CyberShield Security Monitor.")
            print("Exiting application...")
            break

        else:

            print("\nInvalid choice.")
            print("Please enter a number between 1 and 7.")
            continue


# -------------------- PROGRAM START --------------------

if __name__ == "__main__":
    main()