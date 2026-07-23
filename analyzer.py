import csv
from collections import Counter
from pathlib import Path


LOG_FILE = Path("sample_logs/authentication.log")
REPORT_FILE = Path("reports/security-report.csv")
SUSPICIOUS_THRESHOLD = 5


def write_csv_report(
    failed_by_ip: Counter[str],
    report_file: Path,
) -> None:
    """Export failed-login findings to a CSV report."""

    report_file.parent.mkdir(parents=True, exist_ok=True)

    with report_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(
            ["ip_address", "failed_attempts", "status"]
        )

        for ip_address, attempts in failed_by_ip.most_common():
            status = (
                "Suspicious"
                if attempts >= SUSPICIOUS_THRESHOLD
                else "Normal"
            )

            writer.writerow([ip_address, attempts, status])


def analyze_log(log_file: Path) -> None:
    """Read an authentication log and display a security summary."""

    total_events = 0
    successful_logins = 0
    failed_logins = 0

    failed_by_ip: Counter[str] = Counter()
    failed_by_user: Counter[str] = Counter()

    try:
        with log_file.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()

                if not line:
                    continue

                parts = line.split()

                if len(parts) != 4:
                    print(
                        f"Skipping malformed line "
                        f"{line_number}: {line}"
                    )
                    continue

                _timestamp, ip_address, username, result = parts
                result = result.upper()

                if result not in {"SUCCESS", "FAILED"}:
                    print(
                        f"Skipping invalid result on line "
                        f"{line_number}: {result}"
                    )
                    continue

                total_events += 1

                if result == "FAILED":
                    failed_logins += 1
                    failed_by_ip[ip_address] += 1
                    failed_by_user[username] += 1
                else:
                    successful_logins += 1

    except FileNotFoundError:
        print(f"Error: log file not found: {log_file}")
        return
    except OSError as error:
        print(f"Error reading log file: {error}")
        return

    print("\nSecurity Log Analysis")
    print("-" * 40)
    print(f"Total events: {total_events}")
    print(f"Failed logins: {failed_logins}")
    print(f"Successful logins: {successful_logins}")

    print("\nSuspicious IP addresses:")

    suspicious_ips = [
        (ip_address, attempts)
        for ip_address, attempts in failed_by_ip.items()
        if attempts >= SUSPICIOUS_THRESHOLD
    ]

    if suspicious_ips:
        for ip_address, attempts in sorted(
            suspicious_ips,
            key=lambda item: item[1],
            reverse=True,
        ):
            print(
                f"- {ip_address}: "
                f"{attempts} failed attempts"
            )
    else:
        print("- No suspicious IP addresses detected.")

    print("\nMost targeted users:")

    if failed_by_user:
        for username, attempts in failed_by_user.most_common():
            print(f"- {username}: {attempts} failed attempts")
    else:
        print("- No failed login attempts detected.")

    write_csv_report(failed_by_ip, REPORT_FILE)

    print(f"\nCSV report created: {REPORT_FILE}")


if __name__ == "__main__":
    analyze_log(LOG_FILE)
