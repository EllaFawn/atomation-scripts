"""
failed_login_counter.py

Counts failed SSH password attempts per IP address in an auth log,
prints the top 5 offenders and writes all counts to failed_counts.txt.
"""
import time
from collections import defaultdict

LOGFILE = "sample_auth_small.log"


def extract_ip(line):
    """
    Extracts the IP address from a log line using token-based extraction.
    Looks for the token 'from' and returns the next token as the IP address.
    Returns None if not found.
    """
    if " from " in line:
        parts = line.split()
        try:
            anchor = parts.index("from")
            ip = parts[anchor + 1]
            return ip.strip()
        except (ValueError, IndexError):
            return None
    return None


def main():
    start = time.time()
    failed_counts = defaultdict(int)
    lines_read = 0
    with open(LOGFILE, "r") as f:
        for line in f:
            lines_read += 1
            if "Failed password" in line:
                ip = extract_ip(line)
                if ip:
                    failed_counts[ip] += 1

    # Top 5 IPs by failed attempts
    top5 = sorted(failed_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    print("Top 5 IPs by failed attempts:")
    for i, (ip, count) in enumerate(top5, 1):
        print(f"{i}. {ip} — {count}")

    # Write all counts to file
    with open("failed_counts.txt", "w") as out:
        out.write("ip,failed_count\n")
        for ip, count in failed_counts.items():
            out.write(f"{ip},{count}\n")

    elapsed = time.time() - start
    print(f"Lines read: {lines_read}")
    print(f"Unique IPs with failed attempts: {len(failed_counts)}")
    print(f"Elapsed time: {elapsed:.3f} seconds")


if __name__ == "__main__":
    main()
