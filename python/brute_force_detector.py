"""
brute_force_detector.py

Parses an SSH auth log, flags IPs with repeated failed logins inside a short
time window (likely brute-force attempts) and writes incident and summary reports.
"""
from collections import defaultdict
from datetime import datetime, timedelta

LOGFILE = "sample_auth_small.log"


def parse_auth_line(line):
    """
    Parse an auth log line and return (timestamp, ip, event_type).

    Example auth line:
    Mar 10 13:58:01 host1 sshd[1023]: Failed password for invalid user admin from 203.0.113.45 port 52344 ssh2

     - timestamp: parsed from the first 3 tokens (year assumed to be 2025)
     - ip: the token after 'from'
     - event_type: 'failed' if 'Failed password', 'accepted' if 'Accepted password', else 'other'
    """
    parts = line.split()
    # timestamp: first 3 tokens 'Mar 10 13:58:01'
    ts_str = " ".join(parts[0:3])
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        ts = None
    ip = None
    event_type = "other"
    if "Failed password" in line:
        event_type = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"
    if " from " in line:
        try:
            idx = parts.index("from")
            ip = parts[idx + 1]
        except (ValueError, IndexError):
            ip = None
    return ts, ip, event_type


def detect_brute_force(per_ip_timestamps, max_minutes=10, threshold=5):
    """
    Detect IPs with >= threshold failures within a max_minutes window.
    Return a list of incident dicts (ip, count, start_time, end_time, duration_minutes).
    """
    incidents = []
    for ip, timestamps in per_ip_timestamps.items():
        # if fewer than threshold, skip
        if len(timestamps) < threshold:
            continue
        # Use two pointers (sliding window)
        left = 0
        for right in range(len(timestamps)):
            # Move left pointer until window is <= max_minutes
            while timestamps[right] - timestamps[left] > timedelta(minutes=max_minutes):
                left += 1
            window_size = right - left + 1
            # check if current window meets threshold
            if window_size >= threshold:
                # found suspicious activity
                incident = {
                    'ip': ip,
                    'count': window_size,
                    'start_time': timestamps[left],
                    'end_time': timestamps[right],
                    'duration_minutes': (timestamps[right] - timestamps[left]).total_seconds() / 60
                }
                incidents.append(incident)
                # stop after the first incident for this IP to avoid duplicate reports
                break
    return incidents


def save_incidents_to_file(incidents, filename="bruteforce_incidents.txt"):
    with open(filename, 'w') as f:
        f.write("Bruteforce Incidents Report \n")
        f.write("=" * 60 + "\n\n")

        if not incidents:
            f.write("No incidents detected.\n")
            return
        for i, incident in enumerate(incidents, 1):
            f.write(f"Incident {i}:\n")
            f.write(f"IP: {incident['ip']}\n")
            f.write(f"Failed attempts: {incident['count']}\n")
            f.write(f"Time window: {incident['start_time'].strftime('%Y-%m-%d %H:%M:%S')} to {incident['end_time'].strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {incident['duration_minutes']:.1f} minutes\n")
            f.write("-" * 30 + "\n\n")


def create_summary_report(per_ip_timestamps, filename="summary_report.txt"):
    with open(filename, 'w') as f:
        f.write("Summary Report of Failed Login Attempts\n")
        f.write("=" * 60 + "\n\n")

        # total failed attempts per ip
        ip_fail_counts = {ip: len(timestamps) for ip, timestamps in per_ip_timestamps.items()}
        # sort by count descending
        top_offenders = sorted(ip_fail_counts.items(), key=lambda x: x[1], reverse=True)

        f.write("Top Offending IPs by Failed Attempts:\n")
        f.write("-" * 40 + "\n")
        for ip, count in top_offenders:
            f.write(f"IP: {ip}, Failed Attempts: {count}\n")

        f.write(f"\nTotal Unique IPs with Failed Attempts: {len(ip_fail_counts)}\n")
        # TODO: include detected incidents in the summary (would need passing in as an argument)


def plot_attackers_chart(per_ip_timestamps, top_n=10):
    import matplotlib.pyplot as plt
    # calculate total fails per ip
    ip_fail_counts = {ip: len(timestamps) for ip, timestamps in per_ip_timestamps.items()}

    top_ips = sorted(ip_fail_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    if not top_ips:
        print("No failed login attempts to plot.")
        return
    ips = [ip for ip, count in top_ips]
    counts = [count for ip, count in top_ips]

    plt.figure(figsize=(10, 6))
    bars = plt.bar(ips, counts, color='red')
    plt.title(f'Top {top_n} IPs by Failed Login Attempts')
    plt.xlabel('IP Address')
    plt.ylabel('Number of Failed Attempts')

    for bar, count in zip(bars, counts):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1, f'{count}', ha='center', va='bottom')

    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('top_attackers.png')
    plt.show()


if __name__ == "__main__":
    per_ip_timestamps = defaultdict(list)
    with open(LOGFILE) as f:
        for line in f:
            ts, ip, event = parse_auth_line(line)
            if ts and ip and event == "failed":  # checks that ts and ip are not null, and that event == "failed"
                per_ip_timestamps[ip].append(ts)
    # Sort the list of timestamps for each IP
    for ip in per_ip_timestamps:
        per_ip_timestamps[ip].sort()
    incidents = detect_brute_force(per_ip_timestamps)

    print("Suspicious Activities Detected:")
    print("-" * 60)
    for incident in incidents:
        print(f"IP: {incident['ip']}")
        print(f"   Failed attempts: {incident['count']}")
        print(f"   Time window: {incident['start_time'].strftime('%H:%M:%S')} to {incident['end_time'].strftime('%H:%M:%S')}")
        print(f"   Duration:  {incident['duration_minutes']:.1f} minutes")
        print()

    # Write reports to files
    save_incidents_to_file(incidents, filename="bruteforce_incidents.txt")
    create_summary_report(per_ip_timestamps, filename="summary_report.txt")
