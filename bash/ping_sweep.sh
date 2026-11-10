# ping_sweep.sh
# Network helper functions: a small subnet ping sweep, a single-host up/down check,
# and a ROT13 encoder.
#
# Usage:
#   source ping_sweep.sh
#   ping_sweep <subnet_prefix>    e.g. ping_sweep 10.0.0
#   check_host <host>             e.g. check_host 10.0.0.1
#   rot13 <text>                  e.g. rot13 "hello"

ping_sweep() {
    if [ "$#" -ne 1 ]; then
        echo "Usage: ping_sweep <subnet_prefix>"
        echo "Example: ping_sweep 10.0.0"
        return 1
    fi

    subnet="$1"

    echo "Starting ping sweep for $subnet.1 - $subnet.10..."

    for i in {1..10}; do
        ip="$subnet.$i"
        ping -c1 -w1 "$ip" &> /dev/null && echo "[+] $ip alive" &
    done
    wait

    echo "Scan complete."
}

check_host() { ping -c1 "$1" &>/dev/null && echo "$1 is up" || echo "$1 is down"; }

rot13() { echo "$1" | tr 'A-Za-z' 'N-ZA-Mn-za-m'; }
