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

    local subnet="$1"

    # 1 second reply timeout: -W is seconds on Linux but milliseconds on macOS, which uses -t instead
    local timeout_flag="-W"
    [ "$(uname)" = "Darwin" ] && timeout_flag="-t"

    echo "Starting ping sweep for $subnet.1 - $subnet.10..."

    # The subshell stops the shell printing job numbers for every background ping
    (
        for i in {1..10}; do
            ping -c1 "$timeout_flag" 1 "$subnet.$i" &> /dev/null && echo "[+] $subnet.$i alive" &
        done
        wait
    )

    echo "Scan complete."
}

check_host() {
    local timeout_flag="-W"
    [ "$(uname)" = "Darwin" ] && timeout_flag="-t"
    ping -c1 "$timeout_flag" 1 "$1" &> /dev/null && echo "$1 is up" || echo "$1 is down"
}

rot13() { printf '%s\n' "$*" | tr 'A-Za-z' 'N-ZA-Mn-za-m'; }
