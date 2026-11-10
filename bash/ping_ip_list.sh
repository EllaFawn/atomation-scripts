# ping_ip_list.sh
# Pings every IP address found in a file and saves the live hosts to alive_hosts.txt.
#
# Usage:
#   source ping_ip_list.sh
#   ping_ip_list <filename>

ping_ip_list() {
    if [ "$#" -ne 1 ]; then
        echo "Usage: ping_ip_list <filename>"
        echo "Example: ping_ip_list ips.txt"
        return 1
    fi

    local filename="$1"
    local output_file="alive_hosts.txt"

    if [ ! -f "$filename" ]; then
        echo "Error: File '$filename' not found."
        return 1
    fi

    # 1 second reply timeout: -W is seconds on Linux but milliseconds on macOS, which uses -t instead
    local timeout_flag="-W"
    [ "$(uname)" = "Darwin" ] && timeout_flag="-t"

    local temp_file=$(mktemp)

    # The subshell stops the shell printing job numbers for every background ping.
    # `wait` sits inside the braces so it waits for the pings started by the loop.
    (
        grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$filename" | sort -u | {
            while read -r ip; do
                ping -c1 "$timeout_flag" 1 "$ip" &> /dev/null && echo "$ip is alive" >> "$temp_file" &
            done
            wait
        }
    )

    mv "$temp_file" "$output_file"

    echo "Scan complete. Live hosts saved to $output_file."
}
