# hash_input.sh
# Hashes a string, a file, or piped data with any algorithm supported by Python's hashlib.
#
# Usage:
#   source hash_input.sh
#   hash_input <algo> <string_or_file> [...]
#   echo "data" | hash_input [algo]          (algo defaults to sha256)

hash_input() {
    local usage="Usage: hash_input <algo> <string_or_file> [...] or pipe data: <cmd> | hash_input [algo]"

    # Nothing to hash: no arguments after the algorithm and nothing piped in
    if [ "$#" -le 1 ] && [ -t 0 ]; then
        echo "$usage"
        return 1
    fi

    local algo="${1:-sha256}"
    [ "$#" -gt 0 ] && shift

    # The script is passed with -c (not a heredoc) so stdin stays free for piped data.
    # With arguments, each one is hashed; with none, stdin is hashed.
    python3 -c '
import hashlib, os, sys

def new_hash(algo):
    try:
        return hashlib.new(algo)
    except (ValueError, TypeError):
        sys.stderr.write(f"Algorithm not supported: {algo}\n")
        sys.exit(2)

def hexdigest(h):
    # shake algorithms have no fixed length, so use the standard 256/512-bit output
    if h.name.startswith("shake_"):
        return h.hexdigest(64 if h.name == "shake_256" else 32)
    return h.hexdigest()

algo, targets = sys.argv[1], sys.argv[2:]

if not targets:
    h = new_hash(algo)
    h.update(sys.stdin.buffer.read())
    print(hexdigest(h))

for t in targets:
    h = new_hash(algo)
    if os.path.isfile(t):
        with open(t, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    else:
        h.update(t.encode())
    print(hexdigest(h))
' "$algo" "$@"
}
