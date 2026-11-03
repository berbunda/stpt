#!/bin/bash
# A real change of the Client's address (RD008, PROTOCOL.md 15.12), which `cargo test`
# cannot do: Server and Client run in separate network namespaces joined by a veth pair.
# It touches neither the firewall nor a Server already running.
#
#   sudo bash tests/network_change.sh target/debug/stpt
#
# Exit code 0: the output continued after every change, soon after it.
BIN=$(readlink -f "$1")
D=$(mktemp -d /tmp/stpt-network.XXXXXX)
FAILED=0
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null; done
    sleep 1
    ip netns del stptc 2>/dev/null
    ip netns del stpts 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT
mkdir -p "$D/keys" "$D/home/stpt"
cp "$BIN" "$D/stpt"
BIN=$D/stpt
chmod 755 "$D" "$D/keys"

ip netns add stpts
ip netns add stptc
ip link add vs type veth peer name vc
ip link set vs netns stpts
ip link set vc netns stptc
ip -n stpts addr add 10.77.0.1/24 dev vs
ip -n stpts link set vs up
ip -n stpts link set lo up
ip -n stptc addr add 10.77.0.2/24 dev vc
ip -n stptc link set vc up
ip -n stptc link set lo up

openssl genpkey -algorithm ed25519 -out "$D/home/stpt/id_ed25519" 2>/dev/null
chmod 600 "$D/home/stpt/id_ed25519"
openssl pkey -in "$D/home/stpt/id_ed25519" -pubout | sed -n 2p > "$D/keys/root"
chmod 644 "$D/keys/root"
cat > "$D/server.toml" <<EOF
listen = "10.77.0.1:843"
identity_key = "$D/server_key"
authorized_keys = "$D/keys"
EOF
FP=$("$BIN" server --fingerprint --config "$D/server.toml" 2>/dev/null)
ip netns exec stpts "$BIN" server --config "$D/server.toml" > "$D/server.log" 2>&1 &
PIDS+=($!)
sleep 1

exec_in_client() { # OUTPUT COMMAND
    ip netns exec stptc env HOME="$D/home" XDG_CONFIG_HOME="$D/home" "$BIN" -v exec \
        root@10.77.0.1 --fingerprint "$FP" "$2" > "$1" 2> "$1.err" < /dev/null &
}
move_to() { # NEW OLD
    ip -n stptc addr add "10.77.0.$1/24" dev vc
    ip -n stptc addr del "10.77.0.$2/24" dev vc
}
now() { date +%s.%N | cut -c1-14; }
# Waits for a line in a file; prints the seconds it took, fails after 30 s.
arrives() { # FILE TEXT
    local start
    start=$(now)
    for _ in $(seq 1 300); do
        if grep -q "$2" "$1"; then
            echo "$(now) - $start" | bc
            return 0
        fi
        sleep 0.1
    done
    return 1
}
# The check of one scenario.
report() { # NAME SECONDS LIMIT
    if [ -n "$2" ] && [ "$(echo "$2 <= $3" | bc)" = 1 ]; then
        echo "ok    $1: $2 s (limit $3 s)"
    else
        echo "FAIL  $1: ${2:-nothing arrived} (limit $3 s)"
        FAILED=1
    fi
}

TICKS='i=0; while :; do echo tick $i; i=$((i+1)); sleep 0.2; done'

# Output is flowing when the address changes.
exec_in_client "$D/a" "$TICKS"
A=$!
PIDS+=($A)
sleep 2
move_to 3 2
sleep 0.2
N=$(($(wc -l < "$D/a") + 2))
report "output flowing, new address" "$(arrives "$D/a" "^tick $N\$")" 4
kill -HUP $A 2>/dev/null
wait $A 2>/dev/null

# Silence when the address changes: nothing tells the Server until the Client speaks.
exec_in_client "$D/b" 'sleep 3; echo woke; sleep 60'
B=$!
PIDS+=($B)
sleep 1
move_to 4 3
report "idle, new address, program prints 2 s later" "$(arrives "$D/b" '^woke$')" 5
kill -HUP $B 2>/dev/null
wait $B 2>/dev/null

# The network goes away for a while and comes back with another address.
exec_in_client "$D/c" "$TICKS"
C=$!
PIDS+=($C)
sleep 2
ip -n stptc link set vc down
sleep 3
move_to 5 4
ip -n stptc link set vc up
ip -n stptc route replace 10.77.0.0/24 dev vc 2>/dev/null
sleep 0.2
N=$(($(wc -l < "$D/c") + 2))
report "3 s without a network, new address" "$(arrives "$D/c" "^tick $N\$")" 4
if ! kill -0 $C 2>/dev/null; then
    echo "FAIL  the Client ended: $(cat "$D/c.err")"
    FAILED=1
fi
kill -HUP $C 2>/dev/null
wait $C 2>/dev/null

grep -h "Connection migrated" "$D"/*.err | sed -E 's/^[0-9-]+T([0-9:.]+)Z +/\1 /' | cut -c1-110
grep -c "Connection established" "$D/server.log" | sed 's/$/ Connections, expected 3: no reconnects/'
[ "$(grep -c 'Connection established' "$D/server.log")" = 3 ] || FAILED=1
exit $FAILED
