#!/bin/sh
# Start mod-host against a dummy JACK server and check that it answers
# commands on its socket with a successful response.
set -eu

port=5555
jackd --no-realtime -d dummy -r 48000 -p 256 >jackd.log 2>&1 &
jack_pid=$!
trap 'kill "$host_pid" "$jack_pid" 2>/dev/null || true' EXIT
host_pid=

# no jack client tools are needed: give the server a moment, then check it lives
sleep 2
kill -0 "$jack_pid" || { echo "jackd did not start"; cat jackd.log; exit 1; }

./mod-host -n -p "$port" >mod-host.log 2>&1 &
host_pid=$!

python3 - "$port" <<'PY'
import socket, sys, time

port = int(sys.argv[1])
deadline = time.time() + 15
while True:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        break
    except OSError:
        if time.time() > deadline:
            sys.exit("mod-host did not open its socket")
        time.sleep(0.2)

def ask(cmd):
    s.sendall(cmd.encode() + b"\0")
    buf = b""
    while not buf.endswith(b"\0"):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.rstrip(b"\0").decode()

for cmd in ("cpu_load",):
    reply = ask(cmd)
    print(f"{cmd!r} -> {reply!r}")
    if not reply.startswith("resp 0"):
        sys.exit(f"{cmd}: expected 'resp 0', got {reply!r}")
s.close()
PY
kill -0 "$host_pid" || { echo "mod-host exited"; cat mod-host.log; exit 1; }
echo "smoke test passed"
