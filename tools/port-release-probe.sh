#!/bin/bash
# 停机后端口释放的时序观察。以非 root 身份运行，工作目录须可写。
set -u
cd "$(dirname "$0")" || exit 1
PORT=31099
cat > port.json <<'JSON'
{"version":1,"inbounds":[{"type":"socks5","tag":"in","listen":"127.0.0.1:31099"}],
 "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"}}
JSON
./dubhe run -c port.json >/dev/null 2>&1 &
pid=$!
sleep 2
kill -TERM "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
for i in $(seq 1 15); do
  python3 - "$PORT" "$i" <<'PY'
import socket, sys
port, tick = int(sys.argv[1]), int(sys.argv[2])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", port))
    print(f"free after {tick*100} ms")
except OSError:
    print(f"busy at {tick*100} ms")
finally:
    s.close()
PY
  sleep 0.1
done
