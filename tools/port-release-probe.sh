#!/bin/bash
# 停机后端口释放的时序观察。以非 root 身份运行，工作目录须可写。
# 时间用单调时钟实测，不按轮次乘固定间隔估算。
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
start=$(python3 -c 'import time; print(time.monotonic())')
wait "$pid" 2>/dev/null
python3 - "$PORT" "$start" <<'PY'
import socket, sys, time
port, start = int(sys.argv[1]), float(sys.argv[2])
deadline = start + 5.0
while time.monotonic() < deadline:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        print("free after %.0f ms" % ((time.monotonic() - start) * 1000))
        s.close()
        break
    except OSError:
        s.close()
        time.sleep(0.01)
else:
    print("still busy after %.0f ms" % ((time.monotonic() - start) * 1000))
PY
