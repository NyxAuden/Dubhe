#!/bin/bash
# 停机后端口释放观测。可选诊断，不作为验收门槛。
# 前提：运行用户对当前目录可写（要写配置与结果文件）。
# 计时由同一 Python 进程在发信号前取单调时间，避免「先 kill 再取时」的偏差。
set -u
cd "$(dirname "$0")" || exit 1
PORT=31099
OUT=port-release.txt

[ -x ./dubhe ] || { echo "缺少 ./dubhe"; exit 1; }
[ -w . ] || { echo "当前目录不可写，无法写配置"; exit 1; }

cat > port.json <<'JSON' || exit 1
{"version":1,"inbounds":[{"type":"socks5","tag":"in","listen":"127.0.0.1:31099"}],
 "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"}}
JSON

# dubhe 由本脚本启动，Python 负责等它就绪、计时、发信号、探测。
./dubhe run -c port.json >port-server.log 2>&1 &
pid=$!

python3 - "$pid" "$PORT" "$OUT" <<'PY'
import socket, sys, time, os, signal
pid, port, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]

def listening():
    s = socket.socket()
    s.settimeout(0.2)
    try:
        s.connect(("127.0.0.1", port)); return True
    except OSError:
        return False
    finally:
        s.close()

# 必须确认被测进程真的在监听，否则下面的探测没有意义。
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    if listening():
        break
    if not os.path.exists("/proc/%d" % pid):
        open(out, "w").write("server-died-before-listen\n")
        sys.exit(1)
    time.sleep(0.05)
else:
    open(out, "w").write("server-never-listened\n")
    sys.exit(1)

start = time.monotonic()          # 发信号前取时
os.kill(pid, signal.SIGTERM)

deadline = start + 5.0
while time.monotonic() < deadline:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        open(out, "w").write("free after %.0f ms\n" % ((time.monotonic() - start) * 1000))
        s.close()
        sys.exit(0)
    except OSError:
        s.close()
        time.sleep(0.01)

open(out, "w").write("still-busy after %.0f ms\n" % ((time.monotonic() - start) * 1000))
sys.exit(1)
PY

rc=$?
wait "$pid" 2>/dev/null
cat "$OUT"

# 逐次运行追加，便于累计观察而不覆盖。
if [ "$rc" = 0 ]; then
    printf "%s  %s\n" "$(date -u +%FT%TZ)" "$(cat "$OUT")" >> port-release-samples.txt
fi
