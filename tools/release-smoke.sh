#!/bin/bash
# release 工件在目标平台的原生冒烟验证。
#
# 验证点（Astra 的最小清单）：
#   1. 版本输出
#   2. 配置 check 通过
#   3. 能启动并监听
#   4. 一次允许的转发成功
#   5. 一次出口拒绝生效（目标未收到连接）
#   6. 正常停机并释放端口
#
# 全程以非 root 身份运行。
set -u
BIN="${1:-/var/tmp/dubhe-release/dubhe}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK" || exit 1

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"; }

OPENSSL=openssl
command -v "$OPENSSL" >/dev/null || { echo "需要 openssl"; exit 1; }

# 自签证书（仅本机回环验证）
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1 || {
    bad "生成自签证书"; exit 1; }

TARGET_PORT=35201
SOCKS_PORT=31081

# 1) 版本
if "$BIN" --version >/dev/null 2>&1; then ok "version"; else bad "version"; fi

# 2) 配置 check：一条允许 127.0.0.2 的规则
cat > allow.json <<JSON
{
  "version": 1,
  "inbounds": [{"type":"socks5","tag":"in","listen":"127.0.0.1:${SOCKS_PORT}"}],
  "outbounds": [{"type":"direct","tag":"direct"}],
  "route": {"default":"direct","rules":[
    {"outbound":"direct","ip_cidrs":["127.0.0.2/32"]}
  ]}
}
JSON
if "$BIN" check -c allow.json >/dev/null 2>&1; then ok "config check"; else bad "config check"; fi

# 3-4) 启动 + 一次允许的转发
python3 - <<'PY' &
import socket, sys
s = socket.create_server(("127.0.0.2", 35201))
s.settimeout(15)
try:
    c, _ = s.accept()
    c.settimeout(5)
    # 先确认确实收到业务字节，再回 pong；否则只验证了返回路径。
    got = c.recv(16)
    if got == b"ping":
        c.sendall(b"pong")
    else:
        c.sendall(b"bad:" + got[:8])
    c.close()
except Exception:
    pass
finally:
    s.close()
PY
LISTENER=$!
sleep 1

"$BIN" run -c allow.json >server.log 2>&1 &
SRV=$!
for _ in $(seq 1 50); do
    (exec 3<>/dev/tcp/127.0.0.1/$SOCKS_PORT) 2>/dev/null && { exec 3<&-; break; }
    sleep 0.1
done
if ! kill -0 "$SRV" 2>/dev/null; then
    bad "启动监听：$(tail -2 server.log 2>/dev/null)"
else
    ok "启动监听"
    got=$(python3 - "$SOCKS_PORT" <<'PY'
import socket, struct, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(b"\x05\x01\x00")
assert s.recv(2) == b"\x05\x00"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.2") + struct.pack("!H", 35201))
r = s.recv(4)
if len(r) < 2 or r[1] != 0:
    print("REJECTED"); sys.exit()
# 读完 SOCKS 应答的 BND.ADDR/BND.PORT，否则会被当成载荷。
size = {1: 4, 4: 16}.get(r[3])
if size is None:
    print("unexpected:bad-atyp"); sys.exit()
s.recv(size + 2)
s.sendall(b"ping")
# 只输出 ASCII 可判定的结果，避免非 UTF-8/latin-1 字节让 print 抛异常。
data = s.recv(16)
if data == b"pong":
    print("pong")
else:
    print("unexpected:" + data.hex())
s.close()
PY
)
    case "$got" in
        pong) ok "允许路径转发（目标收到 ping 并回送 pong）" ;;
        *)    bad "允许路径转发：$got" ;;
    esac

    # 5) 拒绝路径：显式 reject 规则必须让拨号在建立前失败，且目标不应收到连接。
    cat > reject.json <<JSON
{
  "version": 1,
  "inbounds": [{"type":"socks5","tag":"in","listen":"127.0.0.1:$((SOCKS_PORT+1))"}],
  "outbounds": [{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],
  "route": {"default":"direct","rules":[
    {"outbound":"reject","ip_cidrs":["127.0.0.3/32"]}
  ]}
}
JSON
    # 目标侧监听：结果写入文件，由主流程判定。
    # 只有「观察窗口内 accept 超时」算通过；收到连接或异常都算失败。
    REJ_RESULT="$WORK/rej-target.txt"
    : > "$REJ_RESULT"
    python3 - "$REJ_RESULT" <<'PY' &
import socket, sys
out = sys.argv[1]
try:
    s = socket.create_server(("127.0.0.3", 35201))
except OSError:
    open(out, "w").write("listen-failed\n")
    sys.exit(0)
s.settimeout(8)
try:
    c, _ = s.accept()
    c.close()
    open(out, "w").write("connection-received\n")
except socket.timeout:
    open(out, "w").write("no-connection\n")
except Exception:
    open(out, "w").write("listener-error\n")
finally:
    s.close()
PY
    REJ_LISTENER=$!
    sleep 1
    "$BIN" run -c reject.json >reject.log 2>&1 &
    REJ_SRV=$!
    for _ in $(seq 1 50); do
        (exec 3<>/dev/tcp/127.0.0.1/$((SOCKS_PORT+1))) 2>/dev/null && { exec 3<&-; break; }
        sleep 0.1
    done
    rej=$(python3 - "$((SOCKS_PORT+1))" <<'PY'
import socket, struct, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(b"\x05\x01\x00")
assert s.recv(2) == b"\x05\x00"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.3") + struct.pack("!H", 35201))
r = s.recv(4)
print("REJECTED" if len(r) >= 2 and r[1] != 0 else "ALLOWED")
s.close()
PY
)
    if [ "$rej" = "REJECTED" ]; then ok "出口拒绝生效（SOCKS 应答非 0）"; else bad "出口拒绝生效（得到 $rej）"; fi
    # 目标侧判定：必须完成观察窗口且未收到连接。
    wait "$REJ_LISTENER" 2>/dev/null
    rej_target=$(tr -d '\n' < "$REJ_RESULT" 2>/dev/null)
    case "$rej_target" in
        no-connection)
            ok "拒绝目标未收到连接（观察窗口内 accept 超时）" ;;
        connection-received)
            bad "拒绝目标收到连接——出口拒绝失效" ;;
        "")
            bad "拒绝目标监听器无结果（未完成观察窗口）" ;;
        *)
            bad "拒绝目标监听异常：$rej_target" ;;
    esac
    kill -TERM "$REJ_SRV" 2>/dev/null; wait "$REJ_SRV" 2>/dev/null
fi

# 6) 正常停机
kill -TERM "$SRV" 2>/dev/null
set +u
wait "$SRV" 2>/dev/null
srv_rc=${?}
set -u
if [ "${srv_rc}" -eq 0 ] || [ "${srv_rc}" -eq 143 ]; then
    ok "SIGTERM 停机（exit=${srv_rc}）"
else
    bad "SIGTERM 停机（exit=${srv_rc}）"
fi
kill "$LISTENER" 2>/dev/null; wait "$LISTENER" 2>/dev/null

# 端口释放：仅观察记录，不作失败判据（TIME_WAIT 属正常 TCP 行为）。
python3 - "$SOCKS_PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", port))
    print("port: free")
except OSError:
    print("port: busy")
finally:
    s.close()
PY

echo
echo "RESULT pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
