#!/bin/bash
# 在 VPS 上运行一批测试并回收结果。
# 用法: run-batch.sh <tag>
# 前置：VPS 上 /var/tmp/dubhe-tests 已解压该批 + 主程序 dubhe。
set -u
tag="$1"
ssh=(/usr/bin/ssh -F /dev/null -S /tmp/dubhe-ssh.jpXcGm/c -o BatchMode=yes -o ProxyCommand=false root@151.242.11.157)

"${ssh[@]}" "cd /var/tmp/dubhe-tests || exit 1; export DUBHE_TEST_BINARY=/var/tmp/dubhe-tests/dubhe; for t in *-$tag-*; do
  [ -x \"\$t\" ] || continue
  n=\${t%%-*}
  printf '%s ' \"\$n\"
  ./\$t --test-threads=1 2>&1 | grep -E '^test result:' | tail -1
done" 2>&1
