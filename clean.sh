#!/usr/bin/env bash
# ============================================================================
# clean.sh —— 清理 GhostLock PC 驱动的 device 侧残留
#
#   分两类，别搞混：
#    A. 内存态（kernelsu late-load / vrpatch 对 vr.ko 的补丁 / SELinux 状态与
#       policy 补丁 / 临时 cred）—— **reboot 就没了**，不需要删任何文件。
#    B. 磁盘态（payload、日志、测试目录、KSU 用户态、管理器 APK）—— 要删。
#
#   正确顺序：趁 root 还在先删文件（root 属主的日志 shell 删不掉），
#             再 reboot 把内核态清掉（root 随之消失）。
#
# 用法（默认只列出要删什么，不动手）：
#   ./clean.sh                        # dry-run：列出清单 + 体积
#   ./clean.sh --yes                  # 真删：工作目录 + 测试目录 + 残留进程
#   ./clean.sh --yes --ksu            # 再删 KSU 用户态（/data/adb/ksud、/data/adb/ksu/*，约 91 MB）
#   ./clean.sh --yes --uninstall      # 再卸载管理器 APK com.resukisu.resukisu
#   ./clean.sh --yes --all --reboot   # 全清 + 重启（推荐：一步回到干净系统）
#
#   --all = --ksu --uninstall
#   --reboot 只在 --yes 时生效
# ============================================================================
set -u

D="/data/local/tmp/ghostlock-app"
TEST_DIRS="/data/local/tmp/gl-selftest /data/local/tmp/gl-pack-test /data/local/tmp/gl-mac-test"
KSU_PKG="com.resukisu.resukisu"

ADB="${ADB:-}"
if [ -z "$ADB" ]; then
  if command -v adb >/dev/null 2>&1; then
    ADB=adb
  else
    for c in "$HOME/Library/Android/sdk/platform-tools/adb" \
             "/opt/homebrew/bin/adb" "/usr/local/bin/adb"; do
      [ -x "$c" ] && { ADB="$c"; break; }
    done
  fi
fi
[ -n "$ADB" ] || { echo "[!] 找不到 adb"; exit 3; }

DO=0; KSU=0; UNINSTALL=0; REBOOT=0
for a in "$@"; do
  case "$a" in
    --yes|-y)     DO=1 ;;
    --ksu)        KSU=1 ;;
    --uninstall)  UNINSTALL=1 ;;
    --all)        KSU=1; UNINSTALL=1 ;;
    --reboot)     REBOOT=1 ;;
    -h|--help)    sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)            echo "[!] 未知参数: $a"; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
sho() { "$ADB" shell "$1" 2>/dev/null | tr -d '\r'; }

have_root() { [ "$(sho "su -c id -u" | tr -d ' ')" = "0" ]; }
as_root() {  # as_root '<cmd>'  —— 有 root 走 su，没有就直接跑
  if [ "$ROOT" = 1 ]; then
    "$ADB" shell "su -c '$1'" 2>/dev/null | tr -d '\r'
  else
    "$ADB" shell "$1" 2>/dev/null | tr -d '\r'
  fi
}
exists() { [ "$(sho "test -e '$1' && echo y")" = "y" ]; }
human()  { sho "du -sh '$1' 2>/dev/null | cut -f1" | head -1; }

if ! "$ADB" devices 2>/dev/null | grep -q "device"; then
  say "[!] 没看到 adb 设备"; exit 3
fi

ROOT=0; have_root && ROOT=1

say "=============================================================="
say " 清理清单（$([ "$DO" = 1 ] && echo '执行模式 --yes' || echo 'DRY-RUN，只列不动手')）"
say "=============================================================="
say ""
say "[内存态] reboot 即消失，不删文件："
say "  kernelsu 模块      : $(sho 'grep -c kernelsu /proc/modules') （1=仍在）"
say "  vr 模块            : $(sho "grep -c '^vr ' /proc/modules") （1=仍在）"
say "  SELinux            : $(sho getenforce)"
say ""
say "[磁盘态] 要删的："

NUM=0
PLAN=""
plan() {  # plan <path> <label>
  NUM=$((NUM + 1))
  if exists "$1"; then
    say "  $NUM) $1   $([ -n "${2:-}" ] && echo "($2) ")体积=$(human "$1")"
    PLAN="$PLAN $1"
  else
    say "  $NUM) $1   (不存在，跳过)"
  fi
}

plan "$D"                                       "payload+日志+root脚本"
for t in $TEST_DIRS; do plan "$t" "测试残留"; done
if [ "$KSU" = 1 ]; then
  plan "/data/adb/ksud"                          "KSU 用户态"
  plan "/data/adb/ksu"                           "KSU 用户态目录"
else
  say "  (KSU 用户态 /data/adb/ksud + /data/adb/ksu 未选：加 --ksu 才删，约 91 MB)"
fi
if [ "$UNINSTALL" = 1 ]; then
  say "  * 卸载管理器：$KSU_PKG"
fi
say ""
say "[残留进程] $(sho 'ps -A 2>/dev/null | grep -c libghostlock.so') 个 libghostlock.so"
[ "$REBOOT" = 1 ] && say "[收尾] 删除后执行 reboot（清内核态，root 同时消失）"

say ""
if [ "$DO" = 0 ]; then
  say "以上只是清单。确认无误后执行："
  say "  $0 --yes$( [ "$KSU" = 1 ] && echo ' --ksu' )$( [ "$UNINSTALL" = 1 ] && echo ' --uninstall' )$( [ "$REBOOT" = 1 ] && echo ' --reboot' )"
  exit 0
fi

say "=============================================================="
say " 开始执行（root=$([ "$ROOT" = 1 ] && echo 有 || echo 无)）"
say "=============================================================="

# 1) 先收掉我们自己的残留进程（不碰系统服务）
say "[*] 停止残留的 exploit 进程"
as_root "pkill -f libghostlock.so" >/dev/null 2>&1 || true
as_root "pkill -f ghostlock_root.sh" >/dev/null 2>&1 || true
sleep 1

# 2) 删目录
for p in $PLAN; do
  if exists "$p"; then
    say "[*] 删除 $p"
    as_root "rm -rf '$p'" >/dev/null 2>&1
    if exists "$p"; then
      say "    [!] 删不掉（多半是 root 属主而当前没有 root）；先确保 root 还在再跑一次"
    else
      say "    ok"
    fi
  fi
done

# 3) 卸载管理器
if [ "$UNINSTALL" = 1 ]; then
  say "[*] 卸载 $KSU_PKG"
  "$ADB" uninstall "$KSU_PKG" 2>&1 | tail -1
fi

say ""
say "=============================================================="
say " 清理结果"
say "=============================================================="
say "  工作目录存在? $(exists "$D" && echo 是 || echo 否)"
say "  KSU 用户态?   $(exists /data/adb/ksu && echo 是 || echo 否)"
say "  管理器安装?   $(sho "pm list packages 2>/dev/null | grep -q $KSU_PKG && echo 是 || echo 否")"
say "  kernelsu 模块: $(sho 'grep -c kernelsu /proc/modules') （1=仍在内存里）"
say "  SELinux      : $(sho getenforce)"

if [ "$REBOOT" = 1 ]; then
  say ""
  say "[*] reboot（内核态随之清空，root 消失）"
  "$ADB" reboot >/dev/null 2>&1 || true
  say "done"
else
  say ""
  say "内核态还在内存里。要彻底回到干净系统："
  say "  adb reboot     （或 $0 --yes --all --reboot）"
fi
