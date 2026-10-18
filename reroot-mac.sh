#!/usr/bin/env bash
# ============================================================================
# reroot-mac.sh —— iQOO Neo9 (PD2338) 一键（重新）root   【macOS 专用版】
#
#   与 reroot.sh 的区别：只依赖 macOS 自带工具（BSD dd / BSD sed / 无 timeout）
#   - 解包用 tail -c | head -c（不用 GNU 的 dd iflag=skip_bytes）
#   - 超时用 timeout / gtimeout / 无超时三种降级
#   - adb 自动探测（Android Studio SDK / Homebrew）
#   - 不用 seq（改成 bash 算术 for 循环）
#   - 兼容 macOS 自带的 bash 3.2
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
CYCLE_WAIT="${CYCLE_WAIT:-600}"   # 等"手机自己重启"的最长秒数

ROUNDS=10
CHECK_ONLY=0
INSPECT=0
DEPLOY_ONLY=0
CHECK_PAYLOAD=0
REDEPLOY=0
FORCE=0

for a in "$@"; do
  case "$a" in
    --no-reboot) : ;;   # 兼容旧参数：现在本来就不主动重启
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

# ---- macOS 兼容层 ----------------------------------------------------------
# timeout：macOS 没有 timeout（GNU coreutils），Homebrew 装的是 gtimeout
TO=""
if command -v timeout  >/dev/null 2>&1; then TO=timeout
elif command -v gtimeout >/dev/null 2>&1; then TO=gtimeout
fi
to() { local s=$1; shift; if [ -n "$TO" ]; then "$TO" "$s" "$@"; else "$@"; fi; }

# adb：不在 PATH 时去 Android Studio / Homebrew 常见位置找
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
[ -n "$ADB" ] || { say "[!] 找不到 adb。装 platform-tools（brew install --cask android-platform-tools）或 Android Studio 后重试。"; exit 3; }

# 剥 ANSI 颜色（BSD sed 不认 \x1b，用真实 ESC 字符）
ESC=$(printf '\033')

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
  for (( i = 0; i < P_N; i++ )); do
    entry "$i"
    if [ "$E_NAME" = "$1" ]; then
      # BSD dd 没有 iflag=skip_bytes；用 tail/head 按字节切，GNU/BSD 都能跑
      tail -c +$(( P_DATA + E_OFF + 1 )) "$PACK" 2>/dev/null | head -c "$E_SIZE" > "$2" || return 1
      [ "$(wc -c < "$2" | tr -d ' ')" = "$E_SIZE" ] || { rm -f "$2"; return 1; }
      return 0
    fi
  done
  return 1
}

do_inspect() {
  read_pack
  say "包：$PACK  ($(wc -c < "$PACK") B, $P_N 个条目)"
  local i
  for (( i = 0; i < P_N; i++ )); do
    entry "$i"
    if [ "$E_NAME" = "release.txt" ]; then
      say "  $(printf '%-18s' "$E_NAME") $(printf '%8s' "$E_SIZE") B   $(dd if="$PACK" bs=1 skip=$(( P_DATA + E_OFF )) count=$E_SIZE 2>/dev/null | tr -d '\n\0')"
    else
      say "  $(printf '%-18s' "$E_NAME") $(printf '%8s' "$E_SIZE") B"
    fi
  done
}

# ---------------------------------------------------------------- adb 小工具
sho() { to 8 "$ADB" shell "$1" 2>/dev/null | tr -d '\r'; }
uptime_s() { sho 'cut -d" " -f1 /proc/uptime' | head -n1; }
dev_size() { sho "wc -c < $D/$1" | tr -d ' '; }

is_root() {
  local u
  u="$(to 6 "$ADB" shell 'su -c id -u' 2>/dev/null | tr -d '\r\n ')"
  [ "$u" = "0" ]
}

show_status() {
  say "当前状态："
  say "  id      : $(sho id)"
  say "  kernelsu: $(sho 'grep -c kernelsu /proc/modules')   （1=已加载）"
  say "  selinux : $(sho getenforce)"
  say "  su      : $(to 6 "$ADB" shell 'su -c id' 2>/dev/null | tr -d '\r')"
}

wait_shell() {
  local i
  for (( i = 1; i <= 750; i++ )); do
    if "$ADB" shell 'echo up' 2>/dev/null | grep -q up; then return 0; fi
    sleep 0.4
  done
  return 1
}

wait_cycle() {   # 等设备自己重启（掉线再回来）；超时返回 1
  local t0 dropped=0
  t0=$(date +%s)
  say "[i] 等设备自己重启（最多 ${CYCLE_WAIT}s；打崩/卡死时手机会自己重启）…"
  while [ $(( $(date +%s) - t0 )) -lt "$CYCLE_WAIT" ]; do
    if ! "$ADB" shell 'echo up' 2>/dev/null | grep -q up; then dropped=1; break; fi
    sleep 3
  done
  if [ "$dropped" = 0 ]; then
    say "[!] ${CYCLE_WAIT}s 内没检测到重启"
    return 1
  fi
  say "[i] 设备掉线，等它回来…"
  wait_shell || return 1
  return 0
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
    extract "$f" "$tmp/$f" || { rm -rf "$tmp"; die "解包 $f 失败（包在但提取出错，检查磁盘/权限）"; }
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
  to 20 "$ADB" shell "mkdir -p $D" >/dev/null 2>&1
  for f in libghostlock.so vrpatch.ko profile.bin glrun.sh; do
    to 90 "$ADB" push "$tmp/$f" "$D/$f" >/dev/null 2>&1 || { rm -rf "$tmp"; die "push $f 失败"; }
  done
  to 20 "$ADB" shell "chmod 755 $D/libghostlock.so $D/glrun.sh; chmod 644 $D/profile.bin $D/vrpatch.ko" >/dev/null 2>&1
  rm -rf "$tmp"
  say "[*] 部署完成（release=$rel）"
}

# ---------------------------------------------------------------- 主流程
[ "$INSPECT" = 1 ] && { do_inspect; exit 0; }

if ! "$ADB" devices 2>/dev/null | grep -q "device"; then
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

say "[i] 最多 $ROUNDS 轮；脚本不会主动重启设备（卡死/打崩时手机会自己重启）"

WIN=0
for (( r = 1; r <= ROUNDS; r++ )); do
  say ""
  say "================ 第 $r/$ROUNDS 轮 ================"

  if ! wait_shell; then
    say "[!] 300 秒内没等到 adb shell，再来一轮"
    continue
  fi

  up="$(uptime_s)"; upi="${up%%.*}"
  if [ -n "$upi" ] && [ "$upi" -gt "$WINDOW" ] 2>/dev/null; then
    say "[i] 当前 uptime=${up}s，已经过了窗口（12~45 秒才容易中）"
    say "    脚本不主动重启；等手机自己重启（打崩会重启），或你现在手动重启"
    if wait_cycle; then say "[i] 设备已重启，继续"; continue; else
      say "[!] 等不到重启，先退出；重启后再跑本脚本"; break
    fi
  fi
  say "[i] 拿到 shell：uptime=${up}s（越早越好）"

  DROPPED=0
  for (( n = 1; n <= PER_BOOT; n++ )); do
    up="$(uptime_s)"; upi="${up%%.*}"
    if [ -n "$upi" ] && [ "$upi" -gt "$WINDOW" ] 2>/dev/null; then
      say "[i] uptime=${up}s 超出窗口 ${WINDOW}s，本轮结束"
      break
    fi
    say "---- 第 $r 轮 / 第 $n 次（uptime=${up}s）----"

    ts="$(date +%s)-$r-$n"
    to 25 "$ADB" shell "cd $D && GL_RUN_ID=$ts setsid sh $D/glrun.sh </dev/null >/dev/null 2>&1 & echo go" >/dev/null 2>&1

    end=$(( $(date +%s) + TIMEOUT ))
    handoff=0
    klog=""
    while [ "$(date +%s)" -lt "$end" ]; do
      sleep 0.7
      if ! "$ADB" shell 'echo up' 2>/dev/null | grep -q up; then
        DROPPED=1
        say "[!] 设备掉线（panic/重启）——正常失败路径"
        break
      fi
      klog="$("$ADB" shell "cat $D/ksu-$ts.log 2>/dev/null" 2>/dev/null | tr -d '\r')"
      case "$klog" in *"KernelSU module loaded"*) WIN=1 ;; esac
      [ "$WIN" = 1 ] && break
      case "$klog" in
        *"fixup failed"*|*"KernelSU module not loaded"*|*"ksud missing"*) break ;;
      esac
      # root 脚本一旦启动：绝对不要再发新的 exploit（会把它打崩），延长等待直到它跑完
      if printf '%s' "$klog" | grep -q "root script start"; then
        if [ "$handoff" = 0 ]; then
          handoff=1
          say "    [i] root 脚本已启动（uid0），等它做完 policy/vrpatch/late-load，不再发射"
          end=$(( $(date +%s) + 120 ))
        fi
        continue
      fi
      if [ "$(sho "test -f $D/native-$ts.rc && echo y")" = "y" ]; then break; fi
    done
    [ "$handoff" = 1 ] && { [ "$WIN" = 1 ] || say "    [!] root 脚本起来了但没等到 KernelSU loaded"; break; }

    [ "$WIN" = 1 ] && break
    [ "$DROPPED" = 1 ] && break
    say "    native: $("$ADB" shell "tail -n 3 $D/native-$ts.log 2>/dev/null" 2>/dev/null | tr -d '\r' | sed "s/${ESC}\[[0-9;]*m//g" | tr '\n' ' ' | cut -c1-150)"
    [ -n "$klog" ] && say "    root脚本: $(printf '%s' "$klog" | tail -n 2 | tr '\n' ' ' | cut -c1-150)"
  done

  [ "$WIN" = 1 ] && break
  if [ "$DROPPED" = 1 ]; then
    say "[i] 等设备回来…"
    wait_shell || { say "[!] 设备没回来，退出"; break; }
    continue
  fi
  say "[i] 本轮没中。等下一次重启（手机自己重启，或你手动重启）…"
  if wait_cycle; then continue; else break; fi
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
