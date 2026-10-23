#!/usr/bin/env bash
# ============================================================================
# reroot.sh —— iQOO Neo9 (PD2338) 一键临时 root（Linux/WSL）
#
#   同目录需要两个文件：
#     reroot.sh        本脚本（纯 bash + adb）
#     ghostlock.bin    payload：libghostlock.so + vrpatch.ko + profile.bin
#
#   原理见 README；脚本只负责：等开机窗口 → 发射 → 命中即停。
#   成功判据 = root 日志出现 "KernelSU module loaded"。
#   脚本不会主动重启手机（失败时手机会自己重启）。
#
#   用法：
#     ./reroot.sh                 # 最多 10 轮
#     ./reroot.sh 20              # 最多 20 轮
#     ./reroot.sh --check         # 只看状态
#     ./reroot.sh --inspect       # 看 payload 包内容
#     ./reroot.sh --deploy        # 只部署 payload
#     ./reroot.sh --check-payload # 只看设备上的 payload 是否就绪
#     ./reroot.sh --redeploy      # 强制重推 payload
#     ./reroot.sh --force         # release 不匹配也打（可能 panic，慎用）
#     ./reroot.sh --ko 1          # 启动时选本目录第 1 个 .ko（late-load 时先加载它）
#     ./reroot.sh --ko 1 --clean-after   # 成功后自动清理本次残留（保留 user.ko / wrapper）
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
KO_SEL=""
KO_FILE=""
CLEAN_AFTER=0

while [ $# -gt 0 ]; do
  case "$1" in
    --no-reboot) : ;;   # 兼容旧参数：现在本来就不主动重启
    --check)     CHECK_ONLY=1 ;;
    --inspect)   INSPECT=1 ;;
    --redeploy)  REDEPLOY=1 ;;
    --deploy)    DEPLOY_ONLY=1 ;;
    --check-payload) CHECK_PAYLOAD=1 ;;
    --force)     FORCE=1 ;;
    --ko)        KO_SEL="${2:-}"; [ -n "$KO_SEL" ] && shift ;;
    --no-ko)     KO_SEL=none ;;
    --clean-after) CLEAN_AFTER=1 ;;
    --pack)      shift; PACK="${1:-$PACK}" ;;
    *.bin)       PACK="$1" ;;
    ''|*[!0-9]*) ;;
    *)           ROUNDS="$1" ;;
  esac
  shift
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

wait_cycle() {   # 等设备自己重启（掉线再回来）；超时返回 1
  local t0 dropped=0
  t0=$(date +%s)
  say "[i] 等设备自己重启（最多 ${CYCLE_WAIT}s）…"
  while [ $(( $(date +%s) - t0 )) -lt "$CYCLE_WAIT" ]; do
    if ! adb shell 'echo up' 2>/dev/null | grep -q up; then dropped=1; break; fi
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

select_ko() {   # 结果写进 KO_FILE；没有/跳过返回 1
  local list=() f i n
  while IFS= read -r f; do list+=("$f"); done < <(find "$HERE" -maxdepth 1 -type f -name '*.ko' | sort)
  [ "${#list[@]}" -gt 0 ] || { say "[i] 本目录没有 .ko —— 用管理器自带的 ko"; return 1; }
  say ""
  say "[本目录的 ko]"
  i=0; for f in "${list[@]}"; do i=$((i+1)); say "  $i) $(basename "$f")  $(wc -c <"$f") B"; done
  [ "$KO_SEL" = none ] && { say "[i] --no-ko：跳过"; return 1; }
  if [ -n "$KO_SEL" ]; then
    case "$KO_SEL" in
      [0-9]*) i=$((KO_SEL-1)); [ "$i" -ge 0 ] && [ "$i" -lt "${#list[@]}" ] && { KO_FILE="${list[$i]}"; return 0; } ;;
      *)      for f in "${list[@]}"; do [ "$(basename "$f")" = "$KO_SEL" ] && { KO_FILE="$f"; return 0; }; done ;;
    esac
    say "[!] --ko $KO_SEL 无效"; return 1
  fi
  [ -t 0 ] || { say "[i] 非交互模式，跳过（--ko N 可指定）"; return 1; }
  printf '选哪个 ko？（回车 = 用管理器自带的）: '
  read -r n || return 1
  case "$n" in
    '') return 1 ;;
    [0-9]*) i=$((n-1)); [ "$i" -ge 0 ] && [ "$i" -lt "${#list[@]}" ] && { KO_FILE="${list[$i]}"; return 0; } ;;
  esac
  say "[!] 编号无效"; return 1
}

install_user_ko() {   # 布置：user.ko + ksud wrapper（root 脚本 late-load 时先加载你的 ko）
  [ -n "$KO_FILE" ] || return 0
  say "[*] 指定 ko：$(basename "$KO_FILE")"
  adb push "$KO_FILE" "$D/user.ko" >/dev/null 2>&1 || die "push ko 失败"
  adb shell "chmod 644 $D/user.ko" >/dev/null 2>&1

  # 管理器包名 + 它 APK 里的 libksud.so
  # 注意：/data/app 对 shell 不可列，glob 展开会失败，必须走 pm path
  PKG_M="$(adb shell 'pm list packages 2>/dev/null' | tr -d '\r' | sed 's/^package://' \
           | grep -iE 'sukisu|resukisu|bakasu|kernelsu|ksunext|supermanager' | head -1)"
  [ -n "$PKG_M" ] || PKG_M=com.sukisu.ultra
  APK_M="$(adb shell "pm path $PKG_M 2>/dev/null" | tr -d '\r' | sed 's/^package://' | head -1)"
  LIB_M=""
  [ -n "$APK_M" ] && LIB_M="$(dirname "$APK_M")/lib/arm64/libksud.so"
  say "    manager=$PKG_M"
  [ -n "$LIB_M" ] && say "    ksud=$LIB_M"

  W="$(mktemp)"; cat > "$W" <<EOS
#!/system/bin/sh
# install-ksu wrapper：late-load 时先 insmod 用户的 ko，再交给真 ksud 做 bootstrap
KO='$D/user.ko'
PKG='$PKG_M'
LOG='$D/.gl_wrap.log'
REAL=''
for R in '$LIB_M' /data/adb/ksu/bin/ksud /data/adb/ksud /data/local/tmp/ksud; do
  [ -n "\$R" ] && [ -x "\$R" ] && { REAL="\$R"; break; }
done
[ -n "\$REAL" ] || REAL=\$(ls -d /data/app/*/*/lib/arm64/libksud.so 2>/dev/null | head -1)
[ -n "\$REAL" ] || { echo "no ksud found" >> "\$LOG"; exit 90; }
if [ "\$1" = "late-load" ]; then
  shift
  ARGS=""
  while [ \$# -gt 0 ]; do
    case "\$1" in
      --package-name) shift 2; continue ;;
      --package-name=*) shift; continue ;;
      *) ARGS="\$ARGS \$1"; shift ;;
    esac
  done
  if [ -f "\$KO" ]; then
    echo "== insmod \$KO ==" >> "\$LOG"
    "\$REAL" insmod "\$KO" allow_shell=1 >> "\$LOG" 2>&1
    echo "insmod exit=\$?" >> "\$LOG"
  fi
  exec "\$REAL" late-load --package-name "\$PKG" \$ARGS
fi
exec "\$REAL" "\$@"
EOS
  adb push "$W" "$D/ksud" >/dev/null 2>&1 || { rm -f "$W"; die "push wrapper 失败"; }
  rm -f "$W"
  adb shell "chmod 755 $D/ksud; rm -f $D/.gl_ksu_pkg $D/.gl_wrap.log" >/dev/null 2>&1
  say "[*] wrapper 就绪（真 ksud 由 pm path 解析，运行时再兜底）"
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
select_ko && install_user_ko

say "[i] 最多 $ROUNDS 轮；脚本不会主动重启设备"

WIN=0
for r in $(seq 1 "$ROUNDS"); do
  say ""
  say "================ 第 $r/$ROUNDS 轮 ================"

  if ! wait_shell; then
    say "[!] 300 秒内没等到 adb shell，再来一轮"
    continue
  fi

  up="$(uptime_s)"; upi="${up%%.*}"
  if [ -n "$upi" ] && [ "$upi" -gt "$WINDOW" ] 2>/dev/null; then
    say "[i] 当前 uptime=${up}s，已经过了窗口（12~45 秒才容易中）"
    say "    等手机自己重启，或你现在手动重启"
    if wait_cycle; then say "[i] 设备已重启，继续"; continue; else
      say "[!] 等不到重启，先退出；重启后再跑本脚本"; break
    fi
  fi
  say "[i] 拿到 shell：uptime=${up}s（越早越好）"

  DROPPED=0
  for n in $(seq 1 "$PER_BOOT"); do
    up="$(uptime_s)"; upi="${up%%.*}"
    if [ -n "$upi" ] && [ "$upi" -gt "$WINDOW" ] 2>/dev/null; then
      say "[i] uptime=${up}s 超出窗口 ${WINDOW}s，本轮结束"
      break
    fi
    say "---- 第 $r 轮 / 第 $n 次（uptime=${up}s）----"

    ts="$(date +%s)-$r-$n"
    timeout 25 adb shell "cd $D && GL_RUN_ID=$ts setsid sh $D/glrun.sh </dev/null >/dev/null 2>&1 & echo go" >/dev/null 2>&1

    end=$(( $(date +%s) + TIMEOUT ))
    handoff=0
    klog=""
    while [ "$(date +%s)" -lt "$end" ]; do
      sleep 0.7
      if ! adb shell 'echo up' 2>/dev/null | grep -q up; then
        DROPPED=1
        say "[!] 设备掉线（panic/重启）——正常失败路径"
        break
      fi
      klog="$(adb shell "cat $D/ksu-$ts.log 2>/dev/null" 2>/dev/null | tr -d '\r')"
      case "$klog" in *"KernelSU module loaded"*) WIN=1 ;; esac
      [ "$WIN" = 1 ] && break
      case "$klog" in
        *"fixup failed"*|*"KernelSU module not loaded"*|*"ksud missing"*) break ;;
      esac
      # root 脚本启动后不再发射，延长等待直到它跑完
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
    if [ "$handoff" = 1 ] && [ "$WIN" != 1 ]; then
      say "    [!] root 脚本起来了但没等到 KernelSU loaded，日志尾部："
      adb shell "tail -n 5 $D/ksu-$ts.log 2>/dev/null" 2>/dev/null | tr -d '\r' | sed 's/^/      /'
      adb shell "tail -n 3 $D/.gl_wrap.log 2>/dev/null" 2>/dev/null | tr -d '\r' | sed 's/^/      wrap: /'
      break
    fi

    [ "$WIN" = 1 ] && break
    [ "$DROPPED" = 1 ] && break
    say "    native: $(adb shell "tail -n 3 $D/native-$ts.log 2>/dev/null" 2>/dev/null | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g' | tr '\n' ' ' | cut -c1-150)"
    [ -n "$klog" ] && say "    root脚本: $(printf '%s' "$klog" | tail -n 2 | tr '\n' ' ' | cut -c1-150)"
  done

  [ "$WIN" = 1 ] && break
  if [ "$DROPPED" = 1 ]; then
    say "[i] 等设备回来…"
    wait_shell || { say "[!] 设备没回来，退出"; break; }
    continue
  fi
  say "[i] 本轮没中（设备没掉线）。窗口已过，重启手机后再跑；不等了。"
  break
done

say ""
if [ "$WIN" = 1 ] || is_root; then
  say "[+] 成功：root 已在（KernelSU late-load）"
  show_status
  say ""
  say "用法：  adb shell su -c 'id'"
  say "注意：  late-load 只在内存里 —— 硬重启就没了，重启后重跑本脚本。"
  if [ -n "$KO_FILE" ]; then
    say "        （本次用的是你的 ko：$(basename "$KO_FILE")，已写入 $D/user.ko，下次仍会用它）"
  fi
  if [ "$CLEAN_AFTER" = 1 ] && [ "$WIN" = 1 ]; then
    say ""
    say "[*] 清理本次提权残留（保留 user.ko 与 ksud wrapper）"
    adb shell "rm -f $D/libghostlock.so $D/profile.bin $D/vrpatch.ko $D/glrun.sh \
      $D/.ghostlock_root.sh $D/.ghostlock_iomem $D/.gl_out $D/.gl_cmd \
      $D/native-*.log $D/native-*.rc $D/ksu-*.log" >/dev/null 2>&1 || true
    say "    ok（payload 与日志已删；root 与 KSU 不受影响）"
  fi
  exit 0
else
  say "[-] 这轮没中。再跑一次（概率问题；作者单轮约 43 秒，也是多轮才稳）。"
  say "    连续很多次不中时，作者的经验：恢复出厂设置可以恢复命中率。"
  exit 1
fi
