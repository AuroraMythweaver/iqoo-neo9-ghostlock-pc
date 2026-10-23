#!/usr/bin/env bash
# ============================================================================
# reroot.sh —— iQOO Neo9 (PD2338) 一键临时 root（macOS 专用）
#
#   同目录需要两个文件：
#     reroot.sh        本脚本（纯 bash + adb）
#     ghostlock.bin    payload：libghostlock.so + vrpatch.ko + profile.bin
#
#   与 reroot.sh 行为一致，只依赖 macOS 自带工具（BSD dd / 无 timeout / 无 seq）。
#   原理见 README；脚本只负责：等开机窗口 → 发射 → 命中即停。
#   成功判据 = root 日志出现 "KernelSU module loaded"。
#   脚本不会主动重启手机（失败时手机会自己重启）。
#
#   用法：
#     ./reroot-mac.sh                 # 最多 10 轮
#     ./reroot-mac.sh 20              # 最多 20 轮
#     ./reroot-mac.sh --check         # 只看状态
#     ./reroot-mac.sh --inspect       # 看 payload 包内容
#     ./reroot-mac.sh --deploy        # 只部署 payload
#     ./reroot-mac.sh --check-payload # 只看设备上的 payload 是否就绪
#     ./reroot-mac.sh --redeploy      # 强制重推 payload
#     ./reroot-mac.sh --force         # release 不匹配也打（可能 panic，慎用）
#     ./reroot-mac.sh --ko 1          # 启动时选本目录第 1 个 .ko（late-load 时先加载它）
#     ./reroot-mac.sh --ko 1 --clean-after   # 成功后自动清理本次残留（保留 user.ko / wrapper）
# ============================================================================
set -u

D="${GL_DIR:-/data/local/tmp/ghostlock-app}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PACK="$HERE/ghostlock.bin"
TIMEOUT="${TIMEOUT:-180}"
PER_BOOT="${PER_BOOT:-6}"
WINDOW="${WINDOW:-90}"
MIN_UPTIME="${MIN_UPTIME:-30}"   # 窗口下沿：太早打容易 panic，等 uptime 到这里再发射
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
PKG_OPT=""
KSUD_OPT=""
LIST_MGRS=0
INSTALL_APK=
NO_FIRE=0

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
    --pkg)       PKG_OPT="${2:-}"; [ -n "$PKG_OPT" ] && shift ;;
    --ksud)      KSUD_OPT="${2:-}"; [ -n "$KSUD_OPT" ] && shift ;;
    --list-managers) LIST_MGRS=1 ;;
    --install-apk) INSTALL_APK="${2:-}"; [ -n "$INSTALL_APK" ] && shift ;;
    --no-fire)   NO_FIRE=1 ;;

    --pack)      shift; PACK="${1:-$PACK}" ;;
    *.bin)       PACK="$1" ;;
    ''|*[!0-9]*) ;;
    *)           ROUNDS="$1" ;;
  esac
  shift
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
pushf() { local i; for i in 1 2 3; do to 60 "$ADB" push "$1" "$2" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
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
  say "[i] 等设备自己重启（最多 ${CYCLE_WAIT}s）…"
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

select_ko() {   # 结果写进 KO_FILE；没有/跳过返回 1
  local list=() f i n
  # 直接给了文件路径（绝对/相对）就用它
  if [ -n "$KO_SEL" ] && [ "$KO_SEL" != none ] && [ -f "$KO_SEL" ]; then
    KO_FILE="$KO_SEL"; say "[*] 使用 ko：$(basename "$KO_FILE")"; return 0
  fi
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

managers() {   # 已装的 KSU 系管理器包名（开机前几秒 pm 可能没就绪，重试）
  local i out
  for i in 1 2 3 4 5 6 7 8 9 10; do
    out="$(sho 'pm list packages 2>/dev/null' | sed 's/^package://' \
           | grep -iE 'sukisu|resukisu|bakasu|kernelsu|ksunext|supermanager' | sort -u)"
    [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
    sleep 0.5
  done
  return 0
}

mgr_ksud() {   # mgr_ksud <pkg> → 该 APK 里的 ksud 动态库
  # 注意：新版 APK 会把 ksud 改成随机库名（如 libdhxddxovny.so），不能只认 libksud.so；
  #       /data/app 对 shell 不可列，所以用 pm path + 直接 ls 目标目录（可读）
  local apk dir out p
  apk="$(sho "pm path $1 2>/dev/null" | sed 's/^package://' | head -1)"
  [ -n "$apk" ] || return 0
  dir="${apk%/*}/lib/arm64"
  out="$(sho "ls -l $dir/*.so 2>/dev/null")"
  [ -n "$out" ] || return 0
  # 1) 标准名
  p="$(printf '%s\n' "$out" | awk '{print $NF}' | grep -E '/libksud\.so$' | head -1)"
  # 2) 否则取体积最大的那个（ksud 有 ~3-6 MB，其余 JNI 库都是几十 KB）
  [ -z "$p" ] && p="$(printf '%s\n' "$out" | awk '$5+0 >= 1000000 {print $5, $NF}' \
                    | sort -nr | head -1 | awk '{print $2}')"
  [ -n "$p" ] && printf '%s\n' "$p"
  return 0
}

install_wrapper() {   # install_wrapper <pkg> <real-ksud>
  local pkg="$1" real="$2" w t
  w="$(mktemp)"; t="$(mktemp)"
  cat > "$t" <<'TEMPLATE_EOF'
#!/system/bin/sh
# root 脚本的 ksud 入口：late-load 时先 insmod 指定 ko，再交给真 ksud 做 bootstrap
D='@D@'
export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
KO="$D/user.ko"
PKG='@PKG@'
SRC='@SRC@'
LOG="$D/.gl_wrap.log"
log() { echo "$*" >> "$LOG" 2>/dev/null; }
REAL=''
# 1) 工作目录里已备好的可执行 ksud（发布包自带或上次复制下来的）
[ -x "$D/ksud.real" ] && REAL="$D/ksud.real"
# 2) 系统里已安装的
if [ -z "$REAL" ]; then
  for R in /data/adb/ksu/bin/ksud /data/adb/ksud /data/local/tmp/ksud; do
    [ -x "$R" ] && { REAL="$R"; break; }
  done
fi
# 3) 从管理器 APK 的库里复制一份出来再执行（应用库不允许直接 exec）
if [ -z "$REAL" ] && [ -n "$SRC" ]; then
  cp "$SRC" "$D/ksud.real" 2>/dev/null && chmod 755 "$D/ksud.real" 2>/dev/null && REAL="$D/ksud.real"
fi
# 4) pm path 兜底：找 APK 目录里体积最大的 .so，复制出来
if [ -z "$REAL" ]; then
  P=$(pm path "$PKG" 2>/dev/null | head -n1 | sed 's/^package://')
  if [ -n "$P" ]; then
    DIR="${P%/*}/lib/arm64"
    BIG=$(ls -l "$DIR"/*.so 2>/dev/null | awk '$5+0 >= 1000000 {print $5, $NF}' | sort -nr | head -1 | awk '{print $2}')
    [ -n "$BIG" ] && cp "$BIG" "$D/ksud.real" 2>/dev/null && chmod 755 "$D/ksud.real" 2>/dev/null && REAL="$D/ksud.real"
  fi
fi
[ -n "$REAL" ] || { log "no ksud found (pkg=$PKG src=$SRC)"; exit 90; }
log "ksud=$REAL pkg=$PKG"
if [ "$1" = "late-load" ]; then
  shift
  ARGS=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --package-name) shift 2; continue ;;
      --package-name=*) shift; continue ;;
      *) ARGS="$ARGS $1"; shift ;;
    esac
  done
  if [ -f "$KO" ]; then
    log "== insmod $KO =="
    "$REAL" insmod "$KO" allow_shell=1 >> "$LOG" 2>&1
    log "insmod exit=$?"
  fi
  exec "$REAL" late-load --package-name "$PKG" $ARGS
fi
exec "$REAL" "$@"
TEMPLATE_EOF
  sed "s|@D@|$D|g; s|@PKG@|$pkg|g; s|@SRC@|$real|g" "$t" > "$w"; rm -f "$t"
  pushf "$w" "$D/ksud" || { rm -f "$w"; die "push wrapper 失败"; }
  rm -f "$w"
  # 用 wrapper 时必须让 .gl_ksu_pkg 为空，root 脚本才会优先用 $HOME_DIR/ksud
  sho "chmod 755 $D/ksud; rm -f $D/.gl_ksu_pkg $D/.gl_wrap.log" >/dev/null 2>&1
  say "[*] ksud 入口已就绪（wrapper，包名 $pkg）"
}

setup_ksu_target() {   # 决定这次 root 脚本用哪个 ksud、以及 --package-name
  local pkg lib kreal
  # 先装管理器（可选）：装完下面的探测就能看到它
  if [ -n "$INSTALL_APK" ]; then
    say "[*] 安装管理器：$(basename "$INSTALL_APK")"
    "$ADB" install -r "$INSTALL_APK" 2>&1 | tail -1 | sed 's/^/    /'
  fi
  pkg="$PKG_OPT"; [ -n "$pkg" ] || pkg="$(managers | head -1)"
  kreal=""

  # 0) 先把 ko 推上去（wrapper 会 insmod 它）
  if [ -n "$KO_FILE" ]; then
    pushf "$KO_FILE" "$D/user.ko" || die "push ko 失败"
    sho "chmod 644 $D/user.ko" >/dev/null 2>&1
  fi

  # A) 用户直接给了 ksud 二进制（没有管理器也行）
  if [ -n "$KSUD_OPT" ]; then
    pushf "$KSUD_OPT" "$D/ksud.real" || die "push ksud 失败"
    sho "chmod 755 $D/ksud.real" >/dev/null 2>&1
    kreal="$D/ksud.real"
    say "[*] ksud：$(basename "$KSUD_OPT")（用户指定）"
  fi

  # A2) 脚本目录里自带的 ksud 二进制（发布包里有 ksud-aarch64-linux-android）
  if [ -z "$kreal" ]; then
    local lk
    lk="$(find "$HERE" -maxdepth 1 -type f -name 'ksud*' ! -name '*.ko' 2>/dev/null | head -1)"
    if [ -n "$lk" ]; then
      pushf "$lk" "$D/ksud.real" || die "push ksud 失败"
      sho "chmod 755 $D/ksud.real" >/dev/null 2>&1
      kreal="$D/ksud.real"
      say "[*] ksud：$(basename "$lk")（脚本目录自带）"
    fi
  fi

  # B) 管理器 APK 里的 ksud 库（可能叫 libksud.so，也可能是随机名，几 MB 那个）
  lib=""
  [ -n "$pkg" ] && [ -z "$kreal" ] && lib="$(mgr_ksud "$pkg")"
  if [ -n "$lib" ] && [ -z "$kreal" ]; then
    # 从 /data/app 复制到工作目录再执行（避免 SELinux 直接 exec 应用库）
    if sho "cp '$lib' '$D/ksud.real' 2>/dev/null && chmod 755 '$D/ksud.real' && test -x '$D/ksud.real' && echo ok" | grep -q ok; then
      kreal="$D/ksud.real"
      say "[*] ksud：从管理器 APK 取出 → $D/ksud.real（$(basename "$lib")）"
    else
      say "[!] 复制管理器里的 ksud 失败，退回直接路径：$lib"
      kreal="$lib"
    fi
  fi

  if [ -n "$KO_FILE" ] && [ -z "$kreal" ] && [ -z "$lib" ]; then
    say "[!] 没找到任何 ksud：先 adb install 管理器 APK，或 --ksud <ksud 二进制>"
  fi

  if [ -n "$KO_FILE" ] || [ -n "$kreal" ]; then
    install_wrapper "${pkg:-com.sukisu.ultra}" "${kreal:-$lib}"
    [ -n "$KO_FILE" ] && say "[*] 本次 ko：$(basename "$KO_FILE")"
    [ -n "$kreal" ] || say "    loader：$lib"
  else
    # C) 纯管理器模式：包名写进 .gl_ksu_pkg，root 脚本自己去 APK 里找 ksud
    if [ -n "$pkg" ]; then
      sho "printf %s '$pkg' > $D/.gl_ksu_pkg; rm -f $D/ksud" >/dev/null 2>&1
      say "[*] 管理器：$pkg"
      say "    loader：$(mgr_ksud "$pkg")"
    else
      say "[!] 设备上没装 KSU 管理器，也没给 --ksud / --ko —— KSU 大概率加载不了"
    fi
  fi
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

if [ "$LIST_MGRS" = 1 ]; then
  say "[已装的管理器]"; managers | sed 's/^/  /'
  say ""
  say "[本目录的 ko]"; find "$HERE" -maxdepth 1 -type f -name '*.ko' 2>/dev/null | sed 's|.*/|  |'
  exit 0
fi

select_ko && :        # 只是填 KO_FILE
setup_ksu_target
[ "$NO_FIRE" = 1 ] && { say ""; say "[i] --no-fire：准备完成（payload/管理器/ko/wrapper 已就位），不发射"; exit 0; }

say "[i] 最多 $ROUNDS 轮；脚本不会主动重启设备"

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
    say "    重启手机后再跑本脚本（脚本不会替你重启）"
    break
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

    # 对齐窗口下沿：uptime 太小就先等（实测成功集中在 32~40 秒）
    upi2="${up%%.*}"
    if [ -n "$upi2" ] && [ "$upi2" -lt "$MIN_UPTIME" ] 2>/dev/null; then
      d=$(( MIN_UPTIME - upi2 ))
      say "    等 ${d}s 到 uptime≈${MIN_UPTIME}s 再发射"
      sleep "$d"
    fi
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
    say "    native: $("$ADB" shell "tail -n 3 $D/native-$ts.log 2>/dev/null" 2>/dev/null | tr -d '\r' | sed "s/${ESC}\[[0-9;]*m//g" | tr '\n' ' ' | cut -c1-150)"
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
  say "内核侧：  $(sho "su -c '/data/adb/ksud debug info 2>/dev/null'" | tr '\n' ' ' | cut -c1-120)"
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
