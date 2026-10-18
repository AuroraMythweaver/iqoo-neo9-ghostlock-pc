#!/usr/bin/env bash
# ============================================================================
# install-ksu.sh —— 提权之后：加载你自己的 .ko，并安装配套的 KSU 管理器
#
#   和原作者 APK 用同一个加载器（ksuinit::load_module）：
#     ksud insmod <你的.ko> allow_shell=1     ← ko 是明文文件，由你提供
#     ksud late-load ...                      ← 此时模块已在，只做用户态 bootstrap
#
#   ⚠ 本脚本**不会**从 APK / libksud.so 里解出 ko（那是编进二进制的数据段，不是文件）。
#     它只用管理器 APK 里的 libksud.so 作为 ksud 可执行文件（loader）。
#
#   把 xxx_kernelsu.ko / 管理器.apk 放在本脚本同级目录，先 ./reroot.sh 提权，再：
#
#     ./install-ksu.sh                    # 预览：列本目录 ko / apk、当前内核状态
#     ./install-ksu.sh --ko 1             # 加载第 1 个 ko
#     ./install-ksu.sh --ko 1 --install 1 # 加载 + 装管理器
#     ./install-ksu.sh --persist --ko 1   # 以后每次 reroot.sh 都用这个 ko（重启生效）
#     ./install-ksu.sh --dry-run --ko 1   # 只看计划
#
#   其它：--ksud <path> 指定 ksud；--pkg <pkg> 指定管理器包名；--yes 跳过确认
#
#   注意：内核里只能有一个 kernelsu 模块；已加载时换 ko 必须先重启。
# ============================================================================
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
HOME_DIR=/data/local/tmp/ghostlock-app

# ---------- adb ----------
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

say() { printf '%s\n' "$*"; }
sho() { "$ADB" shell "$1" 2>/dev/null | tr -d '\r'; }
suro() { "$ADB" shell "su -c '$1'" 2>/dev/null | tr -d '\r'; }
have_root() { [ "$(suro 'id -u' | tr -d ' ')" = "0" ]; }
managers() {
  sho 'pm list packages 2>/dev/null | sed -n "s/^package://p" | grep -iE "sukisu|resukisu|bakasu|kernelsu|ksunext|supermanager"' | tr '\n' ' '
}

KO_SEL=""; APK_SEL=""; KSUD_OPT=""; PKG_OPT=""; PERSIST=0; YES=0; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ko)        KO_SEL="${2:-}"; shift 2 ;;
    --install)   APK_SEL="${2:-}"; shift 2 ;;
    --ksud)      KSUD_OPT="${2:-}"; shift 2 ;;
    --pkg)       PKG_OPT="${2:-}"; shift 2 ;;
    --persist)   PERSIST=1; shift ;;
    --yes|-y)    YES=1; shift ;;
    --dry-run)   DRY=1; shift ;;
    -h|--help)   sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           say "[!] 未知参数: $1（--help 看用法）"; exit 2 ;;
  esac
done

# ---------- 收集本目录文件 ----------
KOS=(); while IFS= read -r f; do KOS+=("$f"); done < <(find "$DIR" -maxdepth 1 -type f -name '*.ko' | sort)
APKS=(); while IFS= read -r f; do APKS+=("$f"); done < <(find "$DIR" -maxdepth 1 -type f -name '*.apk' | sort)

pick() {  # pick <arg> <array...>  → 回显选中路径
  local sel="$1"; shift
  local arr=("$@") i
  case "$sel" in
    '') return 1 ;;
    [0-9]*) i=$((sel-1)); [ "$i" -ge 0 ] && [ "$i" -lt "${#arr[@]}" ] && { printf '%s\n' "${arr[$i]}"; return 0; }; return 1 ;;
    *)  for f in "${arr[@]}"; do [ "$(basename "$f")" = "$sel" ] && { printf '%s\n' "$f"; return 0; }; done
        for f in "${arr[@]}"; do case "$f" in *"$sel"*) printf '%s\n' "$f"; return 0 ;; esac; done
        return 1 ;;
  esac
}

# ---------- 状态 ----------
say "=============================================================="
say " install-ksu.sh   目录: $DIR"
say "=============================================================="
say ""
say "[本目录的 ko]"
if [ "${#KOS[@]}" -eq 0 ]; then
  say "  （没有 .ko）—— 把你这份机型对应的 xxx_kernelsu.ko 放进 $DIR 再跑"
else
  i=0; for f in "${KOS[@]}"; do i=$((i+1)); say "  $i) $(basename "$f")  $(wc -c <"$f") B"; done
fi
say ""
say "[本目录的 APK]"
if [ "${#APKS[@]}" -eq 0 ]; then
  say "  （没有 .apk）—— 管理器安装包放这里就能直接装"
else
  i=0; for f in "${APKS[@]}"; do i=$((i+1)); say "  $i) $(basename "$f")  $(wc -c <"$f") B"; done
fi

if ! "$ADB" devices 2>/dev/null | grep -q "device"; then
  say ""
  say "[!] 没看到 adb 设备"; exit 3
fi

say ""
say "[设备状态]"
say "  uname      : $(sho 'uname -r')"
say "  kernelsu   : $(sho 'grep -c kernelsu /proc/modules')  （1=内核里已有一个）"
say "  su         : $(sho "su -c id -u 2>/dev/null" | head -1)  （0=当前有 root）"
say "  管理器     : $(managers)"

if [ -z "$KO_SEL" ] && [ -z "$APK_SEL" ]; then
  say ""
  say "以上只是预览。用法示例："
  say "  $0 --ko 1                          # 提权后加载第 1 个 ko"
  say "  $0 --ko 1 --install 1              # 加载 + 装管理器"
  say "  $0 --persist --ko 1                # 以后每次 reroot.sh 都用这个 ko（需重启生效）"
  exit 0
fi

# ---------- 前置：必须有 root ----------
if ! have_root; then
  say ""
  say "[!] 当前没有 root。先跑：./reroot.sh  （抢到窗口后再回来执行本脚本）"
  exit 4
fi

# ---------- 定位管理器的 ksud（loader） ----------
find_ksud() {
  local p
  if [ -n "$KSUD_OPT" ]; then printf '%s\n' "$KSUD_OPT"; return 0; fi
  # 1) 已装管理器 APK 里的 libksud.so（最新，和 APK 同源）
  for p in ${PKG_OPT:-$(managers)}; do
    k=$(suro "ls -d /data/app/*/$p-*/lib/arm64/libksud.so 2>/dev/null | head -1")
    [ -n "$k" ] && { printf '%s\n' "$k"; return 0; }
  done
  # 2) 常规落点
  for k in /data/adb/ksu/bin/ksud /data/adb/ksud /data/local/tmp/ksud; do
    [ "$(suro "test -x '$k' && echo y")" = "y" ] && { printf '%s\n' "$k"; return 0; }
  done
  return 1
}

KSUD="$(find_ksud || true)"
if [ -z "$KSUD" ]; then
  say ""
  say "[!] 设备上找不到 ksud（加载器）。先装任意一个 KSU 管理器 APK，或 --ksud 指定路径"
  exit 5
fi

# ---------- 选 ko ----------
KO_FILE=""
if [ -n "$KO_SEL" ]; then
  if [ -f "$KO_SEL" ]; then KO_FILE="$KO_SEL"; else KO_FILE="$(pick "$KO_SEL" "${KOS[@]}" || true)"; fi
  if [ -z "$KO_FILE" ]; then
    say ""
    say "[!] 找不到 ko: $KO_SEL（可用：$(for f in "${KOS[@]}"; do basename "$f"; done | tr '\n' ' ')）"
    exit 6
  fi
fi

# ---------- 选 APK ----------
APK_FILE=""
if [ -n "$APK_SEL" ]; then
  if [ -f "$APK_SEL" ]; then APK_FILE="$APK_SEL"; else APK_FILE="$(pick "$APK_SEL" "${APKS[@]}" || true)"; fi
  if [ -z "$APK_FILE" ]; then
    say ""
    say "[!] 找不到 apk: $APK_SEL（可用：$(for f in "${APKS[@]}"; do basename "$f"; done | tr '\n' ' ')）"
    exit 7
  fi
fi

# ---------- 计划 ----------
say ""
say "[计划]"
say "  loader(ksud) : $KSUD"
[ -n "$KO_FILE" ]  && say "  加载 ko      : $(basename "$KO_FILE")  ($(wc -c <"$KO_FILE") B)"
[ -n "$APK_FILE" ] && say "  安装管理器   : $(basename "$APK_FILE")"
[ "$PERSIST" = 1 ] && say "  持久化       : 写 $HOME_DIR/ksud wrapper（以后 reroot.sh 都用这个 ko）"
say ""
if [ "$DRY" = 1 ]; then
  say "[dry-run] 到此为止，什么都没做。去掉 --dry-run 才会执行。"
  exit 0
fi
if [ "$YES" = 0 ]; then
  printf '[?] 3 秒后开始（Ctrl-C 取消）…'
  sleep 3; echo
fi

# ---------- 加载 ko ----------
if [ -n "$KO_FILE" ]; then
  if [ "$(sho 'grep -c kernelsu /proc/modules')" = "1" ]; then
    say "[i] 内核里已有 kernelsu 模块 —— 同一个内核里不能有两个，跳过 insmod"
    say "    要换成 $(basename "$KO_FILE")，必须：$0 --persist --ko <同上>  →  adb reboot  →  ./reroot.sh"
  else
    suro "mkdir -p $HOME_DIR" >/dev/null 2>&1
    REMOTE="$HOME_DIR/incoming.ko"
    say "[*] push ko → $REMOTE"
    "$ADB" push "$KO_FILE" "$REMOTE" >/dev/null 2>&1 || { say "[!] push 失败"; exit 8; }
    suro "chmod 644 '$REMOTE'" >/dev/null 2>&1
    say "[*] insmod（ksuinit loader，vermagic 自动适配）"
    OUT="$(suro "'$KSUD' insmod '$REMOTE' allow_shell=1 2>&1")"
    [ -n "$OUT" ] && say "    $OUT"
    OK=0
    i=0; while [ "$i" -lt 50 ]; do
      [ "$(sho 'grep -c kernelsu /proc/modules')" = "1" ] && { OK=1; break; }
      sleep 0.1; i=$((i+1))
    done
    if [ "$OK" = 1 ]; then
      say "[+] kernelsu 已加载"
    else
      say "[!] 加载失败（ko 与内核符号/CRC 不匹配？）——看上面 insmod 输出；不会破坏系统分区"
      exit 9
    fi
  fi
  # bootstrap：late-load 会因为 has_kernelsu() 跳过 ko，只做用户态安装
  PKG_FINAL="${PKG_OPT:-$(managers | awk '{print $1}')}"
  [ -n "$PKG_FINAL" ] || PKG_FINAL=com.sukisu.ultra
  KMI="$(sho 'uname -r' | sed -n 's/^\([0-9]*\)\.\([0-9]*\).*/\1 \2/p')"
  case "$KMI" in
    "5 15") KMI=android13-5.15 ;;
    "5 10") KMI=android13-5.10 ;;
    "6 1")  KMI=android14-6.1 ;;
    "6 6")  KMI=android15-6.6 ;;
    "6 12") KMI=android16-6.12 ;;
    *)      KMI="${KMI// /-}" ;;
  esac
  say "[*] bootstrap：ksud late-load --package-name $PKG_FINAL --kmi $KMI（只做用户态安装）"
  suro "'$KSUD' late-load --allow-shell --package-name '$PKG_FINAL' --kmi '$KMI' >/dev/null 2>&1" >/dev/null 2>&1 || true
  sleep 1
  say "    内核信息：$(suro "'$KSUD' debug info 2>/dev/null" | tr '\n' ' ' | cut -c1-160)"
fi

# ---------- 持久化 wrapper ----------
if [ "$PERSIST" = 1 ]; then
  if [ -z "$KO_FILE" ]; then
    say ""
    say "[!] --persist 需要同时给 --ko <文件>"
    exit 10
  fi
  suro "mkdir -p $HOME_DIR" >/dev/null 2>&1
  "$ADB" push "$KO_FILE" "$HOME_DIR/user.ko" >/dev/null 2>&1 || { say "[!] push user.ko 失败"; exit 8; }
  suro "chmod 644 $HOME_DIR/user.ko" >/dev/null 2>&1
  cat > /tmp/ksud_wrapper.sh <<EOS
#!/system/bin/sh
# 由 install-ksu.sh 生成：每次 root 脚本调 late-load 时，先 insmod 用户提供的 ko
KO='$HOME_DIR/user.ko'
REAL=""
for R in '$KSUD' /data/adb/ksu/bin/ksud /data/adb/ksud /data/local/tmp/ksud; do
  [ -x "$R" ] && { REAL="$R"; break; }
done
[ -n "$REAL" ] || exit 90
if [ "\$1" = "late-load" ]; then
  shift
  [ -f "\$KO" ] && "\$REAL" insmod "\$KO" allow_shell=1 >/dev/null 2>&1
  exec "\$REAL" late-load "\$@"
fi
exec "\$REAL" "\$@"
EOS
  "$ADB" push /tmp/ksud_wrapper.sh "$HOME_DIR/ksud" >/dev/null 2>&1 || { say "[!] push wrapper 失败"; exit 8; }
  suro "chmod 755 $HOME_DIR/ksud" >/dev/null 2>&1
  suro "rm -f $HOME_DIR/.gl_ksu_pkg" >/dev/null 2>&1   # 置空，root 脚本才会优先用 $HOME_DIR/ksud
  say "[+] 已持久化：$HOME_DIR/ksud（wrapper）+ $HOME_DIR/user.ko"
  say "    之后每次 ./reroot.sh 都会用这个 ko 去 late-load"
  say "    注意：若安装了 root 脚本候选列表里的管理器（如 com.resukisu.resukisu），"
  say "          脚本会优先用它 APK 内的 ksud，wrapper 可能被绕过"
fi

# ---------- 安装管理器 ----------
if [ -n "$APK_FILE" ]; then
  say ""
  say "[*] 安装管理器：$(basename "$APK_FILE")"
  OUT="$("$ADB" install -r "$APK_FILE" 2>&1 | tail -2)"
  say "    $OUT"
  case "$OUT" in
    *Success*) : ;;
    *) say "[!] 安装失败（签名冲突？先 adb uninstall 旧管理器）" ;;
  esac
  PKG_APK="${PKG_OPT:-}"
  if [ -n "$PKG_APK" ]; then
    say "    $(sho "dumpsys package $PKG_APK 2>/dev/null | grep -E 'versionName|versionCode' | head -2" | tr '\n' ' ')"
  fi
fi

# ---------- 收尾报告 ----------
say ""
say "=============================================================="
say " 结果"
say "=============================================================="
say "  kernelsu   : $(sho 'grep -c kernelsu /proc/modules')"
say "  su         : $(sho 'su -c id 2>/dev/null' | head -1)"
say "  内核信息   : $(suro "'$KSUD' debug info 2>/dev/null" | tr '\n' ' ' | cut -c1-200)"
say "  已装管理器 : $(managers)"
say ""
say " 管理器打开后：若显示「需要更新内核」，说明 管理器uapi > 内核uapi，"
say " 换一个与该内核 ko 同版本的官方管理器 APK；若显示「工作中」，两边 uapi 一致。"
say " 重启后 late-load 失效，重跑 ./reroot.sh（带 --persist 的话会用你这份 ko）。"
