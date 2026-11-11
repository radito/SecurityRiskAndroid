#!/usr/bin/env bash
# Run SecurityRiskAndroid inside an x86_64 emulator configured as one "leg" of the
# module matrix, collect results + ground-truth evidence, and check expectations.
#
#   ci/avd-leg.sh <leg> <app.apk> [fixture.zip]
#
# Legs:
#   baseline  stock emulator, no root
#   magisk    Magisk (patched ramdisk), Zygisk off, no modules
#   zygisk    Magisk + Zygisk + resident CI fixture module
#   shamiko   Magisk + Zygisk + fixture + Shamiko, app on the denylist
#
# Rooting follows Magisk's own CI (scripts/avd.sh + avd_patch.sh): patch the AVD
# ramdisk on a booted stock emulator, then cold-boot with -ramdisk.
#
# Env: API (34), IMG_TYPE (google_apis; must allow `adb root`), OUT (ci-out/<leg>),
#      BOOT_TIMEOUT (300), RUN_SECONDS (45)
set -euo pipefail

LEG="${1:?usage: avd-leg.sh <leg> <app.apk> [fixture.zip]}"
APK="$(realpath "${2:?missing app apk}")"
FIXTURE="${3:-}"
[ -n "$FIXTURE" ] && FIXTURE="$(realpath "$FIXTURE")"

API="${API:-34}"
IMG_TYPE="${IMG_TYPE:-google_apis}"
ARCH=x86_64
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"
RUN_SECONDS="${RUN_SECONDS:-45}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(realpath -m "${OUT:-$ROOT_DIR/ci-out/$LEG}")"
DL="$OUT/downloads"
PKG=com.example.securitysample
AVD_NAME=sra_ci
PORT=5682
export ANDROID_SERIAL="emulator-$PORT"

: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-}}"
[ -n "$ANDROID_HOME" ] || { echo "ANDROID_HOME not set" >&2; exit 1; }
export ANDROID_USER_HOME="$HOME/.android" ANDROID_EMULATOR_HOME="$HOME/.android" ANDROID_AVD_HOME="$HOME/.android/avd"
export PATH="$ANDROID_HOME/platform-tools:$PATH"
SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
AVDMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager"
EMULATOR="$ANDROID_HOME/emulator/emulator"
IMG_PKG="system-images;android-$API;$IMG_TYPE;$ARCH"
RAMDISK="$ANDROID_HOME/system-images/android-$API/$IMG_TYPE/$ARCH/ramdisk.img"

cores=$(nproc 2>/dev/null || echo 4); [ "$cores" -gt 8 ] && cores=8
EMU_ARGS=(-no-window -no-audio -no-boot-anim -gpu software -read-only -no-snapshot
          -memory 4096 -cores "$cores" -port "$PORT")
EMU_PID=

mkdir -p "$OUT" "$DL"
log() { echo -e "\n\033[44;39m[$LEG] $*\033[0m"; }
die() { echo -e "\n\033[41;39m[$LEG] $*\033[0m" >&2; exit 1; }

cleanup() {
  if [ -n "$EMU_PID" ] && kill -0 "$EMU_PID" 2>/dev/null; then
    adb emu kill >/dev/null 2>&1 || true
    sleep 3
    kill "$EMU_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ── artifacts ───────────────────────────────────────────────────────────────
fetch() {  # fetch <name> -> prints local path; verifies sha256 from ci/artifacts.lock
  local name=$1 url sha dest
  read -r _ url sha < <(grep -E "^$name[[:space:]]" "$ROOT_DIR/ci/artifacts.lock") || die "no lock entry: $name"
  dest="$DL/$name.$(basename "$url" | sed 's/.*\.//')"
  [ -f "$dest" ] || curl -fsSL --retry 3 -o "$dest" "$url"
  echo "$sha  $dest" | sha256sum -c --quiet - >&2 || die "sha256 mismatch for $name ($url)"
  echo "$dest"
}

# ── emulator lifecycle ──────────────────────────────────────────────────────
setup_avd() {
  log "SDK: $IMG_PKG"
  yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
  "$SDKMANAGER" --install emulator platform-tools "$IMG_PKG" >/dev/null
  echo no | "$AVDMANAGER" create avd -f -n "$AVD_NAME" -k "$IMG_PKG" >/dev/null
}

wait_boot() {
  local t=0
  adb wait-for-device
  until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
    [ -n "$EMU_PID" ] && ! kill -0 "$EMU_PID" 2>/dev/null && die "emulator died (see $OUT/emulator-*.log)"
    [ $t -ge "$BOOT_TIMEOUT" ] && die "boot timeout after ${BOOT_TIMEOUT}s"
    sleep 3; t=$((t + 3))
  done
  adb shell 'while [ "$(getprop init.svc.bootanim)" = running ]; do sleep 1; done' || true
  sleep 5
}

start_emu() {  # start_emu <tag> [extra args...]
  local tag=$1; shift
  log "Booting emulator ($tag)"
  "$EMULATOR" "@$AVD_NAME" "${EMU_ARGS[@]}" "$@" > "$OUT/emulator-$tag.log" 2>&1 &
  EMU_PID=$!
  wait_boot
}

stop_emu() {
  adb emu kill >/dev/null 2>&1 || true
  wait "$EMU_PID" 2>/dev/null || true
  EMU_PID=
}

adb_root() {
  adb root >/dev/null 2>&1 || true
  sleep 2
  adb wait-for-device
  [ "$(adb shell id -u | tr -d '\r')" = 0 ] || die "adb root unavailable; IMG_TYPE=$IMG_TYPE must be a userdebug image"
}

# Run a script as root through Magisk's su (u:r:magisk:s0), so SELinux never blocks it.
msu() {  # msu <<'EOF' ... EOF
  local f
  f=$(mktemp)
  { echo 'export PATH=/debug_ramdisk:/data/adb/magisk:$PATH'; cat; } > "$f"
  adb push "$f" /data/local/tmp/ci_step.sh >/dev/null
  rm -f "$f"
  adb shell '/debug_ramdisk/su -c "sh /data/local/tmp/ci_step.sh"'
}

# ── Magisk ──────────────────────────────────────────────────────────────────
extract_magisk_bins() {  # extract_magisk_bins <apk> <dir>
  local apk=$1 dir=$2
  rm -rf "$dir"; mkdir -p "$dir"
  for lib in magisk magiskinit magiskboot magiskpolicy busybox init-ld; do
    unzip -p "$apk" "lib/$ARCH/lib$lib.so" > "$dir/$lib"
  done
  for sh in util_functions.sh boot_patch.sh addon.d.sh; do
    unzip -p "$apk" "assets/$sh" > "$dir/$sh"
  done
  chmod 755 "$dir"/*
}

patch_ramdisk() {
  local apk patch bins
  apk=$(fetch magisk_apk); patch=$(fetch magisk_avd_patch)
  bins="$OUT/magisk-bins"; extract_magisk_bins "$apk" "$bins"

  start_emu stock
  log "Patching ramdisk with Magisk (avd_patch.sh)"
  adb shell 'rm -rf /data/local/tmp/*'
  adb push "$bins/magisk" "$bins/magiskinit" "$bins/magiskboot" "$bins/busybox" "$bins/init-ld" \
           "$patch" "$RAMDISK" /data/local/tmp/ >/dev/null
  adb shell "mv /data/local/tmp/$(basename "$patch") /data/local/tmp/avd_patch.sh"
  adb shell sh /data/local/tmp/avd_patch.sh /data/local/tmp/ramdisk.img
  adb pull /data/local/tmp/ramdisk.img.magisk "$OUT/magisk-ramdisk.img" >/dev/null
  stop_emu
}

setup_magisk_env() {
  # Equivalent of the Magisk app's "additional setup" (fix_env in app_functions.sh):
  # module installers source /data/adb/magisk/util_functions.sh.
  log "Populating /data/adb/magisk"
  adb shell 'rm -rf /data/local/tmp/magisk-bins'
  adb push "$OUT/magisk-bins" /data/local/tmp/ >/dev/null
  msu <<'EOF'
set -e
rm -rf /data/adb/magisk && mkdir -p /data/adb/magisk
chmod 700 /data/adb
cp -af /data/local/tmp/magisk-bins/. /data/adb/magisk/
chmod -R 755 /data/adb/magisk
chown -R 0:0 /data/adb/magisk
EOF
}

install_module() {  # install_module <zip>
  log "Installing module $(basename "$1")"
  adb push "$1" /data/local/tmp/module.zip >/dev/null
  msu <<'EOF'
magisk --install-module /data/local/tmp/module.zip
EOF
}

# ── collection ──────────────────────────────────────────────────────────────
collect_state() {
  msu > "$OUT/root-state.txt" 2>&1 <<EOF || true
echo "== magisk"; magisk -v; magisk -V
echo "== zygisk"; magisk --sqlite "SELECT key,value FROM settings WHERE key='zygisk'"
echo "== modules"; ls -la /data/adb/modules
echo "== denylist"; magisk --denylist status; magisk --denylist ls
echo "== zygiskd"; ps -A | grep -i zygisk
EOF
}

run_app() {
  log "Running app for ${RUN_SECONDS}s"
  adb logcat -c
  adb shell am start -W -n "$PKG/.MainActivity" >/dev/null
  sleep "$RUN_SECONDS"

  adb logcat -d -v threadtime > "$OUT/logcat.txt" || true
  adb logcat -d -s SecurityCheckCI:I -v raw > "$OUT/results.txt" || true

  # Ground truth: the kernel's view of each app process (read as root).
  local pid name
  for name in "$PKG" "$PKG:security_isolated"; do
    pid=$(adb shell "pidof $name" | tr -d '\r' | awk '{print $1}')
    [ -n "$pid" ] || continue
    adb shell "cat /proc/$pid/maps" > "$OUT/maps-${name//:/_}.txt" 2>/dev/null || true
    adb shell "cat /proc/$pid/smaps" > "$OUT/smaps-${name//:/_}.txt" 2>/dev/null || true
  done
  adb shell am force-stop "$PKG" || true
}

# ── legs ────────────────────────────────────────────────────────────────────
setup_avd
use_magisk=true; zygisk=0; modules=(); denylist=false
case "$LEG" in
  baseline) use_magisk=false ;;
  magisk)   ;;
  zygisk)   zygisk=1; modules=("$FIXTURE") ;;
  shamiko)  zygisk=1; modules=("$FIXTURE" "$(fetch shamiko_zip)"); denylist=true ;;
  *) die "unknown leg: $LEG" ;;
esac
if [ "$zygisk" = 1 ] && [ -z "$FIXTURE" ]; then die "leg $LEG needs the fixture zip"; fi

if $use_magisk; then
  patch_ramdisk
  start_emu magisk -ramdisk "$OUT/magisk-ramdisk.img" -feature -SystemAsRoot
  adb_root
  adb shell 'PATH=$PATH:/debug_ramdisk magisk -v' || die "Magisk not active after ramdisk boot"
  setup_magisk_env
  adb install -r -g "$APK" >/dev/null
  msu <<EOF
magisk --sqlite "REPLACE INTO settings (key,value) VALUES('zygisk',$zygisk)"
EOF
  for m in "${modules[@]}"; do install_module "$m"; done
  if $denylist; then
    # Shamiko reads the denylist but requires enforcement to stay OFF.
    msu <<EOF || true
magisk --denylist disable
magisk --denylist add $PKG
magisk --denylist add $PKG ${PKG}_zygote
magisk --denylist add isolated $PKG:security_isolated
EOF
  fi
  log "Rebooting to apply Zygisk/modules"
  adb reboot
  wait_boot
  adb_root
  collect_state
else
  start_emu stock
  adb_root
  adb install -r -g "$APK" >/dev/null
fi

run_app
stop_emu

log "Checking expectations"
python3 -I "$ROOT_DIR/ci/check-results.py" "$LEG" "$OUT" "$ROOT_DIR/ci/expectations/$LEG.txt"
