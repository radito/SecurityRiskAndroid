#!/usr/bin/env bash
# Build the CI fixture Zygisk module zip with the NDK.
# Usage: ci/fixture/build.sh <out.zip>
# Needs ANDROID_NDK_HOME (or ANDROID_NDK_LATEST_HOME, set on GitHub runners).
set -euo pipefail

out="$(realpath -m "${1:?usage: build.sh <out.zip>}")"
mkdir -p "$(dirname "$out")"
here="$(cd "$(dirname "$0")" && pwd)"
ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_LATEST_HOME:-}}"
[ -n "$ndk" ] || { echo "ANDROID_NDK_HOME not set" >&2; exit 1; }

host_tag=linux-x86_64
[ "$(uname -s)" = Darwin ] && host_tag=darwin-x86_64
bin="$ndk/toolchains/llvm/prebuilt/$host_tag/bin"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/zygisk"

declare -A targets=(
  [x86_64]=x86_64-linux-android26
  [arm64-v8a]=aarch64-linux-android26
)
for abi in "${!targets[@]}"; do
  "$bin/clang" --target="${targets[$abi]}" -shared -fPIC -O2 -fvisibility=hidden \
    -Wl,-soname,libcifixture.so -o "$work/zygisk/$abi.so" "$here/zygisk_fixture.c"
done

cat > "$work/module.prop" <<'EOF'
id=ci_zygisk_fixture
name=CI Zygisk Fixture
version=1
versionCode=1
author=SecurityRiskAndroid CI
description=No-op resident Zygisk module used as a hiding target in CI.
EOF

mkdir -p "$work/META-INF/com/google/android"
echo '#MAGISK' > "$work/META-INF/com/google/android/updater-script"
# Standard Magisk module installer stub (same as Magisk's module_installer.sh).
cat > "$work/META-INF/com/google/android/update-binary" <<'EOF'
#!/sbin/sh
umask 022
ui_print() { echo "$1"; }
OUTFD=$2
ZIPFILE=$3
mount /data 2>/dev/null
[ -f /data/adb/magisk/util_functions.sh ] || { ui_print "! Magisk env missing"; exit 1; }
. /data/adb/magisk/util_functions.sh
install_module
exit 0
EOF

rm -f "$out"
(cd "$work" && zip -qr "$out" module.prop zygisk META-INF)
echo "built $out"
