#!/system/bin/sh

DEBUG=@DEBUG@

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ] && [ -z "$KSU$APATCH" ] && command -v magisk >/dev/null 2>&1; then
  exit 0
fi

cd "$MODDIR" || exit 1

if [ -f "$MODDIR/spoof-props.sh" ]; then
  sh "$MODDIR/spoof-props.sh" late
fi

# ksud and apd run every enabled module's service.sh themselves, and announce themselves
# through KSU and APATCH. Magisk runs only those of the modules it mounts, which leaves out
# the Zygisk-only ones, and a build with no root framework runs none at all, so fan out
# whenever nothing else will. Late-start injection is not handled here: it belongs to
# post-mount.sh, which runs at the one point where the module set is final and mounted.
if [ -z "$KSU$APATCH" ]; then
  SELF_NAME=${MODDIR##*/}
  for file in ../*; do
    [ "${file##*/}" = "$SELF_NAME" ] && continue
    if [ -d "$file" ] && [ -d "$file/zygisk" ] && ! [ -f "$file/disable" ] && ! [ -f "$file/remove" ]; then
      if [ -f "$file/service.sh" ]; then
        log -p i -t "zygisk-sh" "Manually trigger service.sh for $file"
        (
          cd "$file" && sh "$(realpath ./service.sh)"
        ) &
      fi
    fi
  done
fi
