#!/system/bin/sh

# Early-boot bootstrap: stage the work directory and start the monitor, which then waits
# for init to fork zygote and injects it as it spawns.
#
# This script is also the shared bootstrap for the late-load path: late-load.sh sources it
# on a system that is already up. It must therefore be safe to run while a previous monitor
# and its injected processes are alive, which rules out recreating the work directory from
# scratch -- the live control socket and the mapped libzygisk.so both live in it.

DEBUG=@DEBUG@

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ]; then
  exit 0
fi

cd "$MODDIR" || exit 1

. "$MODDIR/zygisk-init.sh" </dev/null >/dev/null 2>&1

if command -v magisk >/dev/null 2>&1; then
  SELF_NAME=${MODDIR##*/}
  for file in ../*; do
    [ "${file##*/}" = "$SELF_NAME" ] && continue
    if [ -d "$file" ] && [ -d "$file/zygisk" ] && ! [ -f "$file/disable" ] && ! [ -f "$file/remove" ]; then
      if [ -f "$file/post-fs-data.sh" ]; then
        log -p i -t "zygisk-sh" "Manually trigger post-fs-data.sh for $file"
        (
          cd "$file" && sh "$(realpath ./post-fs-data.sh)"
        )
      fi
    fi
  done
fi
