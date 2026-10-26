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

cd "$MODDIR"

if [ "$(which magisk)" ]; then
  for file in ../*; do
    if [ -d "$file" ] && [ -d "$file/zygisk" ] && ! [ -f "$file/disable" ]; then
      if [ -f "$file/post-fs-data.sh" ]; then
        cd "$file"
        log -p i -t "zygisk-sh" "Manually trigger post-fs-data.sh for $file"
        # INFO: Don't propagate errexit
        set +e

        sh "$(realpath ./post-fs-data.sh)"

        # INFO: Re-enable errexit
        set -e

        cd "$MODDIR"
      fi
    fi
  done
fi

. "$MODDIR/zygisk-init.sh"

