#!/system/bin/sh

MODDIR=${0%/*}

if [ -f "$MODDIR/bin/zygisk-ptrace64" ]; then
  TRACER="$MODDIR/bin/zygisk-ptrace64"
elif [ -f "$MODDIR/bin/zygisk-ptrace32" ]; then
  TRACER="$MODDIR/bin/zygisk-ptrace32"
else
  exit 0
fi

# Only one process may trace init, so the monitor that the replayed post-fs-data starts
# cannot seize it until this one is gone. Releasing the control socket is not enough: the
# ptrace attachment outlives it until the process dies, which is also when the daemon
# follows through PR_SET_PDEATHSIG.
if "$TRACER" ctl exit >/dev/null 2>&1; then
  waited=0
  while [ "$(pidof "${TRACER##*/}")" ] && [ "$waited" -lt 10 ]; do
    sleep 1
    waited=$((waited + 1))
  done
fi
