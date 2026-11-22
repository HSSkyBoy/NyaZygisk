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
TRACER_NAME="${TRACER##*/}"
"$TRACER" ctl exit >/dev/null 2>&1 || true

other_tracers() {
  for pid in $(pidof "$TRACER_NAME"); do
    [ "$pid" = "$$" ] || [ "$pid" = "$PPID" ] && continue
    echo "$pid"
  done
}

waited=0
while [ -n "$(other_tracers)" ] && [ "$waited" -lt 20 ]; do
  sleep 0.2 2>/dev/null || sleep 1
  waited=$((waited + 1))
done

# Fallback if the control socket was unreachable or the monitor hung: terminate only
# tracer processes running from our own module directory (or a stashed hot-install copy).
if [ -n "$(other_tracers)" ]; then
  for pid in $(other_tracers); do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    case "$exe" in
      "$MODDIR/bin/"*|*"/hot_install_trash/"*"/bin/$TRACER_NAME"*)
        kill -TERM "$pid" 2>/dev/null || true
        ;;
    esac
  done
  sleep 0.5
  for pid in $(other_tracers); do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    case "$exe" in
      "$MODDIR/bin/"*|*"/hot_install_trash/"*"/bin/$TRACER_NAME"*)
        kill -KILL "$pid" 2>/dev/null || true
        ;;
    esac
  done
fi
