#!/system/bin/sh

# KernelSU runs this once it has replaced the module directory with the version just
# installed, so MODDIR is the new NyaZygisk while the monitor from the last boot is still
# tracing init with binaries that are no longer on disk.
#
# A hot install re-runs no boot stage, so without this nothing would ever start the new
# monitor. Replacing it is only half an update: zygote and every app forked from it still
# have the previous libzygisk.so mapped, and a mapped library cannot be swapped under a
# running process. The injector therefore changes only when zygote restarts.
# The new monitor is armed and running processes stay undisturbed; the new
# injector is picked up whenever zygote next restarts.

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ]; then
  exit 0
fi

if [ -f "$MODDIR/disable" ]; then
  exit 0
fi

if [ -f "$MODDIR/bin/zygisk-ptrace64" ]; then
  TRACER="$MODDIR/bin/zygisk-ptrace64"
elif [ -f "$MODDIR/bin/zygisk-ptrace32" ]; then
  TRACER="$MODDIR/bin/zygisk-ptrace32"
else
  echo "- No tracer binary found, NyaZygisk will start on the next boot"
  exit 1
fi

# Only one process may trace init, so the new monitor cannot seize it until the old one
# has exited. Releasing the control socket is not enough: the ptrace attachment outlives
# it until the process dies, which is also when the daemon follows through PR_SET_PDEATHSIG.
if "$TRACER" ctl exit >/dev/null 2>&1; then
  echo "- Stopping the previous monitor"
  waited=0
  while [ "$(pidof "${TRACER##*/}")" ] && [ "$waited" -lt 10 ]; do
    sleep 1
    waited=$((waited + 1))
  done
fi

# Unconditional, as everywhere else: a monitor that finds the control socket still owned
# stands down by itself, which is the only sane answer if the wait above timed out. The
# output goes nowhere because the installer reads this script's pipe until it closes, and
# a backgrounded monitor would hold it open for the rest of the session.
echo "- Starting the new monitor"
. "$MODDIR/zygisk-init.sh" </dev/null >/dev/null 2>&1

# This is the handshake that makes the restart below safe, not a request to inject
# anything. The monitor binds its control socket only once it has seized init, so a command
# reaching it proves the zygote spawned below cannot be missed. Rearm is the one to send
# because it is also what starts the daemon, and because it is harmless either way: it is
# asynchronous, so by the time it looks for a zygote the one below is usually already
# stopped, and it then attaches nothing. The module set that was just installed is picked up
# by the ZygoteRestart the new zygote reports a moment later.
if ! "$TRACER" ctl rearm; then
  echo "! The new monitor did not answer, NyaZygisk will start on the next boot"
  exit 1
fi

# The monitor is armed, so the next zygote to start carries the new injector while the
# one running now keeps the old one.
echo "- The new monitor is armed; zygote keeps the running injector until it restarts"
