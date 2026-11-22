#!/system/bin/sh
MODDIR=${0%/*}
if [ -x "$MODDIR/bin/zygisk-ptrace64" ]; then
  exec "$MODDIR/bin/zygisk-ptrace64" stage service "$@"
elif [ -x "$MODDIR/bin/zygisk-ptrace32" ]; then
  exec "$MODDIR/bin/zygisk-ptrace32" stage service "$@"
fi
exit 0
