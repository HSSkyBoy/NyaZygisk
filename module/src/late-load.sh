#!/system/bin/sh
MODDIR=${0%/*}
if [ -x "$MODDIR/bin/zygisk-ptrace64" ]; then
  exec "$MODDIR/bin/zygisk-ptrace64" stage late-load "$@"
elif [ -x "$MODDIR/bin/zygisk-ptrace32" ]; then
  exec "$MODDIR/bin/zygisk-ptrace32" stage late-load "$@"
fi
exit 0
