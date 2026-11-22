#!/system/bin/sh
MODDIR=${0%/*}
if [ -x "$MODDIR/bin/zygisk-ptrace64" ]; then
  exec "$MODDIR/bin/zygisk-ptrace64" stage hotinstall "$@"
elif [ -x "$MODDIR/bin/zygisk-ptrace32" ]; then
  exec "$MODDIR/bin/zygisk-ptrace32" stage hotinstall "$@"
fi
exit 0
