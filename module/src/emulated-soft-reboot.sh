#!/system/bin/sh

MODDIR=${0%/*}

if [ -f $MODDIR/bin/zygisk-ptrace64 ]; then
  $MODDIR/bin/zygisk-ptrace64 ctl exit
elif [ -f $MODDIR/bin/zygisk-ptrace32 ]; then
  $MODDIR/bin/zygisk-ptrace32 ctl exit
fi
