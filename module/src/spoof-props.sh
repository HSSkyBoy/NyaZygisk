#!/system/bin/sh

TMP_PATH=@WORK_DIRECTORY@
SPOOF_FILE="$TMP_PATH/spoof.prop"
STAGE="${1:-early}"

if [ ! -f "$SPOOF_FILE" ]; then
  exit 0
fi

if command -v resetprop >/dev/null 2>&1; then
  run_resetprop_n() { resetprop -n "$1" "$2"; }
elif [ -x /data/adb/ksu/bin/resetprop ]; then
  run_resetprop_n() { /data/adb/ksu/bin/resetprop -n "$1" "$2"; }
elif [ -x /data/adb/ap/bin/resetprop ]; then
  run_resetprop_n() { /data/adb/ap/bin/resetprop -n "$1" "$2"; }
elif [ -x /data/adb/magisk/magisk ]; then
  run_resetprop_n() { /data/adb/magisk/magisk resetprop -n "$1" "$2"; }
else
  log -p w -t "zygisk-sh" "spoof-props: resetprop not found, skipping ($STAGE)"
  exit 0
fi

# Defer debug/build properties to service.sh so early-boot adbd is never blocked on userdebug ROMs.
is_late_prop() {
  case "$1" in
    ro.debuggable|ro.force.debuggable|ro.secure|ro.adb.secure|ro.build.type|ro.build.tags|sys.oem_unlock_allowed)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

CR=$(printf '\r')
has_vbmeta_digest=false
has_entries=false

while IFS= read -r line || [ -n "$line" ]; do
  line=${line%"$CR"}
  line="${line#"${line%%[![:space:]]*}"}"
  case "$line" in
    ""|\#*) continue ;;
    *=*) ;;
    *) continue ;;
  esac

  key=${line%%=*}
  val=${line#*=}
  key="${key%"${key##*[![:space:]]}"}"
  val="${val#"${val%%[![:space:]]*}"}"
  val="${val%"${val##*[![:space:]]}"}"
  [ -n "$key" ] || continue

  has_entries=true
  [ "$key" = "ro.boot.vbmeta.digest" ] && has_vbmeta_digest=true

  if [ "$STAGE" = "late" ]; then
    if is_late_prop "$key"; then
      run_resetprop_n "$key" "$val"
    fi
  else
    if ! is_late_prop "$key"; then
      run_resetprop_n "$key" "$val"
    fi
  fi
done < "$SPOOF_FILE"

if [ "$STAGE" != "late" ] && [ "$has_entries" = true ] && [ "$has_vbmeta_digest" = false ]; then
  if [ -r /dev/urandom ]; then
    digest=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 | tr -d ' \t\n')
    if [ "${#digest}" -eq 64 ]; then
      run_resetprop_n "ro.boot.vbmeta.digest" "$digest"
    fi
  fi
fi
