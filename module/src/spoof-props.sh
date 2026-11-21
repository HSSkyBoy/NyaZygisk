#!/system/bin/sh

TMP_PATH=@WORK_DIRECTORY@
SPOOF_FILE="$TMP_PATH/spoof.prop"
STAGE="${1:-early}"

if [ ! -f "$SPOOF_FILE" ]; then
  exit 0
fi

if command -v resetprop >/dev/null 2>&1; then
  run_resetprop_get() { resetprop "$1" 2>/dev/null; }
  run_resetprop_n() { resetprop -n "$1" "$2"; }
elif [ -x /data/adb/ksu/bin/resetprop ]; then
  run_resetprop_get() { /data/adb/ksu/bin/resetprop "$1" 2>/dev/null; }
  run_resetprop_n() { /data/adb/ksu/bin/resetprop -n "$1" "$2"; }
elif [ -x /data/adb/ap/bin/resetprop ]; then
  run_resetprop_get() { /data/adb/ap/bin/resetprop "$1" 2>/dev/null; }
  run_resetprop_n() { /data/adb/ap/bin/resetprop -n "$1" "$2"; }
elif [ -x /data/adb/magisk/magisk ]; then
  run_resetprop_get() { /data/adb/magisk/magisk resetprop "$1" 2>/dev/null; }
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

# OEM-specific bootloader/warranty properties and optional debug overrides:
# rewrite only when the property already exists on the ROM so foreign vendor keys
# (Samsung warranty_bit, Realme, OPlus, MIUI) are never fabricated and absent
# optional keys (ro.force.debuggable on user builds) do not touch prop mtime.
is_existing_only_prop() {
  case "$1" in
    ro.boot.warranty_bit|ro.warranty_bit|ro.vendor.boot.warranty_bit|ro.vendor.warranty_bit|vendor.boot.warranty_bit|vendor.warranty_bit|\
    ro.secureboot.lockstate|\
    ro.boot.realmebootstate|ro.boot.realme.lockstate|ro.boot.realme.flash.locked|\
    ro.is_ever_orange|ro.boot.is_ever_orange|ro.boot.hw.is_ever_orange|ro.boot.orange.state|\
    ro.force.debuggable)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

# VBMeta metadata that varies legitimately across Android/AVB releases (e.g. AVB 1.3
# or larger partition sizes): fill in only when missing, empty, or zero.
is_fallback_vbmeta_prop() {
  case "$1" in
    ro.boot.vbmeta.size|ro.boot.vbmeta.avb_version)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_valid_vbmeta_digest() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in
    *[!0-9a-fA-F]*) return 1 ;;
    *[!0]*) return 0 ;;
    *) return 1 ;;
  esac
}

apply_prop() {
  p_key="$1"
  p_val="$2"

  if is_existing_only_prop "$p_key"; then
    cur=$(run_resetprop_get "$p_key") || return 0
    [ "$cur" = "$p_val" ] && return 0
    run_resetprop_n "$p_key" "$p_val"
    return 0
  fi

  if is_fallback_vbmeta_prop "$p_key"; then
    cur_exists=false
    if cur=$(run_resetprop_get "$p_key"); then
      cur_exists=true
      case "$cur" in
        ""|0|0.0) ;;
        *) return 0 ;;
      esac
    fi
    if [ "$p_key" = "ro.boot.vbmeta.avb_version" ]; then
      if boot_avb=$(run_resetprop_get "ro.boot.avb_version"); then
        case "$boot_avb" in
          ""|0|0.0) ;;
          *) p_val="$boot_avb" ;;
        esac
      fi
    fi
    if [ "$cur_exists" = true ] && [ "$cur" = "$p_val" ]; then
      return 0
    fi
    run_resetprop_n "$p_key" "$p_val"
    return 0
  fi

  if cur=$(run_resetprop_get "$p_key") && [ "$cur" = "$p_val" ]; then
    return 0
  fi
  run_resetprop_n "$p_key" "$p_val"
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
  case "$key" in
    ""|-*) continue ;;
  esac

  has_entries=true
  [ "$key" = "ro.boot.vbmeta.digest" ] && has_vbmeta_digest=true

  if [ "$STAGE" = "late" ]; then
    if is_late_prop "$key"; then
      apply_prop "$key" "$val"
    fi
  else
    if ! is_late_prop "$key"; then
      apply_prop "$key" "$val"
    fi
  fi
done < "$SPOOF_FILE"

if [ "$STAGE" != "late" ] && [ "$has_entries" = true ] && [ "$has_vbmeta_digest" = false ]; then
  cur_digest=$(run_resetprop_get "ro.boot.vbmeta.digest" || true)
  if ! is_valid_vbmeta_digest "$cur_digest" && [ -r /dev/urandom ]; then
    digest=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 | tr -d ' \t\n')
    if is_valid_vbmeta_digest "$digest"; then
      run_resetprop_n "ro.boot.vbmeta.digest" "$digest"
    fi
  fi
fi
