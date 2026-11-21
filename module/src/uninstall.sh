#!/system/bin/sh

export TMP_PATH="@WORK_DIRECTORY@"

[ -n "$TMP_PATH" ] && rm -rf -- "$TMP_PATH"
rm -rf /data/system/nyazygisk /data/adb/nyazygisk
