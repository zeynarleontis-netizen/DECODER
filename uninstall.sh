#!/system/bin/sh
# Restore only values captured by ZYN BOOSTER; do not invent factory defaults.
MODDIR=${0%/*}
"$MODDIR/optimize.sh" restore
rc=$?
if [ "$rc" -eq 0 ]; then
  rm -rf "$MODDIR/state" "$MODDIR/logs"
  echo "ZYN BOOSTER settings restored where originals were readable."
else
  echo "WARNING: some settings could not be restored. Check the module log before removal."
fi
exit "$rc"
