#!/system/bin/sh
# ZYN BOOSTER v26 — boot readiness + re-apply last verified profile.
MODDIR=${0%/*}
STATE="$MODDIR/state"
LOGDIR="$MODDIR/logs"
mkdir -p "$STATE" "$LOGDIR"
chmod 0755 "$MODDIR" "$STATE" "$LOGDIR" 2>/dev/null
log() { printf '%s | %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$*" >> "$LOGDIR/engine.log"; }
log "ZYN BOOSTER v26 service started"
if [ "${AXERON:-false}" = "true" ]; then manager="AxManager"; else manager="Magisk/KernelSU"; fi
log "Manager: $manager"
log "Device: $(getprop ro.product.manufacturer) $(getprop ro.product.model)"
log "Android: $(getprop ro.build.version.release) / SDK $(getprop ro.build.version.sdk)"
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 60 ]; do
  sleep 2
  i=$((i + 1))
done
if [ "$(getprop sys.boot_completed)" = "1" ]; then
  printf 'ready\n' > "$STATE/status"
  if [ -r "$STATE/active_profile" ]; then
    IFS='|' read -r profile pkg refresh animation fps_target features < "$STATE/active_profile"
    case "$profile" in saver|balanced|gaming)
      case "$pkg" in *[!A-Za-z0-9_.]*|.*|*.) pkg="" ;; esac
      case "$refresh" in ''|60|90|120|144|165) ;; *) refresh="" ;; esac
      case "$animation" in ''|*[!0-9.]*|.*|*.) animation="" ;; esac
      log "Re-applying saved profile=$profile package=$pkg refresh=$refresh animation=$animation"
      sh "$MODDIR/optimize.sh" "$profile" "$pkg" "$refresh" "$animation" "$fps_target" "$features" >> "$LOGDIR/engine.log" 2>&1
      log "Saved profile re-apply exit=$?"
      ;;
      *) log "Saved profile file invalid; skipped" ;;
    esac
  else
    log "No saved profile; leaving Android settings unchanged"
  fi
  log "Boot complete; ready"
else
  printf 'boot_timeout\n' > "$STATE/status"
  log "Boot wait timed out; no tuning applied"
fi
exit 0
