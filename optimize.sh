#!/system/bin/sh
# ZYN BOOSTER v26 TITAN X PRO — supported, read-back-verified Android tuning.
# No thermal overrides, kernel frequency writes, or undocumented sysfs writes.
MODDIR=${0%/*}
STATE="$MODDIR/state"
LOGDIR="$MODDIR/logs"
LOG="$LOGDIR/engine.log"
mkdir -p "$STATE" "$LOGDIR"

log() { printf '%s | %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$*" >> "$LOG"; }
valid_pkg() {
  case "$1" in
    ''|*[!A-Za-z0-9_.]*|.*|*.) return 1 ;;
    *.*) return 0 ;;
    *) return 1 ;;
  esac
}
valid_scale() {
  case "$1" in ''|*[!0-9.]*|.*|*.) return 1 ;; esac
  case "$1" in *.*.*) return 1 ;; esac
  return 0
}
valid_refresh() {
  case "$1" in 60|90|120|144|165) return 0 ;; *) return 1 ;; esac
}
save_setting_once() {
  namespace="$1"; key="$2"; file="$STATE/original_${namespace}_${key}"
  [ -f "$file" ] && return 0
  value="$(settings get "$namespace" "$key" 2>/dev/null | tr -d '\r\n')"
  [ -n "$value" ] || value="__ZYN_NULL__"
  [ "$value" = "null" ] && value="__ZYN_NULL__"
  printf '%s\n' "$value" > "$file"
}
restore_setting() {
  namespace="$1"; key="$2"; file="$STATE/original_${namespace}_${key}"
  [ -f "$file" ] || return 0
  value="$(cat "$file" 2>/dev/null | tr -d '\r\n')"
  if [ "$value" = "__ZYN_NULL__" ]; then
    settings delete "$namespace" "$key" >/dev/null 2>&1
  else
    settings put "$namespace" "$key" "$value" >/dev/null 2>&1
  fi
  actual="$(settings get "$namespace" "$key" 2>/dev/null | tr -d '\r\n')"
  if [ "$value" = "__ZYN_NULL__" ]; then
    [ "$actual" = "null" ] || [ -z "$actual" ]
  else
    [ "$actual" = "$value" ]
  fi
}
capture_animation() {
  for key in window_animation_scale transition_animation_scale animator_duration_scale; do
    save_setting_once global "$key"
  done
}
apply_animation() {
  scale="$1"; failed=0
  for key in window_animation_scale transition_animation_scale animator_duration_scale; do
    settings put global "$key" "$scale" >/dev/null 2>&1
    actual="$(settings get global "$key" 2>/dev/null | tr -d '\r\n')"
    if [ "$actual" != "$scale" ]; then
      failed=$((failed + 1)); log "Animation setting readback mismatch: $key wanted=$scale got=$actual"
    fi
  done
  return "$failed"
}
supported_refresh() {
  target="$1"
  dumpsys display 2>/dev/null | awk -v target="$target" '
    {
      line=$0
      while (match(line, /refreshRate[=:][[:space:]]*[0-9]+([.][0-9]+)?/)) {
        token=substr(line,RSTART,RLENGTH)
        sub(/^.*[=:][[:space:]]*/,"",token)
        delta=(token+0)-(target+0); if(delta<0)delta=-delta
        if (delta < 1.0) found=1
        line=substr(line,RSTART+RLENGTH)
      }
    }
    END { exit(found ? 0 : 1) }
  '
}
apply_refresh() {
  target="$1"
  [ -n "$target" ] || return 0
  if ! valid_refresh "$target"; then
    echo "Unsupported refresh target. Choose 60, 90, 120, 144 or 165."
    return 2
  fi
  if ! supported_refresh "$target"; then
    echo "Display does not report ${target}Hz as a supported mode; refresh setting left unchanged."
    log "Refresh skipped: ${target}Hz not listed by dumpsys display"
    return 0
  fi
  save_setting_once system peak_refresh_rate
  settings put system peak_refresh_rate "$target" >/dev/null 2>&1
  actual="$(settings get system peak_refresh_rate 2>/dev/null | tr -d '\r\n')"
  if [ "$(awk -v a="$actual" -v b="$target" 'BEGIN{d=a-b;if(d<0)d=-d;print(d<0.6?1:0)}' 2>/dev/null)" = "1" ]; then
    echo "Display peak refresh configured to ${target}Hz (read-back verified)."
    log "peak_refresh_rate applied=$target readback=$actual"
    return 0
  fi
  echo "Android did not confirm ${target}Hz; original display setting retained/restored."
  log "Refresh readback failed wanted=$target got=$actual"
  restore_setting system peak_refresh_rate
  return 1
}
read_thermal_level() {
  raw="$(dumpsys thermalservice 2>/dev/null | grep -m 1 -i 'Thermal Status' | sed 's/.*:[[:space:]]*//' | sed 's/[[:space:]].*//')"
  case "$raw" in
    NONE|None|none) echo 0 ;;
    LIGHT|Light|light) echo 1 ;;
    MODERATE|Moderate|moderate) echo 2 ;;
    SEVERE|Severe|severe) echo 3 ;;
    CRITICAL|Critical|critical) echo 4 ;;
    EMERGENCY|Emergency|emergency) echo 5 ;;
    SHUTDOWN|Shutdown|shutdown) echo 6 ;;
    *) case "$raw" in 0|1|2|3|4|5|6) echo "$raw" ;; *) echo N/A ;; esac ;;
  esac
}
apply_game_mode() {
  pkg="$1"; desired="$2"
  [ -n "$pkg" ] || { echo "No app selected: per-app Android Game Mode skipped."; return 0; }
  case "$desired" in performance|battery) ;; *) echo "Invalid Game Mode request."; return 2 ;; esac
  valid_pkg "$pkg" || { echo "Invalid package name."; return 2; }
  if ! pm path "$pkg" >/dev/null 2>&1; then
    echo "Mapped game package $pkg is not installed; per-app Game Mode skipped."
    log "Game Mode skipped: package not installed: $pkg"
    return 0
  fi
  thermal="$(read_thermal_level)"
  if [ "$desired" = "performance" ]; then
    case "$thermal" in 3|4|5|6)
      echo "Thermal status is $thermal; performance Game Mode skipped to avoid adding heat."
      log "Game Mode performance skipped by thermal guard status=$thermal package=$pkg"
      return 0 ;;
    esac
  fi
  command -v cmd >/dev/null 2>&1 || { echo "Android cmd utility unavailable; Game Mode skipped."; return 0; }
  modes="$(cmd game list-modes "$pkg" 2>&1)"
  rc=$?
  if [ "$rc" -ne 0 ] || ! printf '%s\n' "$modes" | grep -qi 'current mode'; then
    echo "Per-app Game Mode query is not supported on this Android build; no Game Mode change made."
    log "Game Mode skipped: list-modes unsupported for $pkg"
    return 0
  fi
  current="$(printf '%s\n' "$modes" | sed -n 's/.*[Cc]urrent mode:[[:space:]]*\([A-Za-z0-9_-]*\).*/\1/p' | head -n 1 | tr 'A-Z' 'a-z')"
  if [ "$current" != "standard" ] && [ "$current" != "performance" ] && [ "$current" != "battery" ]; then
    echo "Current Game Mode ($current) is custom/unknown; left unchanged to protect existing app settings."
    log "Game Mode skipped: unrecognised existing mode '$current' for $pkg"
    return 0
  fi
  if ! printf '%s\n' "$modes" | grep -qi "$desired"; then
    echo "Selected app does not advertise Android $desired Game Mode; no change made."
    log "Game Mode skipped: $desired mode unsupported by $pkg"
    return 0
  fi
  safe_file="$(printf '%s' "$pkg" | tr '.' '_')"
  backup="$STATE/game_mode_${safe_file}"
  if [ ! -f "$backup" ]; then
    printf '%s\n%s\n' "$pkg" "$current" > "$backup"
  fi
  if [ "$current" = "$desired" ]; then
    echo "Android Game Mode already reports $desired for $pkg."
    return 0
  fi
  if cmd game mode "$desired" "$pkg" >/dev/null 2>&1; then
    check="$(cmd game list-modes "$pkg" 2>&1)"
    if printf '%s\n' "$check" | grep -qi "current mode:[[:space:]]*$desired"; then
      echo "Android Game Mode $desired applied and read-back verified for $pkg."
      log "Game Mode $desired applied to $pkg"
      return 0
    fi
  fi
  echo "Android refused or did not confirm $desired Game Mode for $pkg; other supported tuning remains applied."
  log "Game Mode apply not confirmed for $pkg"
  return 0
}
restore_game_modes() {
  failed=0
  for file in "$STATE"/game_mode_*; do
    [ -f "$file" ] || continue
    pkg="$(sed -n '1p' "$file")"
    old="$(sed -n '2p' "$file")"
    valid_pkg "$pkg" || { failed=$((failed+1)); continue; }
    case "$old" in standard|performance|battery)
      cmd game mode "$old" "$pkg" >/dev/null 2>&1 || failed=$((failed+1))
      check="$(cmd game list-modes "$pkg" 2>&1)"
      printf '%s\n' "$check" | grep -qi "current mode:[[:space:]]*$old" || failed=$((failed+1))
      ;;
      *) failed=$((failed+1)) ;;
    esac
    [ "$failed" -eq 0 ] && rm -f "$file"
  done
  return "$failed"
}
restore_all() {
  failed=0
  restore_game_modes || failed=$((failed+1))
  for key in window_animation_scale transition_animation_scale animator_duration_scale; do
    restore_setting global "$key" || failed=$((failed+1))
  done
  restore_setting system peak_refresh_rate || failed=$((failed+1))
  if [ "$failed" -eq 0 ]; then
    rm -f "$STATE"/original_global_* "$STATE"/original_system_peak_refresh_rate "$STATE"/backup_version "$STATE/active_profile"
    printf 'restored\n' > "$STATE/profile"
    echo "Saved original animation and display settings restored. Game Mode restore attempted for saved apps."
    log "Restore completed"
    return 0
  fi
  echo "Restore incomplete ($failed issue(s)); backups retained for retry. Check logs/engine.log."
  log "Restore incomplete failures=$failed"
  return 1
}

profile="${1:-balanced}"
pkg="${2:-}"
refresh="${3:-}"
animation="${4:-}"
fps_target="${5:-60}"
features="${6:-game_mode,refresh,animation,telemetry,frames,network,battery,storage,thermal}"
case "$fps_target" in 60|90|120|144|165) ;; *) echo "Invalid FPS target reference."; exit 2 ;; esac
case "$profile" in
  saver) scale="1.0"; game_mode="battery" ;;
  balanced) scale="1.0"; game_mode="standard" ;;
  gaming) scale="0.5"; game_mode="performance" ;;
  restore) restore_all; exit $? ;;
  *) echo "Usage: $0 {saver|balanced|gaming|restore} [package] [refresh] [animation-scale] [fps-target]"; exit 2 ;;
esac
if [ -n "$animation" ]; then
  if ! valid_scale "$animation" || [ "$(awk -v n="$animation" 'BEGIN{print(n>=0 && n<=10?1:0)}')" != "1" ]; then
    echo "Invalid animation scale. Choose a value from 0 to 10."
    exit 2
  fi
  scale="$animation"
fi

anim_rc=0
case ",$features," in *",animation,"*) capture_animation; apply_animation "$scale"; anim_rc=$? ;; *) echo "Animation tuning disabled in saved feature selection; left unchanged." ;; esac
printf '%s\n' "$profile" > "$STATE/profile"
printf '%s\n' "$(date '+%s' 2>/dev/null)" > "$STATE/last_apply"
failures=0
[ "$anim_rc" -eq 0 ] || failures=$((failures+1))

case ",$features," in *",refresh,"*) [ -n "$refresh" ] && { apply_refresh "$refresh" || failures=$((failures+1)); } ;; *) echo "Refresh tuning disabled in saved feature selection; left unchanged." ;; esac
case ",$features," in *",game_mode,"*) game_mode_enabled=1 ;; *) game_mode_enabled=0 ;; esac
# Resolve common regional package variants for supported games.
case "$pkg" in
  com.garena.game.codm) pm path "$pkg" >/dev/null 2>&1 || { pm path com.activision.callofduty.shooter >/dev/null 2>&1 && pkg=com.activision.callofduty.shooter; } ;;
  com.tencent.ig) pm path "$pkg" >/dev/null 2>&1 || { pm path com.pubg.imobile >/dev/null 2>&1 && pkg=com.pubg.imobile; } ;;
  com.dts.freefireth) pm path "$pkg" >/dev/null 2>&1 || { pm path com.dts.freefiremax >/dev/null 2>&1 && pkg=com.dts.freefiremax; } ;;
esac
if [ "$game_mode_enabled" -eq 1 ] && [ "$profile" = "gaming" ] && [ -n "$pkg" ]; then
  apply_game_mode "$pkg" performance || failures=$((failures+1))
elif [ "$game_mode_enabled" -eq 1 ] && [ "$profile" = "saver" ] && [ -n "$pkg" ]; then
  apply_game_mode "$pkg" battery || failures=$((failures+1))
elif [ "$game_mode_enabled" -eq 1 ] && [ "$profile" = "balanced" ]; then
  restore_game_modes || failures=$((failures+1))
fi
printf '%s\n' "$failures" > "$STATE/last_failures"
echo "TITAN profile: $profile"
echo "Animation scale: $scale (Android settings read-back checked)"
[ -n "$refresh" ] && echo "Requested display cap: ${refresh}Hz (only applied if panel reports support)"
[ -n "$pkg" ] && { [ "$profile" = "gaming" ] || [ "$profile" = "saver" ]; } && echo "Per-app Game Mode checked for: $pkg ($game_mode)"
echo "FPS target reference saved: ${fps_target} (not forced; game/Android controls actual FPS)."
echo "Thermal status: $(read_thermal_level) (performance Game Mode guarded at SEVERE or above)."
echo "Thermal protections and CPU/GPU clock limits were not modified."
log "Profile=$profile package=$pkg refresh=$refresh animation=$scale failures=$failures"
if [ "$failures" -eq 0 ]; then
  # Persist only validated selections so the service can re-apply them after reboot.
  printf '%s|%s|%s|%s|%s|%s\n' "$profile" "$pkg" "$refresh" "$scale" "$fps_target" "$features" > "$STATE/active_profile.tmp"
  mv "$STATE/active_profile.tmp" "$STATE/active_profile"
  echo "Saved profile persisted for automatic re-apply after reboot."
fi
[ "$failures" -eq 0 ]
