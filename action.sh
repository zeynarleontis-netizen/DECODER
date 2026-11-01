#!/system/bin/sh
# ZYN BOOSTER v26 TITAN X action entry for AxManager / KernelSU / Magisk.
MODDIR=${0%/*}
valid_pkg() {
  case "$1" in ''|*[!A-Za-z0-9_.]*|.*|*.) return 1 ;; *.*) return 0 ;; *) return 1 ;; esac
}
case "$1" in
  apply)
    profile="$2"; pkg="$3"; refresh="$4"; animation="$5"; fps="$6"; features="$7"
    case "$profile" in saver|balanced|gaming) ;; *) echo "Invalid profile."; exit 2 ;; esac
    [ -z "$pkg" ] || valid_pkg "$pkg" || { echo "Invalid app package."; exit 2; }
    case "$refresh" in ''|60|90|120|144|165) ;; *) echo "Invalid refresh target."; exit 2 ;; esac
    case "$animation" in ''|0|0.4|0.5|0.6|1|1.5|2|5|10) ;; *) echo "Invalid animation scale."; exit 2 ;; esac
    exec sh "$MODDIR/optimize.sh" "$profile" "$pkg" "$refresh" "$animation" "$fps" "$features"
    ;;
  status)
    echo "ZYN BOOSTER v26 — TITAN X PRO ENGINE"
    [ "${AXERON:-false}" = "true" ] && manager="AxManager" || manager="Magisk/KernelSU"
    echo "Manager: $manager"
    echo "Device: $(getprop ro.product.manufacturer) $(getprop ro.product.model)"
    echo "Android: $(getprop ro.build.version.release) (SDK $(getprop ro.build.version.sdk))"
    echo "Kernel: $(uname -r 2>/dev/null)"
    echo "SoC: $(getprop ro.soc.model)"
    echo "Profile: $(cat "$MODDIR/state/profile" 2>/dev/null || echo not-applied)"
    echo "Boot status: $(cat "$MODDIR/state/status" 2>/dev/null || echo unknown)"
    echo "Last apply: $(cat "$MODDIR/state/last_apply" 2>/dev/null || echo never)"
    echo "Last setting failures: $(cat "$MODDIR/state/last_failures" 2>/dev/null || echo unknown)"
    echo "Thermal protection: Android-controlled / unchanged"
    echo "CPU/GPU clocks: kernel-controlled / unchanged"
    ;;
  telemetry)
    pkg="$2"
    [ -z "$pkg" ] || valid_pkg "$pkg" || { echo "Invalid package."; exit 2; }
    exec sh "$MODDIR/telemetry.sh" "$pkg"
    ;;
  compile)
    pkg="$2"
    valid_pkg "$pkg" || { echo "Invalid package name."; exit 2; }
    command -v cmd >/dev/null 2>&1 || { echo "Android package manager command unavailable."; exit 1; }
    help="$(cmd package help 2>&1)"
    printf '%s\n' "$help" | grep -q 'compile' || { echo "App compilation is not supported on this Android build."; exit 1; }
    echo "Compiling $pkg with speed-profile (may take a little while)…"
    cmd package compile -m speed-profile -f "$pkg"
    rc=$?
    [ "$rc" -eq 0 ] && echo "Android accepted the speed-profile compilation request."
    exit "$rc"
    ;;
  health)
    echo "ZYN BOOSTER v26 DEVICE HEALTH"
    echo "Android: $(getprop ro.build.version.release) / SDK $(getprop ro.build.version.sdk)"
    echo "Boot completed: $(getprop sys.boot_completed)"
    echo "Thermal service: $(dumpsys thermalservice 2>/dev/null | grep -m 1 -i 'Thermal Status' | sed 's/.*:[[:space:]]*//' || echo unavailable)"
    echo "Memory: $(awk '/MemAvailable:/{printf "%.0f MB",$2/1024}' /proc/meminfo 2>/dev/null) available"
    echo "Battery: $(cat /sys/class/power_supply/battery/capacity 2>/dev/null || echo N/A)%"
    echo "Storage: $(df -h /data 2>/dev/null | awk 'NR==2{print $4 " free of " $2}' )"
    echo "Display peak refresh: $(settings get system peak_refresh_rate 2>/dev/null)"
    echo "GameManager command: $(cmd game help 2>&1 | head -n 1)"
    ;;
  capabilities)
    echo "Android: $(getprop ro.build.version.release) / SDK $(getprop ro.build.version.sdk)"
    echo "Supported display refresh rates:"
    dumpsys display 2>/dev/null | grep -Eo 'refreshRate[=:][[:space:]]*[0-9]+([.][0-9]+)?' | sed 's/.*[=:][[:space:]]*//' | sort -nu
    echo "Peak refresh setting: $(settings get system peak_refresh_rate 2>/dev/null)"
    echo "Game Manager:"
    cmd game help 2>&1 | head -n 12
    echo "GPU sysfs: $( [ -r /sys/class/kgsl/kgsl-3d0/gpubusy ] && echo KGSL || echo vendor-specific/unavailable )"
    ;;
  engine)
    engine="$2"
    case "$engine" in
      network)
        echo "NETWORK DIAGNOSTICS — READ ONLY"
        dns="$(getprop net.dns1 2>/dev/null)"; [ -n "$dns" ] || dns="N/A"
        route="$(ip route 2>/dev/null | grep -m 1 '^default' | awk '{print $3}')"; [ -n "$route" ] || route="N/A"
        iface="$(ip route 2>/dev/null | grep -m 1 '^default' | awk '{print $5}')"; [ -n "$iface" ] || iface="N/A"
        if command -v timeout >/dev/null 2>&1 && command -v getent >/dev/null 2>&1; then
          if timeout 4 getent hosts connectivitycheck.gstatic.com >/dev/null 2>&1; then dns_test="PASS"; else dns_test="FAILED_OR_BLOCKED"; fi
        elif command -v timeout >/dev/null 2>&1 && command -v ping >/dev/null 2>&1; then
          if timeout 4 ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then dns_test="IP_REACHABLE_DNS_UNTESTED"; else dns_test="UNAVAILABLE_OR_BLOCKED"; fi
        else dns_test="UNAVAILABLE_NO_BOUNDED_PROBE"; fi
        echo "DNS1=$dns"; echo "GATEWAY=$route"; echo "INTERFACE=$iface"; echo "CONNECTIVITY_TEST=$dns_test"
        ;;
      storage)
        echo "STORAGE ANALYZER — READ ONLY"
        for path in /data /storage/emulated/0 /cache; do
          if [ -e "$path" ]; then df -k "$path" 2>/dev/null | awk -v p="$path" 'NR==2{printf "%s | total=%s MB | used=%s MB | free=%s MB | use=%s\n",p,int($2/1024),int($3/1024),int($4/1024),$5}'; fi
        done
        echo "INODE_STATUS=$(df -i /data 2>/dev/null | awk 'NR==2{print $5}')"
        ;;
      battery)
        echo "BATTERY INTELLIGENCE — READ ONLY"
        for pair in "LEVEL:capacity" "STATUS:status" "HEALTH:health" "TEMP_DECI_C:temp" "VOLTAGE_UV:voltage_now" "CURRENT_UA:current_now" "CYCLE_COUNT:cycle_count"; do
          key=${pair%%:*}; file=${pair#*:}; value="$(cat "/sys/class/power_supply/battery/$file" 2>/dev/null)"; [ -n "$value" ] || value="N/A"; echo "$key=$value"
        done
        ;;
      display)
        echo "DISPLAY INTELLIGENCE — READ ONLY"
        echo "CURRENT_CAP=$(settings get system peak_refresh_rate 2>/dev/null)"
        echo "MIN_CAP=$(settings get system min_refresh_rate 2>/dev/null)"
        echo "REPORTED_MODES=$(dumpsys display 2>/dev/null | grep -Eo 'refreshRate[=:][[:space:]]*[0-9]+([.][0-9]+)?' | sed 's/.*[=:][[:space:]]*//' | sort -nu | tr '\n' ' ' )"
        echo "DISPLAY_SERVICE=$(dumpsys display 2>/dev/null | grep -m 1 -E 'mDisplayState|state=ON' | tr -s ' ' | cut -c1-180)"
        ;;
      diagnostics)
        echo "ENGINE SELF TEST — READ ONLY"
        for cmdname in getprop settings dumpsys pm cmd awk sed grep df ip timeout; do
          if command -v "$cmdname" >/dev/null 2>&1; then echo "CMD_$cmdname=AVAILABLE"; else echo "CMD_$cmdname=MISSING"; fi
        done
        echo "BOOT_COMPLETED=$(getprop sys.boot_completed 2>/dev/null)"
        echo "PLUGIN_DIR=$MODDIR"
        [ -r "$MODDIR/module.prop" ] && echo "MODULE_PROP=READABLE" || echo "MODULE_PROP=UNREADABLE"
        [ -w "$MODDIR/state" ] 2>/dev/null && echo "STATE_DIR=WRITABLE" || { mkdir -p "$MODDIR/state" 2>/dev/null && [ -w "$MODDIR/state" ] && echo "STATE_DIR=WRITABLE" || echo "STATE_DIR=READ_ONLY"; }
        echo "THERMAL_STATUS=$(dumpsys thermalservice 2>/dev/null | grep -m 1 -i 'Thermal Status' | sed 's/.*:[[:space:]]*//' | cut -c1-50)"
        ;;
      frames)
        pkg="$3"
        [ -n "$pkg" ] && valid_pkg "$pkg" || pkg="$(dumpsys activity activities 2>/dev/null | grep -m 1 -E 'mResumedActivity|topResumedActivity' | sed -n 's/.*[[:space:]]\([A-Za-z0-9_][A-Za-z0-9_.]*\)\/[^[:space:]]*.*/\1/p')"
        [ -n "$pkg" ] || { echo "No foreground package could be detected."; exit 1; }
        echo "FRAME PACING ANALYSIS"
        echo "PACKAGE=$pkg"
        echo "$(sh "$MODDIR/telemetry.sh" "$pkg" | grep -E '^(GAME_FPS|FRAME_INTERVAL_AVG_MS|FRAME_INTERVAL_P95_MS|SLOW_FRAME_PERCENT|FRAME_SAMPLES|SAMPLED_PACKAGE)=')"
        echo "NOTE=SurfaceFlinger timestamp sampling is device/ROM dependent; this is not a guaranteed FPS unlock or frame-time trace."
        ;;
      thermal)
        echo "THERMAL INTELLIGENCE — READ ONLY"
        echo "THERMAL_SERVICE=$(dumpsys thermalservice 2>/dev/null | grep -m 3 -Ei 'Thermal Status|mStatus=|Temperature\{' | tr '\n' ';' | cut -c1-500)"
        for f in /sys/class/thermal/thermal_zone*/type; do [ -r "$f" ] || continue; z=${f%/type}; t=$(cat "$z/temp" 2>/dev/null); typ=$(cat "$f" 2>/dev/null); [ -n "$t" ] && echo "ZONE_${typ}=$t"; done | head -n 16
        echo "SAFETY=Android thermal throttling remains enabled"
        ;;
      memory)
        echo "MEMORY PRESSURE ANALYZER — READ ONLY"
        awk '/MemTotal:|MemAvailable:|SwapTotal:|SwapFree:|Cached:|Dirty:/{print}' /proc/meminfo 2>/dev/null
        [ -r /proc/pressure/memory ] && { echo "MEMORY_PSI:"; cat /proc/pressure/memory; } || echo "MEMORY_PSI=UNAVAILABLE"
        for f in /sys/block/zram*/mm_stat; do [ -r "$f" ] && echo "$(basename "$(dirname "$f")")_MM_STAT=$(cat "$f")"; done
        ;;
      graphics)
        echo "GRAPHICS CAPABILITY SCAN — READ ONLY"
        echo "GPU_VENDOR=$(getprop ro.hardware.egl)"; echo "GPU_RENDERER=$(getprop ro.hardware.vulkan)"; echo "OPENGL_ES_VERSION=$(getprop ro.opengles.version)"
        echo "SURFACEFLINGER=$(dumpsys SurfaceFlinger 2>/dev/null | grep -m 3 -Ei 'GLES:|Vulkan|HWC|refresh-rate' | tr '\n' ';' | cut -c1-500)"
        for f in /sys/class/kgsl/kgsl-3d0/gpu_model /sys/class/kgsl/kgsl-3d0/devfreq/cur_freq /sys/class/devfreq/*gpu*/cur_freq /sys/class/devfreq/*mali*/cur_freq; do [ -r "$f" ] && echo "$(basename "$f")=$(cat "$f" 2>/dev/null)"; done
        ;;
      appinfo)
        pkg="$3"; [ -n "$pkg" ] && valid_pkg "$pkg" || { echo "Select a supported game first."; exit 2; }
        if ! pm path "$pkg" >/dev/null 2>&1; then
          case "$pkg" in
            com.garena.game.codm) pm path com.activision.callofduty.shooter >/dev/null 2>&1 && pkg=com.activision.callofduty.shooter ;;
            com.tencent.ig) pm path com.pubg.imobile >/dev/null 2>&1 && pkg=com.pubg.imobile ;;
            com.dts.freefireth) pm path com.dts.freefiremax >/dev/null 2>&1 && pkg=com.dts.freefiremax ;;
          esac
        fi
        echo "GAME PACKAGE INSPECTOR — READ ONLY"; echo "PACKAGE=$pkg"
        if pm path "$pkg" >/dev/null 2>&1; then echo "INSTALLED=YES"; echo "RESOLVED_PACKAGE=$pkg"; pm path "$pkg"; dumpsys package "$pkg" 2>/dev/null | grep -m 1 -E 'versionName=|versionCode='; else echo "INSTALLED=NO"; exit 1; fi
        ;;
      power)
        echo "POWER & BATTERY PROFILE — READ ONLY"
        for f in capacity status health temp voltage_now current_now cycle_count charge_counter; do v=$(cat "/sys/class/power_supply/battery/$f" 2>/dev/null); [ -n "$v" ] && echo "$f=$v"; done
        echo "POWER_SERVICE=$(dumpsys battery 2>/dev/null | grep -E 'level:|status:|health:|temperature:|voltage:' | tr '\n' ';' | cut -c1-400)"
        ;;
      *) echo "Usage: $0 engine {network|storage|battery|display|diagnostics|frames|thermal|memory|graphics|appinfo|power} [package.name]"; exit 2 ;;
    esac
    ;;
  config)
    mkdir -p "$MODDIR/state" || exit 1
    case "$2" in
      save)
        mode="$3"; game="$4"; pkg="$5"; fps="$6"; refresh="$7"; animation="$8"; features="$9"
        case "$mode" in saver|balanced|gaming) ;; *) echo "Invalid saved profile mode."; exit 2 ;; esac
        case "$game" in "Mobile Legends"|"PUBG Mobile"|"Call of Duty Mobile"|"CarX Street"|Roblox|"Car Parking Multiplayer"|"Free Fire"|"Blood Strike"|"Genshin Impact") ;; *) echo "Invalid game selection."; exit 2 ;; esac
        [ -z "$pkg" ] || valid_pkg "$pkg" || { echo "Invalid package mapping."; exit 2; }
        case "$fps" in 60|90|120|144|165) ;; *) echo "Invalid FPS target."; exit 2 ;; esac
        case "$refresh" in ''|60|90|120|144|165) ;; *) echo "Invalid refresh target."; exit 2 ;; esac
        case "$animation" in ''|0|0.4|0.5|0.6|1|1.5|2|5|10) ;; *) echo "Invalid animation scale."; exit 2 ;; esac
        case ",$features," in *",game_mode,"*|*",refresh,"*|*",animation,"*|*",telemetry,"*|*",frames,"*|*",network,"*|*",battery,"*|*",storage,"*|*",thermal,"* ) ;; *) echo "Invalid feature selection."; exit 2 ;; esac
        tmp="$MODDIR/state/ui_config.tmp"
        printf '%s|%s|%s|%s|%s|%s|%s\n' "$mode" "$game" "$pkg" "$fps" "$refresh" "$animation" "$features" > "$tmp" || exit 1
        mv "$tmp" "$MODDIR/state/ui_config" || exit 1
        echo "PROFILE_SAVED=YES"; echo "GAME=$game"; echo "PACKAGE=${pkg:-unmapped}"; echo "FEATURES=$features"; echo "SAVE_LOCATION=plugin state/ui_config"
        ;;
      load)
        if [ -r "$MODDIR/state/ui_config" ]; then
          printf 'CONFIG='; cat "$MODDIR/state/ui_config"
        else echo "CONFIG=Performance Boost|Mobile Legends|com.mobile.legends|165|60|1|game_mode,refresh,animation,telemetry,frames,network,battery,storage,thermal"; fi
        ;;
      *) echo "Usage: $0 config {save|load} ..."; exit 2 ;;
    esac
    ;;
  restore) exec sh "$MODDIR/optimize.sh" restore ;;
  logs) tail -n 120 "$MODDIR/logs/engine.log" 2>/dev/null || echo "No engine log yet." ;;
  *) echo "Usage: $0 {apply [saver|balanced|gaming] [package] [refresh] [animation] [fps-target]|status|telemetry [package]|health|capabilities|engine {network|storage|battery|display|diagnostics|frames|thermal|memory|graphics|appinfo|power}|compile package.name|restore|logs}"; exit 2 ;;
esac
