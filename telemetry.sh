#!/system/bin/sh
# ZYN BOOSTER v26 — read-only Android telemetry; never fabricates unavailable sensors.
pkg="$1"
valid_pkg() { case "$1" in ''|*[!A-Za-z0-9_.]*|.*|*.) return 1 ;; *.*) return 0 ;; *) return 1 ;; esac; }
[ -n "$pkg" ] && valid_pkg "$pkg" || pkg=""

read_cpu_load() {
  [ -r /proc/stat ] || { echo N/A; return; }
  set -- $(awk '$1=="cpu"{print $2,$3,$4,$5,$6,$7,$8}' /proc/stat 2>/dev/null)
  [ "$#" -ge 4 ] || { echo N/A; return; }
  total1=$(($1+$2+$3+$4+$5+$6+$7)); idle1=$(($4+$5))
  sleep 1
  set -- $(awk '$1=="cpu"{print $2,$3,$4,$5,$6,$7,$8}' /proc/stat 2>/dev/null)
  [ "$#" -ge 4 ] || { echo N/A; return; }
  total2=$(($1+$2+$3+$4+$5+$6+$7)); idle2=$(($4+$5))
  dt=$((total2-total1)); di=$((idle2-idle1))
  [ "$dt" -gt 0 ] || { echo N/A; return; }
  awk -v t="$dt" -v i="$di" 'BEGIN{v=(t-i)*100/t;if(v<0)v=0;if(v>100)v=100;printf "%.0f",v}'
}
read_mem_used() {
  awk '/MemTotal:/{t=$2}/MemAvailable:/{a=$2}/MemFree:/{f=$2}/Cached:/{c=$2}/Buffers:/{b=$2}END{if(t>0){if(a==0)a=f+c+b;v=(t-a)*100/t;if(v<0)v=0;if(v>100)v=100;printf "%.0f",v}else print "N/A"}' /proc/meminfo 2>/dev/null
}

read_mem_available() {
  awk '/MemAvailable:/{printf "%.0f",$2/1024;found=1}END{if(!found)print "N/A"}' /proc/meminfo 2>/dev/null
}
read_temp() {
  max=""
  for f in /sys/class/thermal/thermal_zone*/temp; do
    [ -r "$f" ] || continue
    n="$(cat "$f" 2>/dev/null)"
    case "$n" in ''|*[!0-9-]*) continue ;; esac
    if [ "$n" -gt 1000 ] 2>/dev/null; then n=$((n/1000)); elif [ "$n" -gt 100 ] 2>/dev/null; then n=$((n/10)); fi
    [ "$n" -lt 0 ] 2>/dev/null && continue; [ "$n" -gt 120 ] 2>/dev/null && continue
    [ -z "$max" ] || [ "$n" -le "$max" ] || max="$n"
    [ -n "$max" ] || max="$n"
  done
  if [ -z "$max" ] && [ -r /sys/class/power_supply/battery/temp ]; then
    n="$(cat /sys/class/power_supply/battery/temp 2>/dev/null)"
    case "$n" in ''|*[!0-9-]*) ;; *) max=$((n/10)) ;; esac
  fi
  [ -n "$max" ] && echo "$max" || echo N/A
}
read_power_value() {
  file="$1"; divisor="$2"
  if [ -r "$file" ]; then n="$(cat "$file" 2>/dev/null)"; case "$n" in ''|*[!0-9-]*) echo N/A ;; *) awk -v n="$n" -v d="$divisor" 'BEGIN{printf "%.0f",n/d}' ;; esac; else echo N/A; fi
}
read_cpu_cores() {
  if [ -r /sys/devices/system/cpu/online ]; then cat /sys/devices/system/cpu/online 2>/dev/null; else
    find /sys/devices/system/cpu -maxdepth 1 -type d -name 'cpu[0-9]*' 2>/dev/null | wc -l | tr -d ' '
  fi
}
read_zram_used() {
  for f in /sys/block/zram0/mm_stat /sys/block/zram0/mem_used_total; do
    [ -r "$f" ] || continue
    set -- $(cat "$f" 2>/dev/null)
    case "$1" in ''|*[!0-9]*) continue ;; esac
    # mm_stat field 2 is compressed memory in bytes; mem_used_total is bytes.
    if [ "$(basename "$f")" = mm_stat ]; then n="$2"; else n="$1"; fi
    case "$n" in ''|*[!0-9]*) continue ;; esac
    awk -v n="$n" 'BEGIN{printf "%.0f",n/1048576}'; return
  done
  echo N/A
}
read_memory_pressure() {
  if [ -r /proc/pressure/memory ]; then
    awk '/^some /{for(i=1;i<=NF;i++)if($i~/^avg10=/){split($i,a,"=");printf "%s",a[2];found=1}}END{if(!found)print "N/A"}' /proc/pressure/memory
  else echo N/A; fi
}
read_battery() { [ -r /sys/class/power_supply/battery/capacity ] && cat /sys/class/power_supply/battery/capacity 2>/dev/null || echo N/A; }
read_freq() {
  for f in /sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq /sys/devices/system/cpu/cpufreq/policy0/cpuinfo_cur_freq; do
    [ -r "$f" ] || continue; n="$(cat "$f" 2>/dev/null)"; case "$n" in ''|*[!0-9]*) continue ;; esac; echo "$((n/1000))"; return
  done; echo N/A
}
read_gpu_freq() {
  for f in /sys/class/kgsl/kgsl-3d0/devfreq/cur_freq /sys/class/devfreq/*gpu*/cur_freq /sys/class/devfreq/*mali*/cur_freq; do
    [ -r "$f" ] || continue; n="$(cat "$f" 2>/dev/null)"; case "$n" in ''|*[!0-9]*) continue ;; esac
    if [ "$n" -gt 1000000 ]; then echo "$((n/1000000))"; else echo "$((n/1000))"; fi; return
  done; echo N/A
}
read_gpu_load() {
  for f in /sys/class/kgsl/kgsl-3d0/gpubusy /sys/class/kgsl/kgsl-3d0/devfreq/load /sys/class/devfreq/*gpu*/load /sys/class/devfreq/*mali*/load; do
    [ -r "$f" ] || continue; n="$(cat "$f" 2>/dev/null)"
    case "$f" in *gpubusy) set -- $n; if [ "$#" -ge 2 ] && [ "$2" -gt 0 ] 2>/dev/null; then awk -v a="$1" -v b="$2" 'BEGIN{v=100*a/b;if(v>100)v=100;printf "%.0f",v}'; return; fi ;;
      *) case "$n" in ''|*[!0-9]*) continue ;; esac; [ "$n" -le 100 ] 2>/dev/null && { echo "$n"; return; } ;;
    esac
  done; echo N/A
}
read_storage() { value="$(df -k /data 2>/dev/null | awk 'NR==2 && $4!=""{printf "%.0f",$4/1024}')"; [ -n "$value" ] && echo "$value" || echo N/A; }
read_foreground() {
  line="$(dumpsys activity activities 2>/dev/null | grep -m 1 -E 'mResumedActivity|topResumedActivity')"
  found="$(printf '%s\n' "$line" | sed -n 's/.*[[:space:]]\([A-Za-z0-9_][A-Za-z0-9_.]*\)\/[^[:space:]]*.*/\1/p')"
  [ -n "$found" ] && echo "$found" || echo N/A
}
read_thermal_status() {
  value="$(dumpsys thermalservice 2>/dev/null | grep -m 1 -i 'Thermal Status' | sed 's/.*:[[:space:]]*//')"
  [ -n "$value" ] || value="$(dumpsys thermalservice 2>/dev/null | grep -m 1 -i 'mStatus=' | sed 's/.*mStatus=//;s/[ ,}].*//')"
  [ -n "$value" ] && echo "$value" || echo N/A
}
read_refresh() { v="$(settings get system peak_refresh_rate 2>/dev/null | tr -d '\r\n')"; case "$v" in ''|null) echo N/A ;; *) echo "$v" ;; esac; }
read_max_refresh() {
  dumpsys display 2>/dev/null | awk '{line=$0;while(match(line,/refreshRate[=:][[:space:]]*[0-9]+([.][0-9]+)?/)){v=substr(line,RSTART,RLENGTH);sub(/^.*[=:][[:space:]]*/,"",v);if(v+0>max)max=v+0;line=substr(line,RSTART+RLENGTH)}}END{if(max>0)printf "%.0f",max;else print "N/A"}'
}
read_governor() { for f in /sys/devices/system/cpu/cpufreq/policy0/scaling_governor /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor; do [ -r "$f" ] && { cat "$f" 2>/dev/null; return; }; done; echo N/A; }
read_frame_stats() {
  [ -n "$pkg" ] || { echo "GAME_FPS=N/A"; echo "FRAME_INTERVAL_AVG_MS=N/A"; echo "FRAME_INTERVAL_P95_MS=N/A"; echo "SLOW_FRAME_PERCENT=N/A"; echo "FRAME_SAMPLES=0"; return; }
  layer="$(dumpsys SurfaceFlinger --list 2>/dev/null | grep -F "$pkg" | head -n 1)"
  [ -n "$layer" ] || { echo "GAME_FPS=N/A"; echo "FRAME_INTERVAL_AVG_MS=N/A"; echo "FRAME_INTERVAL_P95_MS=N/A"; echo "SLOW_FRAME_PERCENT=N/A"; echo "FRAME_SAMPLES=0"; return; }
  rate="$(settings get system peak_refresh_rate 2>/dev/null)"
  printf '%s\n' "$(dumpsys SurfaceFlinger --latency "$layer" 2>/dev/null)" | awk -v rate="$rate" '
    NR>1 && NF>=2 && $2~/^[0-9]+$/ && $2>0 { if(!n || $2!=ts[n]) ts[++n]=$2 }
    END {
      if(n<3){print "GAME_FPS=N/A\nFRAME_INTERVAL_AVG_MS=N/A\nFRAME_INTERVAL_P95_MS=N/A\nSLOW_FRAME_PERCENT=N/A\nFRAME_SAMPLES=" n;exit}
      total=0; slow=0; k=0; budget=(rate+0)>0?1000/(rate+0):16.667
      for(i=2;i<=n;i++){d=ts[i]-ts[i-1];if(d<=0)continue;ms=d/1000000;iv[++k]=ms;total+=ms;if(ms>budget*1.5)slow++}
      if(k<2){print "GAME_FPS=N/A\nFRAME_INTERVAL_AVG_MS=N/A\nFRAME_INTERVAL_P95_MS=N/A\nSLOW_FRAME_PERCENT=N/A\nFRAME_SAMPLES=" n;exit}
      for(i=2;i<=k;i++){v=iv[i];j=i-1;while(j>=1&&iv[j]>v){iv[j+1]=iv[j];j--}iv[j+1]=v}
      p= int(k*.95);if(p<1)p=1;if(p>k)p=k
      avg=total/k; fps=(n-1)*1000000000/(ts[n]-ts[1])
      printf "GAME_FPS=%.1f\nFRAME_INTERVAL_AVG_MS=%.2f\nFRAME_INTERVAL_P95_MS=%.2f\nSLOW_FRAME_PERCENT=%.1f\nFRAME_SAMPLES=%d\n",fps,avg,iv[p],slow*100/k,k
    }'
}

[ -n "$pkg" ] || { pkg="$(read_foreground)"; valid_pkg "$pkg" || pkg=""; }
# Every field is read from Android procfs, sysfs, settings, or dumpsys. N/A is intentional when blocked.
echo "CPU_LOAD=$(read_cpu_load)"
echo "RAM_USED=$(read_mem_used)"
echo "RAM_AVAILABLE_MB=$(read_mem_available)"
echo "CPU_CORES_ONLINE=$(read_cpu_cores)"
echo "ZRAM_USED_MB=$(read_zram_used)"
echo "MEMORY_PRESSURE_AVG10=$(read_memory_pressure)"
echo "TEMPERATURE=$(read_temp)"
echo "THERMAL_STATUS=$(read_thermal_status)"
echo "BATTERY=$(read_battery)"
echo "BATTERY_CURRENT_MA=$(read_power_value /sys/class/power_supply/battery/current_now 1000)"
echo "BATTERY_VOLTAGE_MV=$(read_power_value /sys/class/power_supply/battery/voltage_now 1000)"
echo "STORAGE_FREE=$(read_storage)"
echo "CPU_FREQ_MHZ=$(read_freq)"
echo "CPU_GOVERNOR=$(read_governor)"
echo "GPU_FREQ_MHZ=$(read_gpu_freq)"
echo "GPU_LOAD=$(read_gpu_load)"
read_frame_stats
echo "REFRESH_CAP=$(read_refresh)"
echo "MAX_REFRESH=$(read_max_refresh)"
echo "FOREGROUND_APP=$(read_foreground)"
echo "SAMPLED_PACKAGE=${pkg:-N/A}"
echo "UPTIME_SECONDS=$(awk '{printf "%.0f",$1}' /proc/uptime 2>/dev/null)"
