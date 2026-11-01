#!/system/bin/sh
# ZYN BOOSTER v26 — AxManager-compatible installer hook.
# AxManager sources this file after extracting the ZIP into MODPATH.
SKIPMOUNT=false
PROPFILE=true
POSTFSDATA=false
LATESTARTSERVICE=true

zyn_print() {
  if command -v ui_print >/dev/null 2>&1; then ui_print "$1"; else echo "$1"; fi
}

# Fail with a clear installer message if the extracted plugin is incomplete.
if [ -z "${MODPATH:-}" ] || [ ! -d "$MODPATH" ]; then
  if command -v abort >/dev/null 2>&1; then abort "ZYN BOOSTER: installer did not provide MODPATH."; fi
else
  if [ ! -f "$MODPATH/module.prop" ]; then
    if command -v abort >/dev/null 2>&1; then abort "ZYN BOOSTER: module.prop missing after extraction."; fi
  fi
  chmod 0755 "$MODPATH" "$MODPATH/service.sh" "$MODPATH/action.sh" "$MODPATH/optimize.sh" "$MODPATH/telemetry.sh" "$MODPATH/uninstall.sh" 2>/dev/null
  chmod 0755 "$MODPATH/webroot" 2>/dev/null
  chmod 0644 "$MODPATH/module.prop" "$MODPATH/README.txt" "$MODPATH/webroot/index.html" "$MODPATH/webroot/main.js" 2>/dev/null
  if [ "${AXERON:-false}" = "true" ]; then
    zyn_print "ZYN BOOSTER v26 — AxManager plugin"
    zyn_print "AxManager server: ${AXERONVER:-unknown}"
    zyn_print "Plugin ID: zyn_booster"
    zyn_print "WebUI: webroot/index.html"
    zyn_print "Thermal controls and CPU/GPU clocks remain Android-managed."
  fi
fi

print_modname() {
  ui_print "  ZYN BOOSTER v26 TITAN"
  ui_print "  Adaptive Android Performance Engine"
}
on_install() {
  ui_print "- Verifying Android device and available interfaces..."
  ui_print "- Enabling reversible, supported tuning only..."
  ui_print "- Thermal safeguards remain enabled."
}
set_permissions() {
  set_perm_recursive "$MODPATH" 0 0 0755 0644
  set_perm "$MODPATH/service.sh" 0 0 0755
  set_perm "$MODPATH/action.sh" 0 0 0755
  set_perm "$MODPATH/optimize.sh" 0 0 0755
  set_perm "$MODPATH/telemetry.sh" 0 0 0755
  set_perm "$MODPATH/uninstall.sh" 0 0 0755
}
