ZTC BOOSTER 
================================
AxManager WebUI plugin (axeronPlugin=10000) and Magisk / KernelSU module layout.
Original banner assets and the existing dashboard identity are preserved.

INSTALL
1. Install the ZIP from AxManager > Plugins (+), or from Magisk / KernelSU.
2. In AxManager, enable the plugin and re-ignite if requested.
3. Open the plugin WebUI. Browser preview cannot perform privileged Android actions.

ENGINE FUNCTIONS
- Android per-app GameManager PERFORMANCE / BATTERY mode, only when the OS advertises support.
- Adaptive peak refresh cap, only when dumpsys reports the requested display mode.
- Animation-scale settings are backed up once and read-back verified.
- Restore attempts to return saved settings and per-app Game Mode.
- Live read-only CPU/RAM/GPU/thermal/battery/storage/clock/refresh telemetry, CPU online-core count, ZRAM usage and memory PSI pressure where exposed.
- SurfaceFlinger FPS sampling where the ROM exposes layer timestamps; otherwise N/A.
- Automatic known-game package targeting with an installed-package check.
- Thermal-aware per-game Android Game Mode where supported.
- Persistent verified profile and boot re-apply.
- Device health diagnostics and engine logs.

 IMPROVEMENTS
- AxManager command bridge now uses AXERONDIR/AXERON_PLUGIN; no malformed cwd path.
- Removed the installed-app selector, app list, OPTIMIZE APP and RELOAD LIST controls entirely.
- Monitor polling reduced to 7 seconds and visibility listener is registered once.
- Added thermal-aware performance Game Mode guard and corrected RAM telemetry output.
- Clearer versioning and v23 build output name.
- Existing safe engine behavior retained; unsupported features report unavailable rather than faking results.

PERFORMANCE LIMITS / SAFETY
- FPS target is a reference only; it does not unlock or force game FPS.
- A refresh cap cannot make a 60Hz panel become 120Hz.
- CPU/GPU clocks are not forced; thermal protections are never disabled.
- No arbitrary kernel writes, memory killing, thermal spoofing, vendor driver overrides or cache purges.
- ART compilation is an Android package-manager task, not an FPS unlock; it may take time.

COMMANDS
  sh ./action.sh status
  sh ./action.sh capabilities
  sh ./action.sh telemetry [package.name]
  sh ./action.sh apply saver
  sh ./action.sh apply balanced
  sh ./action.sh apply gaming package.name 120 0.5 120
  sh ./action.sh compile package.name
  sh ./action.sh restore
  sh ./action.sh logs

BUILD
Run BUILD_ZYN_v23.sh in a shell with zip installed.
AxManager requires axeronPlugin <= the installed server version; this package
declares 10000 (AxManager 1.0.0+).

 FIXES
- AxManager WebUI no longer passes the invalid moduleDir cwd. It invokes the
  action script through $AXERONDIR/plugins/$AXERON_PLUGIN/action.sh.
- KernelSU WebUI retains its moduleInfo() cwd flow.
- App targeting is automatic from the selected game; no app list is rendered.
- Game Mode is skipped when the mapped package is not installed or thermal
  status is SEVERE or higher.
- Telemetry RAM output line separator corrected.
- WebView motion is lighter: continuous full-screen overlays and redundant
  animation loops are disabled; reduced-motion preference is respected.


 INSTALLER / ENGINE NOTES
- module.prop is at the ZIP root, stored as UTF-8 with UNIX LF line endings.
- ZIP entries are packed without a parent folder; module.prop is the first entry.
- Plugin ID remains zyn_booster and matches the installed plugin directory.
- AxManager compatibility target is 10000 (AxManager 1.0.0+).
- Added read-only device health diagnostics for boot, thermal, memory, battery, storage, display and GameManager availability.
- Dashboard motion is reduced to short transitions; perpetual scan/glint/reveal loops are disabled for lower WebView load.
- Existing tuning remains reversible: animation scales, supported refresh cap and Android Game Mode are backed up/read-back checked.
- No forced CPU/GPU clocks, thermal bypasses, or fabricated FPS values.

INSTALLATION CHECK
If AxManager still reports module.prop missing, verify the selected file is the v23 ZIP and that the archive viewer shows module.prop at the top level (not inside a nested folder).
