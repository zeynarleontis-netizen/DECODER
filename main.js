/* ZYN BOOSTER v27 TITAN X ULTRA — AxManager/KernelSU WebUI
 * Full rewrite: Quick Boost, CPU Governor, RAM Flush, ring meters, animated counters
 * All Android actions through the documented async bridge only.
 */
(() => {
  "use strict";

  /* ─── UTILITIES ─────────────────────────────────────────────── */
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
  const parseJson = (v, fb) => { try { return typeof v==="string"?JSON.parse(v):(v??fb); } catch(_){return fb;} };
  const clamp = (n,lo,hi) => Math.max(lo, Math.min(hi, n));

  /* ─── STATE ──────────────────────────────────────────────────── */
  const state = {
    mode: "Performance Boost",
    game: "Mobile Legends",
    fps: "144",
    refresh: "60Hz",
    animation: "1",
    governor: "schedutil",
    api: null,
    moduleDir: "",
    manager: "Browser preview",
    callbackSeq: 0,
    selectedPkg: "",
    selectedLabel: "",
    features: {
      game_mode:true, refresh:true, animation:true,
      telemetry:true, frames:true, network:true,
      battery:true, storage:true, thermal:true,
      zram:true, bg_limit:true, net_buf:true,
      touch_latency:true, zram_prio:true, cache_limit:true
    },
    animationTouched: false,
    busy: false,
    pollTimer: null,
    connected: false,
    telemetryBusy: false,
    lastTelemetryAt: 0
  };

  const ANIM_VALUES  = ["0","0.4","0.5","0.6","1","1.5","2","5","10"];
  const FPS_VALUES   = ["60","90","120","144","165","240","480"];
  const REFRESH_VALUES = ["60Hz","90Hz","120Hz","144Hz","165Hz"];
  const GOV_VALUES   = ["performance","schedutil","interactive","powersave"];
  const PACKAGE_RE   = /^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$/;

  /* ─── GAME PACKAGE MAP ──────────────────────────────────────── */
  const PACKAGES = {
    "Mobile Legends":               ["com.mobile.legends"],
    "PUBG Mobile":                  ["com.tencent.ig","com.pubg.imobile"],
    "Call of Duty Mobile":          ["com.garena.game.codm","com.activision.callofduty.shooter"],
    "CarX Street":                  ["com.carxtech.sr"],
    "Roblox":                       ["com.roblox.client"],
    "Car Parking Multiplayer":      ["com.olzhas.carparking.multyplayer"],
    "Free Fire":                    ["com.dts.freefireth","com.dts.freefiremax"],
    "Blood Strike":                 ["com.netease.newspike"],
    "Genshin Impact":               ["com.miHoYo.GenshinImpact"],
    "Honkai Star Rail":             ["com.HoYoverse.hkrpgoversea","com.miHoYo.hkrpg"],
    "Warzone Mobile":               ["com.activision.warzone"],
    "Brawl Stars":                  ["com.supercell.brawlstars"],
    "Stumble Guys":                 ["com.scopely.stumbleguys"],
    "League of Legends Wild Rift":  ["com.riotgames.league.wildrift"],
    "Minecraft":                    ["com.mojang.minecraftpe"]
  };
  const packageForGame = g => (PACKAGES[g]||[]).find(p=>PACKAGE_RE.test(p))||"";

  /* ─── BRIDGE INIT ────────────────────────────────────────────── */
  function initBridge() {
    try {
      if (window.ksu && typeof window.ksu.moduleInfo==="function") {
        const info = parseJson(window.ksu.moduleInfo(), {});
        if (info && typeof info.moduleDir==="string") state.moduleDir = info.moduleDir;
      }
    } catch(_) {}
    if (window.Axeron && typeof window.Axeron.exec==="function") {
      state.api = window.Axeron;
      state.manager = "AxManager";
    } else if (window.ksu && typeof window.ksu.exec==="function") {
      state.api = window.ksu;
      state.manager = "KernelSU WebUI";
    }
    state.connected = !!state.api && (state.manager==="AxManager" || !!state.moduleDir);
    return state.connected;
  }

  /* ─── COMMAND BUILDER ───────────────────────────────────────── */
  function buildCommand(action, args=[]) {
    const q = v => "'"+String(v).replace(/'/g,"'\\''")+"'";
    const entry = state.manager==="AxManager"
      ? 'sh "$AXERONDIR/plugins/$AXERON_PLUGIN/action.sh" '
      : "sh ./action.sh ";
    if (["status","health","capabilities","restore","logs"].includes(action)) {
      return args.length ? null : entry+action;
    }
    if (action==="telemetry") {
      if (args.length>1||(args[0]&&!PACKAGE_RE.test(args[0]))) return null;
      return entry+"telemetry"+(args[0]?" "+q(args[0]):"");
    }
    if (action==="compile") {
      if (args.length!==1||!PACKAGE_RE.test(args[0])) return null;
      return entry+action+" "+q(args[0]);
    }
    if (action==="engine") {
      if (args.length<1||args.length>2) return null;
      const allowed=["network","storage","battery","display","diagnostics","frames",
                     "thermal","memory","graphics","appinfo","power",
                     "cpu-sched","wakelock","process"];
      if (!allowed.includes(args[0])) return null;
      if (["frames","appinfo"].includes(args[0])&&args[1]&&!PACKAGE_RE.test(args[1])) return null;
      return entry+"engine "+args[0]+(args[1]?" "+q(args[1]):"");
    }
    if (action==="config") {
      if (!args.length||args.length>9) return null;
      if (args[0]==="load"&&args.length===1) return entry+"config load";
      if (args[0]==="save"&&args.length>=8) return entry+"config save "+args.slice(1).map(q).join(" ");
      return null;
    }
    if (action==="apply") {
      if (args.length!==6) return null;
      const [profile,pkg,refresh,animation,fps,features]=args;
      if (!["saver","balanced","gaming"].includes(profile)) return null;
      if (pkg&&!PACKAGE_RE.test(pkg)) return null;
      if (refresh&&!["60","90","120","144","165"].includes(refresh)) return null;
      if (animation&&!ANIM_VALUES.includes(animation)) return null;
      if (!FPS_VALUES.includes(String(fps))) return null;
      return entry+"apply "+profile
        +(pkg?" "+q(pkg):" ''")+
        (refresh?" "+q(refresh):" ''")+
        (animation?" "+q(animation):" ''")+
        " "+q(fps)+" "+q(features);
    }
    if (action==="governor") {
      if (args.length!==1||!GOV_VALUES.includes(args[0])) return null;
      return entry+"engine cpu-sched "+q(args[0]);
    }
    if (action==="ram_flush") {
      return entry+"engine memory flush";
    }
    return null;
  }

  /* ─── RUN ACTION ────────────────────────────────────────────── */
  function runAction(action, args=[], done, options={}) {
    if (!state.connected||!state.api) {
      setStatus("Preview only — open the installed plugin WebUI for live Android actions.", false, "#statusText");
      if (done) done(new Error("Bridge unavailable"), "");
      return false;
    }
    if (state.busy&&!options.allowBusy) return false;
    const command = buildCommand(action, args);
    if (!command) {
      setStatus("Action rejected: invalid or unsupported arguments.", false);
      return false;
    }
    state.busy = true;
    const cbName = "ZYN_V27_DONE_"+(++state.callbackSeq);
    const opts = JSON.stringify(state.manager==="AxManager"?{}:{cwd:state.moduleDir});
    window[cbName] = (errno, stdout, stderr) => {
      const out = [stdout,stderr].filter(Boolean).map(String).join("\n").trim();
      state.busy = false;
      try {
        const targetId = options.statusId||"statusText";
        if (errno===0) {
          if (out&&!options.silent) setStatus(out, true, targetId);
          if (typeof done==="function") done(null, out);
        } else {
          setStatus(out||(action+" failed (exit "+errno+")."), false, targetId);
          if (typeof done==="function") done(new Error(out||"Command failed"), out);
        }
      } finally {
        try { delete window[cbName]; } catch(_) { window[cbName]=undefined; }
      }
    };
    try {
      state.api.exec(command, opts, cbName);
      if (!options.silent) setStatus("TITAN engine running…", true, options.statusId||"statusText");
      return true;
    } catch(err) {
      state.busy=false;
      setStatus("Bridge error: "+String(err), false, options.statusId||"statusText");
      if (done) done(err, "");
      return false;
    }
  }

  /* ─── STATUS HELPERS ────────────────────────────────────────── */
  function setStatus(msg, good=true, id="statusText") {
    const node = $("#"+id);
    if (!node) return;
    node.textContent = msg;
    const box = node.closest(".status");
    if (box) box.dataset.state = good?"ok":"error";
  }

  /* ─── ACTIVATE HELPER ────────────────────────────────────────── */
  function activate(selector, attr, value) {
    $$(selector).forEach(el => el.classList.toggle("active", el.dataset[attr]===value));
  }

  /* ─── SUMMARY + QB CHIPS ────────────────────────────────────── */
  function updateSummary() {
    setText("summaryMode", state.mode);
    setText("summaryGame", state.selectedLabel||state.game);
    setText("summaryFps", state.fps+" FPS");
    setText("summaryGov", state.governor);
    if ($("#fpsGameLabel")) $("#fpsGameLabel").textContent = state.game.toUpperCase();
    // QB chips
    if ($("#qbChipMode")) { $("#qbChipMode").textContent=state.mode; }
    if ($("#qbChipFps"))  { $("#qbChipFps").textContent=state.fps+" FPS"; }
    if ($("#qbChipRefresh")) { $("#qbChipRefresh").textContent=state.refresh; }
    if ($("#qbChipGov"))  { $("#qbChipGov").textContent=state.governor; }
    // Titan score
    updateTitanScore();
  }

  function updateTitanScore() {
    const fpsScore = {60:10,90:20,120:35,144:50,165:65,240:80,480:100}[state.fps]||50;
    const modeScore = {
      "Power Save":10,"Balance Mode":30,
      "Performance Boost":65,"Extreme Boost":100
    }[state.mode]||50;
    const govScore = {performance:100,schedutil:80,interactive:65,powersave:20}[state.governor]||60;
    const featCount = Object.values(state.features).filter(Boolean).length;
    const featScore = clamp(featCount*5,0,30);
    const score = Math.round((fpsScore+modeScore+govScore+featScore)/3.7);
    const el = $("#titanScore");
    if (el) {
      animateCounter(el, parseInt(el.dataset.prev||"0"), clamp(score,0,99));
      el.dataset.prev = String(clamp(score,0,99));
    }
  }

  /* ─── ANIMATION SCALE ───────────────────────────────────────── */
  function setAnimation(value, userAction=false) {
    state.animation = String(value);
    if (userAction) state.animationTouched = true;
    const el = $("#animValue");
    if (el) el.textContent = state.animation==="0"?"Off":state.animation+"x";
    const range = $("#animRange");
    if (range) range.value = String(Math.max(0,ANIM_VALUES.indexOf(state.animation)));
    $$(".scale").forEach(b => b.classList.toggle("active", b.dataset.scale===state.animation));
  }
  function updateProfileAnimation() {
    if (state.animationTouched) return;
    const s = (state.mode==="Performance Boost"||state.mode==="Extreme Boost")?"0.5":"1";
    setAnimation(s);
  }

  /* ─── PREFERENCES ───────────────────────────────────────────── */
  function savePreferences() {
    try {
      localStorage.setItem("zynBoosterV27", JSON.stringify({
        mode:state.mode, game:state.game, fps:state.fps,
        refresh:state.refresh, animation:state.animation,
        animationManual:state.animationTouched,
        governor:state.governor, features:state.features
      }));
    } catch(_) {}
  }
  function loadPreferences() {
    const raw = (() => { try { return localStorage.getItem("zynBoosterV27"); } catch(_){return null;} })();
    const d = parseJson(raw, null);
    if (!d||typeof d!=="object") return;
    if (["Power Save","Balance Mode","Performance Boost","Extreme Boost"].includes(d.mode)) state.mode=d.mode;
    if (typeof d.game==="string") state.game=d.game;
    if (FPS_VALUES.includes(String(d.fps))) state.fps=String(d.fps);
    if (REFRESH_VALUES.includes(d.refresh)) state.refresh=d.refresh;
    if (ANIM_VALUES.includes(String(d.animation))) setAnimation(String(d.animation));
    state.animationTouched = d.animationManual===true;
    if (GOV_VALUES.includes(d.governor)) state.governor=d.governor;
    if (d.features&&typeof d.features==="object") {
      Object.keys(state.features).forEach(k=>{
        if (typeof d.features[k]==="boolean") state.features[k]=d.features[k];
      });
    }
    if (!state.animationTouched) updateProfileAnimation();
    activate(".mode","mode",state.mode);
    activate(".game","game",state.game);
    activate("[data-fps]","fps",state.fps);
    activate("[data-refresh]","refresh",state.refresh);
    activate("[data-gov]","gov",state.governor);
    updateSummary();
  }

  /* ─── FEATURE FLAGS ─────────────────────────────────────────── */
  function selectedFeatures() {
    return Object.keys(state.features).filter(k=>state.features[k]).join(",");
  }
  function profileCode() {
    return state.mode==="Power Save"?"saver"
      :(state.mode==="Performance Boost"||state.mode==="Extreme Boost")?"gaming":"balanced";
  }
  function configArgs() {
    const refresh = state.features.refresh?String(parseInt(state.refresh,10)):"";
    const animation = state.features.animation?state.animation:"";
    const feats = selectedFeatures()+(state.animationTouched?",animation_manual":"");
    return ["save",profileCode(),state.game,state.selectedPkg||"",state.fps,refresh,animation,feats||"thermal",state.governor];
  }
  function renderFeatureSwitches() {
    $$("[data-feature]").forEach(input => {
      input.checked = !!state.features[input.dataset.feature];
    });
  }

  /* ─── SAVE / APPLY ──────────────────────────────────────────── */
  function saveToDevice(done) {
    savePreferences();
    if (!state.connected) {
      setStatus("Saved locally. Open the installed plugin WebUI to save to device.", false);
      if (done) done(new Error("Bridge unavailable"));
      return;
    }
    runAction("config", configArgs(), (err,out)=>{
      if (!err) setStatus("PROFILE SAVED. "+(out||""));
      if (done) done(err,out);
    });
  }
  function loadDeviceConfig() {
    if (!state.connected) return;
    runAction("config",["load"],(err,out)=>{
      if (err||!out) return;
      const line = out.split(/\r?\n/).find(x=>x.startsWith("CONFIG="));
      if (!line) return;
      const parts = line.slice(7).split("|");
      if (parts.length<7) return;
      const modeMap={saver:"Power Save",balanced:"Balance Mode",gaming:"Performance Boost"};
      if (modeMap[parts[0]]) state.mode=modeMap[parts[0]];
      if (parts[1]) state.game=parts[1];
      if (PACKAGE_RE.test(parts[2]||"")) state.selectedPkg=parts[2];
      if (FPS_VALUES.includes(parts[3])) state.fps=parts[3];
      if (["60","90","120","144","165"].includes(parts[4])) state.refresh=parts[4]+"Hz";
      if (ANIM_VALUES.includes(parts[5])) state.animation=parts[5];
      const enabled=new Set((parts[6]||"").split(","));
      Object.keys(state.features).forEach(k=>state.features[k]=enabled.has(k));
      state.animationTouched=enabled.has("animation_manual");
      if (parts[7]&&GOV_VALUES.includes(parts[7])) state.governor=parts[7];
      activate(".mode","mode",state.mode);
      activate(".game","game",state.game);
      activate("[data-fps]","fps",state.fps);
      activate("[data-refresh]","refresh",state.refresh);
      activate("[data-gov]","gov",state.governor);
      setAnimation(state.animation);
      renderFeatureSwitches();
      updateSummary();
      savePreferences();
      if (!state.features.telemetry) {
        if (state.pollTimer) clearTimeout(state.pollTimer);
        state.pollTimer=null;
        setText("telemetryLive","MONITOR PAUSED");
      }
    },{silent:true});
  }

  /* ─── QUICK BOOST ───────────────────────────────────────────── */
  function quickBoost() {
    savePreferences();
    if (!state.connected) {
      setStatus("Preview mode: Quick Boost available after connecting the TITAN engine.", false);
      return;
    }
    // Save + Apply in one shot
    runAction("config", configArgs(), (saveErr)=>{
      if (saveErr) return;
      const refresh = state.features.refresh?String(parseInt(state.refresh,10)):"";
      const anim = state.features.animation&&state.animationTouched?state.animation:"";
      runAction("apply",[profileCode(),state.selectedPkg,refresh,anim,state.fps,selectedFeatures()],(err,out)=>{
        if (!err) setStatus("⚡ QUICK BOOST COMPLETE — "+(out||"All supported optimizations applied."));
      });
    });
  }

  /* ─── CPU GOVERNOR ──────────────────────────────────────────── */
  function applyGovernor(gov) {
    state.governor = gov;
    activate("[data-gov]","gov",gov);
    updateSummary();
    savePreferences();
    if (state.connected) {
      runAction("governor",[gov],(err,out)=>{
        const diag=$("#govDiag");
        if (diag) diag.textContent = err?"FAILED":"APPLIED";
        if (!err) setStatus("CPU governor set to "+gov.toUpperCase()+" with read-back verification. "+(out||""));
      });
    } else {
      setStatus("Governor "+gov.toUpperCase()+" selected — connect TITAN engine to apply.");
    }
  }

  /* ─── RAM FLUSH ─────────────────────────────────────────────── */
  function flushRAM() {
    if (!state.connected) {
      setStatus("Connect the TITAN engine to flush RAM.", false, "memStatusText");
      return;
    }
    runAction("engine",["memory","flush"],(err,out)=>{
      if (!err) setStatus("RAM FLUSH COMPLETE — "+(out||"Idle processes evicted."), true, "memStatusText");
      else       setStatus("RAM flush failed: "+(out||err.message), false, "memStatusText");
    },{statusId:"memStatusText"});
  }

  /* ─── RING METER RENDERER ───────────────────────────────────── */
  const CIRC = 2*Math.PI*24; // r=24
  function renderRing(containerId, pct, colorClass) {
    const container = $("#"+containerId);
    if (!container) return;
    const fill = clamp(pct||0, 0, 100)/100;
    const dash = CIRC*fill;
    const gap  = CIRC-dash;
    let svg = container.querySelector("svg");
    if (!svg) {
      container.innerHTML = `<svg width="54" height="54" viewBox="0 0 54 54">
        <circle cx="27" cy="27" r="24" fill="none" stroke="#1e1e22" stroke-width="5"/>
        <circle class="ring-fill ${colorClass}" cx="27" cy="27" r="24" fill="none"
          stroke-width="5" stroke-linecap="round"
          stroke-dasharray="0 ${CIRC}" transform="rotate(-90 27 27)"
          style="transition:stroke-dasharray .42s ease"/>
      </svg>`;
      svg = container.querySelector("svg");
    }
    const arc = svg.querySelector(".ring-fill");
    if (arc) arc.setAttribute("stroke-dasharray", `${dash} ${gap}`);
    // Update label
    const labelId = containerId.replace("ring","").toLowerCase();
    // colors based on load
    if (arc) {
      if (colorClass==="cpu"||colorClass==="gpu"||colorClass==="temp") {
        arc.style.stroke = pct>85?"#ff4855":pct>65?"#ff9944":"#e31c2e";
      }
      if (colorClass==="fps") {
        arc.style.stroke = pct>80?"#55d99a":pct>50?"#f5c542":"#e31c2e";
      }
    }
  }

  /* ─── ANIMATED COUNTER ───────────────────────────────────────── */
  function animateCounter(el, from, to, suffix="", duration=400) {
    if (!el||from===to) { if(el) el.childNodes[0].textContent=to+suffix; return; }
    const start = performance.now();
    const step = (now)=>{
      const t = Math.min((now-start)/duration, 1);
      const eased = 1-(1-t)*(1-t);
      const v = Math.round(from+(to-from)*eased);
      if (el.childNodes[0]) el.childNodes[0].textContent = v+suffix;
      if (t<1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  /* ─── TEXT HELPERS ───────────────────────────────────────────── */
  function setText(id, value, suffix="") {
    const node=$("#"+id);
    if (!node) return;
    const text = (value===undefined||value===null||value==="")?"N/A":String(value);
    node.textContent = text==="N/A"?text:text+suffix;
  }
  function addMetric(label, id, suffix="") {
    const grid=$("#monitorGrid");
    if (!grid||$("#metric_"+id)) return;
    const card=document.createElement("div");
    card.className="metric"; card.id="metric_"+id;
    card.innerHTML=`<div class="label-row">${label}</div>
      <div class="ring-metric">
        <div class="ring-container" id="ring_${id}"></div>
        <div class="ring-info"><strong id="${id}">N/A${suffix?`<span> ${suffix}</span>`:""}</strong><small>${label.toLowerCase()}</small></div>
      </div>`;
    grid.appendChild(card);
  }
  function setMeter(id, value) {
    const el=$("#"+id+"Bar");
    if (el) el.style.width=clamp(Number(value)||0,0,100)+"%";
  }

  /* ─── TELEMETRY RENDER ──────────────────────────────────────── */
  function renderTelemetry(output) {
    const vals={};
    String(output||"").split(/\r?\n/).forEach(line=>{
      const i=line.indexOf("=");
      if (i>0) vals[line.slice(0,i).trim()]=line.slice(i+1).trim();
    });

    const cpuPct = Number(vals.CPU_LOAD)||0;
    const gpuPct = Number(vals.GPU_LOAD)||0;
    const memPct = Number(vals.RAM_USED)||0;
    const maxFps = Math.max(60,Number(vals.MAX_REFRESH)||120);
    const fpsPct = vals.GAME_FPS?(Number(vals.GAME_FPS)/maxFps*100):0;

    // Ring meters
    renderRing("ringCPU",cpuPct,"cpu");
    renderRing("ringGPU",gpuPct,"gpu");
    renderRing("ringMEM",memPct,"mem");
    renderRing("ringFPS",fpsPct,"fps");
    if ($("#ring_bat")) renderRing("ring_bat",Number(vals.BATTERY)||0,"bat");
    if ($("#ring_temp")) {
      const tPct = clamp(((Number(vals.TEMPERATURE)||25)-20)/60*100,0,100);
      renderRing("ring_temp",tPct,"temp");
    }

    // Main metrics — animated counters
    const cpuEl=$("#cpu"); if (cpuEl) animateCounter(cpuEl,parseInt(cpuEl.dataset.prev||"0"),cpuPct,"%"); if(cpuEl) cpuEl.dataset.prev=cpuPct;
    const gpuEl=$("#gpu"); if (gpuEl) animateCounter(gpuEl,parseInt(gpuEl.dataset.prev||"0"),gpuPct,"%"); if(gpuEl) gpuEl.dataset.prev=gpuPct;
    const memEl=$("#mem"); if (memEl) animateCounter(memEl,parseInt(memEl.dataset.prev||"0"),memPct,"%"); if(memEl) memEl.dataset.prev=memPct;
    const fpsEl=$("#fps"); const fpsV=Math.round(Number(vals.GAME_FPS)||0);
    if (fpsEl) { animateCounter(fpsEl,parseInt(fpsEl.dataset.prev||"0"),fpsV," FPS"); fpsEl.dataset.prev=fpsV; }

    // Memory optimizer panel
    if ($("#memUsedVal")) {
      animateCounter($("#memUsedVal"),parseInt($("#memUsedVal").dataset.prev||"0"),memPct);
      $("#memUsedVal").dataset.prev=memPct;
      const circ=176; const fill=clamp(memPct,0,100)/100*circ;
      const arc=$("#memRingFill"); if(arc) arc.setAttribute("stroke-dasharray",fill+" "+(circ-fill));
    }
    setText("memFreeVal",vals.RAM_AVAILABLE_MB,"MB");
    setText("memZramVal",vals.ZRAM_USED_MB,"MB");

    // Extended metrics
    setText("ramAvailable",vals.RAM_AVAILABLE_MB,"MB");
    setText("frameAvg",vals.FRAME_INTERVAL_AVG_MS,"ms");
    setText("frameP95",vals.FRAME_INTERVAL_P95_MS,"ms");
    setText("slowFrames",vals.SLOW_FRAME_PERCENT,"%");
    setText("temp",vals.TEMPERATURE,"°C");
    setText("thermalStatus",vals.THERMAL_STATUS);
    setText("battery",vals.BATTERY,"%");
    setText("cpuFreq",vals.CPU_FREQ_MHZ,"MHz");
    setText("gpuFreq",vals.GPU_FREQ_MHZ,"MHz");
    setText("batteryCurrent",vals.BATTERY_CURRENT_MA,"mA");
    setText("batteryVoltage",vals.BATTERY_VOLTAGE_MV,"mV");
    setText("cpuGovernor",vals.CPU_GOVERNOR||state.governor);
    setText("uptime",vals.UPTIME_SECONDS,"s");
    setText("cpuCores",vals.CPU_CORES_ONLINE);
    setText("zramUsed",vals.ZRAM_USED_MB,"MB");
    setText("memoryPressure",vals.MEMORY_PRESSURE_AVG10,"%");
    setText("refreshCap",vals.REFRESH_CAP,"Hz");
    setText("maxRefresh",vals.MAX_REFRESH,"Hz");
    setText("storageFree",vals.STORAGE_FREE,"MB");
    const fg=vals.FOREGROUND_APP||"N/A";
    setText("foreground",fg);

    const note=$("#monitorNote");
    if (note) {
      const sampled=vals.SAMPLED_PACKAGE&&vals.SAMPLED_PACKAGE!=="N/A"
        ?vals.SAMPLED_PACKAGE:"foreground surface";
      const stamp=new Date(state.lastTelemetryAt).toLocaleTimeString();
      note.textContent="Live telemetry · FPS sampled from SurfaceFlinger for "+sampled+
        " · N/A = sensor not exposed by this ROM · Updated "+stamp;
    }
    setText("telemetryLive","LIVE · TELEMETRY");

    // Sync governor display
    if (vals.CPU_GOVERNOR&&GOV_VALUES.includes(vals.CPU_GOVERNOR)) {
      if (vals.CPU_GOVERNOR!==state.governor) {
        state.governor=vals.CPU_GOVERNOR;
        activate("[data-gov]","gov",state.governor);
        updateSummary();
      }
    }
  }

  /* ─── EXTRA METRICS INJECTION ───────────────────────────────── */
  function addMonitorMetrics() {
    addMetric("BATTERY","bat","%");
    addMetric("TEMPERATURE","temp","°C");
    addMetric("RAM AVAILABLE","ramAvailable","MB");
    addMetric("FRAME AVG","frameAvg","ms");
    addMetric("FRAME P95","frameP95","ms");
    addMetric("SLOW FRAMES","slowFrames","%");
    addMetric("THERMAL STATUS","thermalStatus","");
    addMetric("CPU CLOCK","cpuFreq","MHz");
    addMetric("GPU CLOCK","gpuFreq","MHz");
    addMetric("REFRESH CAP","refreshCap","Hz");
    addMetric("PANEL MAX","maxRefresh","Hz");
    addMetric("STORAGE FREE","storageFree","MB");
    addMetric("BATTERY CURRENT","batteryCurrent","mA");
    addMetric("BATTERY VOLTAGE","batteryVoltage","mV");
    addMetric("CPU GOVERNOR","cpuGovernor","");
    addMetric("DEVICE UPTIME","uptime","s");
    addMetric("CPU CORES ONLINE","cpuCores","");
    addMetric("ZRAM USED","zramUsed","MB");
    addMetric("MEMORY PRESSURE","memoryPressure","%");
    // Foreground card
    const grid=$("#monitorGrid");
    if (grid&&!$("#metric_foreground")) {
      const card=document.createElement("div");
      card.className="metric"; card.id="metric_foreground";
      card.innerHTML=`<div class="label-row">FOREGROUND APP</div>
        <strong id="foreground" style="font-size:11px;margin-top:8px">N/A</strong>`;
      grid.appendChild(card);
    }
  }

  /* ─── TELEMETRY POLLER ──────────────────────────────────────── */
  function startMonitor() {
    if (!state.connected||!state.features.telemetry) return;
    const tick=()=>{
      if (state.busy||state.telemetryBusy||document.visibilityState==="hidden") return;
      state.telemetryBusy=true;
      runAction("telemetry",[state.selectedPkg],(err,out)=>{
        state.telemetryBusy=false;
        if (!err) {
          renderTelemetry(out);
          state.lastTelemetryAt=Date.now();
        } else {
          const n=$("#monitorNote");
          if (n) n.textContent="Telemetry error: "+String(out||err.message||"unknown")+
            ". Check plugin permissions and engine logs.";
          setText("telemetryLive","MONITOR ERROR");
        }
      },{silent:true,allowBusy:false});
      if (!state.busy) state.telemetryBusy=false;
    };
    if (state.pollTimer) clearTimeout(state.pollTimer);
    const schedule=()=>{
      if (state.pollTimer) clearTimeout(state.pollTimer);
      if (document.visibilityState==="hidden") return;
      state.pollTimer=setTimeout(()=>{tick();schedule();},11000);
    };
    tick(); schedule();
    if (!state.visibilityHandler) {
      state.visibilityHandler=()=>{
        if (state.pollTimer) clearTimeout(state.pollTimer);
        state.pollTimer=null;
        if (document.visibilityState==="visible"){tick();schedule();}
      };
      document.addEventListener("visibilitychange",state.visibilityHandler);
    }
  }

  /* ─── RESET ─────────────────────────────────────────────────── */
  function resetSelections() {
    state.mode="Performance Boost"; state.game="Mobile Legends";
    state.selectedPkg=packageForGame(state.game);
    state.fps="144"; state.refresh="60Hz"; state.animation="1";
    state.animationTouched=false; state.governor="schedutil";
    Object.keys(state.features).forEach(k=>state.features[k]=true);
    renderFeatureSwitches();
    activate(".mode","mode",state.mode); activate(".game","game",state.game);
    activate("[data-fps]","fps",state.fps); activate("[data-refresh]","refresh",state.refresh);
    activate("[data-gov]","gov",state.governor);
    updateProfileAnimation(); updateSummary();
    try { localStorage.removeItem("zynBoosterV27"); } catch(_) {}
    setStatus("Dashboard reset to defaults. Applied Android settings were not changed — use Restore to revert.");
  }

  /* ─── ADD RESTORE BUTTON ─────────────────────────────────────── */
  function addRestoreButton() {
    const reset=$("#resetBtn");
    if (!reset||$("#restoreBtn")) return;
    const btn=document.createElement("button");
    btn.type="button"; btn.id="restoreBtn"; btn.className="action secondary";
    btn.textContent="RESTORE ORIGINAL DEVICE SETTINGS";
    reset.insertAdjacentElement("afterend",btn);
    btn.addEventListener("click",()=>{
      if (confirm("Restore the original animation and refresh settings backed up by TITAN?"))
        runAction("restore");
    });
  }

  /* ─── BIND ALL CONTROLS ─────────────────────────────────────── */
  function bindControls() {
    // Mode buttons
    $$(".mode").forEach(btn=>btn.addEventListener("click",()=>{
      state.mode=btn.dataset.mode;
      activate(".mode","mode",state.mode);
      updateProfileAnimation(); updateSummary();
      setStatus(state.mode+" selected — Save & Apply to execute supported Android tuning.");
    }));

    // Game buttons
    $$(".game").forEach(btn=>btn.addEventListener("click",()=>{
      state.game=btn.dataset.game;
      activate(".game","game",state.game);
      state.selectedPkg=packageForGame(state.game);
      state.selectedLabel=state.selectedPkg?state.game:"";
      updateSummary(); savePreferences();
      setStatus(state.selectedPkg
        ?state.game+" selected — Game Mode attempted only if package is installed and OS supports it."
        :state.game+" selected — no verified package mapping; device-wide settings still apply.");
    }));

    // FPS buttons
    $$("[data-fps]").forEach(btn=>btn.addEventListener("click",()=>{
      state.fps=btn.dataset.fps;
      activate("[data-fps]","fps",state.fps);
      updateSummary();
      setStatus(state.fps+" FPS target selected. The game engine and display must support this rate.");
    }));

    // Refresh buttons
    $$("[data-refresh]").forEach(btn=>btn.addEventListener("click",()=>{
      state.refresh=btn.dataset.refresh;
      activate("[data-refresh]","refresh",state.refresh);
      updateSummary();
      setStatus(state.refresh+" selected — TITAN verifies the panel reports this mode before applying.");
    }));

    // Animation scale
    $$(".scale").forEach(btn=>btn.addEventListener("click",()=>{setAnimation(btn.dataset.scale,true);savePreferences();}));
    $("#animRange")?.addEventListener("input",e=>{setAnimation(ANIM_VALUES[Number(e.target.value)]||"1",true);savePreferences();});

    // Governor buttons
    $$("[data-gov]").forEach(btn=>btn.addEventListener("click",()=>{applyGovernor(btn.dataset.gov);}));

    // Feature toggles
    $$("[data-feature]").forEach(input=>input.addEventListener("change",()=>{
      state.features[input.dataset.feature]=input.checked;
      updateSummary(); savePreferences();
    }));

    // Engine lab
    $$("[data-engine]").forEach(btn=>btn.addEventListener("click",()=>{
      const name=btn.dataset.engine;
      const out=$("#engineOutput");
      if (out){out.dataset.state="busy";out.textContent="Running "+name.toUpperCase()+"…";}
      btn.setAttribute("aria-busy","true");
      const fk=({frames:"frames",network:"network",battery:"battery",storage:"storage"})[name];
      if (fk&&!state.features[fk]){
        setStatus("Enable "+fk+" in Engine Features before running this engine.",false);
        btn.removeAttribute("aria-busy"); return;
      }
      const args=["frames","appinfo"].includes(name)?[name,state.selectedPkg]:[name];
      runAction("engine",args,(err,res)=>{
        btn.removeAttribute("aria-busy");
        if (out){out.textContent=res||(err?err.message:"No output returned.");out.dataset.state=err?"error":"ok";}
      });
    }));

    // Save / Apply / Reset
    $("#saveBtn")?.addEventListener("click",()=>saveToDevice());
    $("#applyBtn")?.addEventListener("click",()=>{
      saveToDevice(saveErr=>{
        if (saveErr) return;
        const refresh=state.features.refresh?String(parseInt(state.refresh,10)):"";
        const anim=state.features.animation&&state.animationTouched?state.animation:"";
        runAction("apply",[profileCode(),state.selectedPkg,refresh,anim,state.fps,selectedFeatures()],(err,out)=>{
          if (!err) setStatus("APPLY COMPLETE — "+(out||"All supported optimizations verified and saved."));
        });
      });
    });
    $("#resetBtn")?.addEventListener("click",resetSelections);

    // Health check
    $("#cleanBtn")?.addEventListener("click",()=>runAction("health",[],(err,out)=>{
      const n=$("#monitorNote"); if(n&&!err) n.textContent=out;
    }));

    // Quick Boost
    $("#quickBoostBtn")?.addEventListener("click",quickBoost);

    // RAM flush
    $("#ramFlushBtn")?.addEventListener("click",flushRAM);
    $("#ramReportBtn")?.addEventListener("click",()=>{
      runAction("engine",["memory"],(err,out)=>{
        setStatus(err?"Memory report failed: "+(out||err.message):"Memory report: "+out,
          !err, "memStatusText");
      },{statusId:"memStatusText"});
    });
  }

  /* ─── BRIDGE STATUS DISPLAY ─────────────────────────────────── */
  function updateBridgeUI() {
    const bridgeLabel=$("#bridgeLabel");
    const bridgeState=$("#bridgeState");
    if (state.connected) {
      if (bridgeLabel) bridgeLabel.textContent=state.manager+" · command bridge active";
      if (bridgeState) bridgeState.textContent="ONLINE";
      runAction("status",[],null,{silent:true});
    } else {
      if (bridgeLabel) bridgeLabel.textContent="Open inside AxManager / KernelSU plugin WebUI";
      if (bridgeState) bridgeState.textContent="PREVIEW";
      setStatus("Preview mode: all dashboard controls work locally. Open the installed plugin WebUI for live Android actions.",false);
    }
  }

  /* ─── INIT ──────────────────────────────────────────────────── */
  function start() {
    document.documentElement.dataset.zynVersion="27.0";
    initBridge();
    addMonitorMetrics();
    loadPreferences();
    state.selectedPkg = packageForGame(state.game);
    updateProfileAnimation();
    addRestoreButton();
    renderFeatureSwitches();
    activate("[data-gov]","gov",state.governor);
    bindControls();
    updateBridgeUI();
    if (state.connected) {
      loadDeviceConfig();
      startMonitor();
    }
    updateSummary();
  }

  if (document.readyState==="loading") {
    document.addEventListener("DOMContentLoaded",start,{once:true});
  } else {
    start();
  }
})();
