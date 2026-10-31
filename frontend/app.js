const $ = (sel) => document.querySelector(sel);
const all = (sel) => document.querySelectorAll(sel);
let selectedIP = null;
let lastDevices = [];
const reapplyDaemons = [];
const panelResetters = [];

function runtimeReady() {
  return !!window.runtime?.EventsEmit;
}

function emit(name, data) {
  if (!runtimeReady()) return;
  window.runtime.EventsEmit(name, data || {});
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "show" + (err ? " err" : "");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => (t.className = ""), err ? 5000 : Math.max(1800, msg.length * 55));
}

// window.confirm would show a browser dialog titled "wails.localhost says".
function ask(text) {
  return new Promise((resolve) => {
    const box = $("#ask");
    $("#askText").textContent = text;
    box.classList.remove("hidden");
    const prevFocus = document.activeElement;
    $("#askOk").focus();
    const done = (ok) => {
      box.classList.add("hidden");
      $("#askOk").onclick = null;
      $("#askCancel").onclick = null;
      if (prevFocus && prevFocus.focus) prevFocus.focus();
      resolve(ok);
    };
    $("#askOk").onclick = () => done(true);
    $("#askCancel").onclick = () => done(false);
  });
}

// ---------- appearance (as in dimap/yandex-station-web) ----------
function applyUI() {
  const root = document.documentElement;
  const theme = localStorage.getItem("ui.theme") || "auto";
  const accent = localStorage.getItem("ui.accent") || "";
  if (theme === "auto") delete root.dataset.theme; else root.dataset.theme = theme;
  for (const [k, v] of [["--accent", accent], ["--accent-ink", accent && `color-mix(in srgb, ${accent} 72%, var(--text))`],
    ["--accent-soft", accent && `color-mix(in srgb, ${accent} 15%, var(--card))`]]) {
    v ? root.style.setProperty(k, v) : root.style.removeProperty(k);
  }
  all("#setTheme button").forEach((b) => b.classList.toggle("active", b.dataset.v === theme));
  all("#setAccent .sw").forEach((b) => b.classList.toggle("sel", b.dataset.v === accent));
}
all("#setTheme button").forEach((b) => (b.onclick = () => { localStorage.setItem("ui.theme", b.dataset.v); applyUI(); }));
all("#setAccent .sw").forEach((b) => (b.onclick = () => { localStorage.setItem("ui.accent", b.dataset.v); applyUI(); }));
applyUI();

// ---------- pages ----------
const DEVICE_PAGES = ["overview", "access", "apps", "console"];
let currentTab = "devices";
function showTab(name) {
  currentTab = name;
  document.body.dataset.tab = name;
  const page = DEVICE_PAGES.includes(name) && !selectedIP ? "none" : name;
  all("main.page").forEach((m) => m.classList.toggle("hidden", m.id !== "tab-" + page));
  all("nav.side a").forEach((a) => a.classList.toggle("active", a.dataset.tab === name));
  if (name === "overview") pollStats();
  if (name === "bootstrap") emit("Server", { action: "status" });
  if (name === "settings") emit("cleanup", { action: "status" });
  if (name === "console" && (!termOpen || !term)) termConnect();
  if (name === "log") { const log = $("#log"); log.scrollTop = log.scrollHeight; }
}
all("nav.side a").forEach((a) => {
  a.tabIndex = 0; // anchors without href are not focusable by default
  a.onclick = () => showTab(a.dataset.tab);
});
// Keyboard activation for elements that act as links but are not <a href>:
// sidebar entries, inline data-goto spans.
all("[data-goto]").forEach((el) => (el.tabIndex = 0));
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") {
    const pop = $("#swPop");
    if (!pop.classList.contains("hidden")) {
      pop.classList.add("hidden");
      $("#swBtn").setAttribute("aria-expanded", "false");
      $("#swBtn").focus();
      return;
    }
    return;
  }
  if (ev.key !== "Enter" && ev.key !== " ") return;
  const nav = ev.target.closest("nav.side a");
  if (nav) {
    ev.preventDefault();
    showTab(nav.dataset.tab);
    return;
  }
  const g = ev.target.closest("[data-goto]");
  if (g) {
    ev.preventDefault();
    showTab(g.dataset.goto);
  }
});
document.addEventListener("click", (ev) => {
  const g = ev.target.closest("[data-goto]");
  if (g) showTab(g.dataset.goto);
});

// ---------- journal ----------
let lastLogLine = "";
function appendLog(e) {
  const log = $("#log");
  const row = document.createElement("span");
  row.className = e.level || "info";
  const ts = document.createElement("span");
  ts.className = "ts";
  ts.textContent = e.ts || "";
  row.appendChild(ts);
  row.appendChild(document.createTextNode(e.msg || ""));
  log.appendChild(row);
  log.appendChild(document.createTextNode("\n"));
  while (log.childNodes.length > 4000) log.removeChild(log.firstChild);
  if ($("#autoscroll").checked) log.scrollTop = log.scrollHeight;
  lastLogLine = (e.msg || "").split("\n")[0];
  if (!busyNow) $("#actText").textContent = lastLogLine;
  // The bottom activity bar is the one place a live error surfaces; no
  // extra toast for the same text.
  $("#activity").classList.toggle("err", e.level === "err");
}

let busyNow = false;
function setBusy(e) {
  busyNow = !!e.on;
  all("button:not([data-free])").forEach((b) => (b.disabled = !!e.on));
  $("#busy").classList.toggle("hidden", !e.on);
  $("#busyText").textContent = e.on ? e.what || "…" : "";
  $("#actSpin").classList.toggle("hidden", !e.on);
  $("#activity").classList.toggle("busy", !!e.on);
  if (e.on) $("#activity").classList.remove("err");
  $("#actText").textContent = e.on ? e.what || "…" : lastLogLine || "Готово";
  if (!e.on) $("#scanProgress").textContent = "";
  if (!e.on && selectedIP) renderDeviceInfo();
}

// ---------- adapters ----------
let lastAdapters = [];
// name -> checked. Defaults (physical on, virtual off) are applied once.
const adapterChoice = new Map();

function enabledAdapterNames() {
  return lastAdapters.filter((ifc) => adapterChoice.get(ifc.name)).map((ifc) => ifc.name);
}

function renderAdapters(e) {
  const list = $("#adapterList");
  list.innerHTML = "";
  lastAdapters = e.list || [];
  // Physical adapters first (they are what you scan with), virtual last;
  // within each group active before inactive, names alphabetical.
  const sorted = [...lastAdapters].sort((a, b) =>
    ((a.virtual ? 1 : 0) - (b.virtual ? 1 : 0)) || (b.up - a.up) || a.name.localeCompare(b.name));
  for (const ifc of sorted) {
    if (!adapterChoice.has(ifc.name)) adapterChoice.set(ifc.name, !ifc.virtual);
    const row = document.createElement("label");
    row.className = "adapterRow" + (ifc.virtual ? " virtual" : "");
    const label = document.createElement("span");
    label.className = "adapterName";
    label.textContent = ifc.name + (ifc.virtual ? " · вирт." : "");
    const nets = document.createElement("span");
    nets.className = "adapterNets";
    nets.textContent = (ifc.cidrs || []).filter(Boolean).join(", ");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.className = "switch";
    cb.checked = !!adapterChoice.get(ifc.name);
    cb.onchange = () => adapterChoice.set(ifc.name, cb.checked);
    row.append(label, nets, cb);
    list.appendChild(row);
  }
}
// Pre-flight: port chips and the start-button gate. Free ports render
// no clutter; an occupied one turns the chip red, names its holder, and
// disables «Запустить» until it clears. The firewall verdict lives in
// the journal only.
window.runtime?.EventsOn?.("serverCheck", (e) => {
  const box = $("#serverPorts");
  if (!box) return;
  box.innerHTML = "";
  const busy = $("#serverBusy");
  const start = $("#serverBtn");
  const holders = [];
  for (const p of e.ports || []) {
    if (p.free) continue;
    const c = document.createElement("span");
    c.className = "chip bad";
    c.textContent = `${p.port} ${p.proto.toUpperCase()}`;
    c.title = p.holder ? `занят: ${p.holder}` : "порт занят";
    box.appendChild(c);
    holders.push(`${p.port} → ${p.holder || "неизвестный процесс"}`);
  }
  if (e.running) {
    // The Server's own listeners hold the ports; that is fine.
    busy.hidden = true;
    return;
  }
  busy.hidden = !holders.length;
  busy.textContent = holders.length ? "Порты заняты: " + holders.join(", ") + ". Остановите занявшую программу или отключите её адаптер." : "";
  const hasStart = !!start;
  if (hasStart) {
    const blocked = holders.length > 0;
    start.disabled = blocked;
    renderServerBtn();
    if (blocked) start.title = "Освободите порты выше, затем повторите";
  }
});

// The Jailbreak page tells the owner which address to put into the
// router's DNS setting: every address of an active physical adapter.
function renderServerIPs() {
  const el = $("#serverIPs");
  if (!el) return;
  const ips = [];
  for (const ifc of lastAdapters) {
    if (ifc.virtual || !ifc.up) continue;
    for (const ip of ifc.addrs || []) {
      if (!ips.includes(ip)) ips.push(ip);
    }
  }
  el.textContent = ips.length ? ips.join("  ·  ") : "—";
}
window.runtime?.EventsOn?.("adapters", (e) => { renderAdapters(e); renderServerIPs(); });

// ---------- devices ----------
function modelOf(d) {
  return d.model || d.modelRaw || d.platform || "Яндекс Станция";
}

function deviceTags(d) {
  const tags = document.createElement("div");
  tags.className = "tags";
  const mk = (label, cls, title) => {
    const t = document.createElement("span");
    t.className = "tag " + (cls || "");
    t.textContent = label;
    if (title) t.title = title;
    tags.appendChild(t);
  };
  let adbCls = "on";
  let adbTitle = "";
  if (!(d.ports && d.ports["5555"])) {
    // Closed ADB is the stock state, not a fault: neutral, with the way in.
    adbCls = "";
    adbTitle = "сетевой ADB не открыт — включается при первичной настройке";
  } else if (d.adbPending) {
    adbCls = "warn";
    adbTitle = "порт открыт, но adb не установлен";
  } else if (d.identVia !== "adb" && d.identErr) {
    adbCls = "warn";
    adbTitle = d.identErr;
  }
  // The root flag leads the tag row; the color alone carries yes/no.
  if (d.rootKnown && d.root) mk("root", "on", "получен root-шелл");
  else mk("root", "red", "root не обнаружен — смотрите Jailbreak");
  mk("adb", adbCls, adbTitle);
  const sshCls = d.sshLocked ? "warn" : "on";
  const sshTitle = d.sshLocked ? "порт открыт, но подходящие учётные данные не найдены" : "";
  if (d.ports && d.ports["2222"]) mk("SSH:2222", sshCls, sshTitle);
  if (d.ports && d.ports["22"]) mk("SSH:22", sshCls, sshTitle);
  return tags;
}

function renderDevices(e) {
  const list = $("#deviceList");
  list.innerHTML = "";
  const found = e.list || [];
  const devices = found.filter((d) => d.isYandex);
  $("#navCount").textContent = devices.length ? String(devices.length) : "";
  if (!devices.length) {
    list.innerHTML = `<div class="empty">${found.length ? "Колонок не найдено." : "Список пуст — просканируйте сеть."}</div>`;
  }
  for (const d of devices) {
    const row = document.createElement("div");
    row.className = "dev" + (d.ip === selectedIP ? " selected" : "");
    row.appendChild(stationIcon(d));
    const body = document.createElement("div");
    body.className = "devBody";
    const name = document.createElement("div");
    name.className = "name";
    name.textContent = d.nickname || modelOf(d);
    const sub = document.createElement("div");
    sub.className = "ip";
    sub.textContent = [d.nickname ? modelOf(d) : "", d.ip, d.sku].filter(Boolean).join(" · ");
    body.append(name, sub);
    const devid = d.deviceId || deviceIdFromHostname(d.hostname) || "";
    if (devid) {
      const did = document.createElement("div");
      did.className = "devid";
      did.textContent = devid;
      body.appendChild(did);
    }
    body.appendChild(deviceTags(d));
    row.appendChild(body);
    row.onclick = () => { selectDevice(d.ip); showTab("overview"); };
    list.appendChild(row);
  }
  renderSwitcher();
}

function renderSwitcher() {
  const pop = $("#swPop");
  pop.innerHTML = "";
  for (const d of lastDevices.filter((x) => x.isYandex)) {
    const b = document.createElement("button");
    b.type = "button";
    b.dataset.free = "";
    b.className = d.ip === selectedIP ? "sel" : "";
    const ic = stationIcon(d);
    ic.className = "sw-icon";
    const txt = document.createElement("span");
    txt.className = "sw-text";
    txt.innerHTML = `<b>${escapeHtml(d.nickname || modelOf(d))}</b><small>${escapeHtml(d.ip)}</small>`;
    b.append(ic, txt);
    b.onclick = () => { pop.classList.add("hidden"); selectDevice(d.ip); if (!DEVICE_PAGES.includes(currentTab)) showTab("overview"); };
    pop.appendChild(b);
  }
  const more = document.createElement("button");
  more.type = "button";
  more.dataset.free = "";
  more.className = "sw-more";
  more.textContent = "Найти колонки…";
  more.onclick = () => { pop.classList.add("hidden"); showTab("devices"); };
  pop.appendChild(more);

  const d = lastDevices.find((x) => x.ip === selectedIP);
  $("#swIcon").innerHTML = "";
  if (d) $("#swIcon").appendChild(stationIcon(d));
  $("#swName").textContent = d ? d.nickname || modelOf(d) : "Колонка не выбрана";
  $("#swSub").textContent = d ? d.ip : "выберите из списка";
  // Only ADB/SSH count as a control channel; glagol presence is assumed
  // for every station and is not surfaced in the UI.
  const ctrl = d ? [d.ports?.["5555"] && "ADB", d.ports?.["2222"] && "SSH 2222", d.ports?.["22"] && "SSH 22"].filter(Boolean) : [];
  // Root is the status that matters: green only with verified root; a
  // working channel without root says so; anything else is "no root
  // detected" — undetected and verified-absent are the same state here.
  const rooted = !!(d && d.rootKnown && d.root);
  let dotCls = " off";
  let text = "Root не обнаружен";
  if (rooted) {
    dotCls = " on";
    text = d.identVia ? "Подключено по " + d.identVia : "Root есть";
  } else if (d && d.identVia) {
    dotCls = " mid";
    text = "Подключено по " + d.identVia + " · без root";
  }
  $("#connDot").className = "dot" + (!d ? "" : dotCls);
  $("#connText").textContent = !d ? "Не выбрана" : text;
  $("#connIP").textContent = d ? [d.ip, ...ctrl].join(" · ") : "—";
}
$("#swBtn").onclick = (ev) => {
  ev.stopPropagation();
  const hidden = $("#swPop").classList.toggle("hidden");
  $("#swBtn").setAttribute("aria-expanded", hidden ? "false" : "true");
};
document.addEventListener("click", (ev) => {
  if (!ev.target.closest(".switcher")) {
    $("#swPop").classList.add("hidden");
    $("#swBtn").setAttribute("aria-expanded", "false");
  }
});

// Without a chosen color the first model color is shown, but d.color stays
// empty so the picker still shows "—".
function stationIcon(d) {
  const wrap = document.createElement("span");
  wrap.className = "devIcon";
  const displayColor = d.color || (d.colors && d.colors.length ? d.colors[0] : "");
  const colorIcon = displayColor && d.icons ? d.icons[displayColor] : "";
  const src = colorIcon || d.icon || "";
  if (src) {
    wrap.innerHTML = `<img src="icons/${escapeHtml(src)}" alt="" draggable="false">`;
    return wrap;
  }
  let hue = displayColor ? colorHex(displayColor) : "";
  if (!hue) {
    const model = (d.model || "").toLowerCase();
    if (model.includes("макс")) hue = "#3a3f4b";
    else if (model.includes("миди")) hue = "#b08968";
    else if (model.includes("мини 3")) hue = "#4cc38a";
    else if (model.includes("мини 2")) hue = "#7d8794";
    else if (model.includes("мини")) hue = "#e5b567";
    else if (model.includes("лайт 2")) hue = "#c9a0dc";
    else if (model.includes("лайт")) hue = "#9aa7b8";
    else if (model.includes("стрит")) hue = "#e06c75";
    else hue = "#5aa9ff";
  }
  wrap.innerHTML = `<svg viewBox="0 0 24 24" width="26" height="26" aria-hidden="true">
    <path fill="${hue}" d="M12 2.5c-3.6 0-6.5 2-6.5 4.5v10c0 2.5 2.9 4.5 6.5 4.5s6.5-2 6.5-4.5v-10c0-2.5-2.9-4.5-6.5-4.5z"/>
    <path fill="#0f1116" opacity="0.35" d="M12 2.5c-3.6 0-6.5 2-6.5 4.5v10c0 2.5 2.9 4.5 6.5 4.5s6.5-2 6.5-4.5v-10c0-2.5-2.9-4.5-6.5-4.5zm0 1.8c2.7 0 4.7 1.3 4.7 2.7v10c0 1.4-2 2.7-4.7 2.7s-4.7-1.3-4.7-2.7v-10c0-1.4 2-2.7 4.7-2.7z"/>
    <circle cx="12" cy="9" r="2.2" fill="#0f1116" opacity="0.55"/>
  </svg>`;
  return wrap;
}

function colorHex(name) {
  const m = {
    beige: "#d9c4a3", black: "#1c1f24", blue: "#5aa9ff", brown: "#8a5a3b",
    coral: "#ff8a80", copper: "#c08a5a", gray: "#7d8794", green: "#4cc38a",
    lilac: "#c9a0dc", mint: "#9fd6c0", orange: "#e5b567",
    pink: "#f48fb1", purple: "#9c7ad6", raspberry: "#c0486b", red: "#e06c75",
    ruby: "#9b1f3a", turquoise: "#4dd0c4", violet: "#7e5fb0", white: "#e8edf2",
    yellow: "#f3d24e",
  };
  return m[name] || "";
}

function deviceIdFromHostname(h) {
  if (!h) return "";
  const m = h.match(/^yandex[a-z]+-(.+)$/i);
  return m ? m[1] : "";
}

function selectDevice(ip) {
  selectedIP = ip;
  all("#deviceList .dev").forEach((el) => el.classList.remove("selected"));
  resetAsyncPanels();
  resetStats();
  emit("shell", { action: "close" });
  termOpen = false;
  // Buffered keystrokes belong to the previous device only.
  termBuf = "";
  term?.reset();
  renderDevices({ list: lastDevices });
  renderDeviceInfo();
  if (DEVICE_PAGES.includes(currentTab)) showTab(currentTab);
  emit("ota", { action: "status", ip });
  emit("ssh", { action: "status", ip });
  emit("yse", { action: "status", ip });
  emit("yam", { action: "status", ip });
  emit("betteryam", { action: "status", ip });
  emit("adbboot", { action: "status", ip });
  pollStats();
}

// Status panels (SSH, OTA, ADB, YAM, BetterYAM) are filled in asynchronously
// per-host after a device is selected. Without this reset, switching devices
// left the previous host's SSH port/security/keys and daemon chips on screen
// — looking like the new host's config — until that host's own status
// replies arrived.
function resetAsyncPanels() {
  // Back to the install defaults (2222, keys only) rather than leaving no
  // radio selected, so "Установить" still works before the real status for
  // this host comes back.
  all("input[name=sshPort]").forEach((r) => (r.checked = r.value === "2222"));
  $("#sshPortCustom").value = "";
  $("#sshPortCustom").classList.remove("on");
  $("#sshPortCustom").disabled = true;
  all("input[name=sshSecurity]").forEach((r) => (r.checked = r.value === "keyonly"));
  syncSSHKeysBlock();
  $("#keys").value = "";

  $("#otaChips").innerHTML = '<span class="chip">не проверено</span>';
  paintToggle($("#otaToggle"), false, "Вернуть", "Отключить");

  lastADB = null;
  $("#adbChips").innerHTML = '<span class="chip">не проверено</span>';
  paintToggle($("#adbRun"), false, "Стоп", "Старт");
  paintToggle($("#adbBoot"), false, "Авто выкл", "Автозапуск");

  panelResetters.forEach((fn) => fn());
}

function renderDeviceInfo() {
  const d = lastDevices.find((x) => x.ip === selectedIP);
  if (!d) {
    $("#statsGrid").classList.remove("hidden");
    $("#noStats").classList.add("hidden");
    return;
  }
  const model = d.model || d.modelRaw || (d.isYandex ? "уточняется" : "—");
  const platform = d.compat || d.platform || "";
  const v = (s) => (s ? escapeHtml(s) : "—");
  // "full" in cls makes the pair span both columns of the two-column kv.
  const row = (k, val, cls) => {
    const full = (cls || "").split(" ").includes("full") ? " full" : "";
    return `<dt class="${full.trim()}">${k}</dt><dd class="${cls || ""}">${val}</dd>`;
  };
  const colors = d.colors || [];
  const colorRu = {
    beige: "бежевый", black: "чёрный", blue: "синий", coral: "коралловый",
    copper: "медный", gray: "серый", green: "зелёный", lilac: "сиреневый",
    mint: "мятный", orange: "оранжевый", pink: "розовый", purple: "фиолетовый",
    raspberry: "малиновый", red: "красный", ruby: "рубиновый",
    turquoise: "бирюзовый", violet: "фиолетовый", white: "белый",
    yellow: "жёлтый",
  };
  const colorLabel = (c) => {
    if (c.startsWith("clock-")) {
      const base = colorRu[c.slice(6)] || c.slice(6);
      return base + " (с часами)";
    }
    return colorRu[c] || c;
  };
  const colorOpts = ['<option value="">—</option>'].concat(colors.map((c) =>
    `<option value="${escapeHtml(c)}"${c === d.color ? " selected" : ""}>${escapeHtml(colorLabel(c))}</option>`)).join("");
  // Row order is knowledge order: what the network always answers first,
  // what only a shell on the station can answer last. Undetected root
  // counts as non-root.
  const rooted = !!(d.rootKnown && d.root);
  const rootFlag = rooted
    ? '<span class="chip ok">да</span>'
    : '<span class="chip bad">нет</span>';
  $("#deviceInfo").innerHTML = `
    <dl class="kv cols">
      ${row("Псевдоним", `<span class="nickline"><input class="field" id="nickInline" value="${escapeHtml(d.nickname || "")}" placeholder="имя" spellcheck="false"><button type="button" id="nickApply" class="icon small" data-free title="Сохранить">✓</button><button type="button" id="nickClear" class="icon small" data-free title="Очистить">×</button></span>`, "plain keep")}
      ${row("Цвет", `<span class="nickline"><select class="field" id="colorInline">${colorOpts}</select></span>`, "plain keep")}
      ${row("Модель", v(model), "plain")}
      ${row("Код модели", v(d.sku))}
      ${row("Платформа", v(platform))}
      ${row("Device ID", v(d.deviceId), "keep")}
      ${row("IP", v(d.ip))}
      ${row("MAC", v(d.mac))}
      ${row("Hostname", v(d.hostname))}
    </dl>
    <div class="kv-split">Доступ к колонке</div>
    <dl class="kv cols">
      ${row("Прошивка", v(d.firmware), "keep")}
      ${row("Канал", v(d.identVia))}
      ${row("Root", rootFlag, "plain")}
    </dl>`;
  all(".devsub").forEach((el) => (el.textContent = [d.nickname || model, d.nickname ? model : "", d.ip, d.firmware].filter(Boolean).join(" · ")));
  renderYSEChip(!!d.yseKnown, !!d.yseInstalled);
  renderYAMChip(!!d.yamKnown, !!d.yamInstalled);
  const nick = $("#nickInline");
  const saveNick = (value) => {
    const next = value.trim();
    if (next === (d.nickname || "")) return;
    emit("setNickname", { ip: selectedIP, nickname: next });
  };
  $("#nickApply").onclick = () => saveNick(nick.value);
  $("#nickClear").onclick = () => {
    nick.value = "";
    if (d.nickname) emit("setNickname", { ip: selectedIP, nickname: "" });
  };
  nick.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") { ev.preventDefault(); saveNick(nick.value); }
  });
  $("#colorInline").onchange = () => emit("setColor", { ip: selectedIP, color: $("#colorInline").value });

  // The widgets need verified root on a control channel; undetected root
  // counts as none (a flapping channel cannot separate the two cases).
  // Anything else gets one short card that names the cause.
  $("#statsGrid").classList.toggle("hidden", !rooted);
  $("#noStats").classList.toggle("hidden", rooted);
  $("#goBootstrap").onclick = () => showTab("bootstrap");
  const hasChannel = !!(d.ports && (d.ports["5555"] || d.ports["2222"] || d.ports["22"]));
  const needChannel = ["#otaToggle", "#otaStatus", "#adbRun", "#adbBoot", "#sshInstall", "#sshUninstall", "#reboot", "#ysePkg", "#yamPkg", "#yamPanel", "#byamRun", "#byamBoot", "#byamPkg"];
  needChannel.forEach((sel) => {
    const b = $(sel);
    if (!b) return;
    b.disabled = !hasChannel || busyNow;
    b.title = hasChannel ? "" : "Нужен канал управления (ADB или SSH). Включите сетевой ADB на колонке.";
  });
  if (hasChannel) {
    reapplyDaemons.forEach((fn) => fn());
    if (lastADB && lastADB.ip === selectedIP) renderADBBoot(lastADB);
  }
}

window.runtime?.EventsOn?.("devices", (e) => {
  lastDevices = e.list || [];
  renderDevices(e);
  if (selectedIP) renderDeviceInfo();
});

// ---------- OTA ----------
function otaChip(label, good) {
  const chip = document.createElement("span");
  chip.className = "chip " + (good ? "ok" : "bad");
  chip.textContent = label + (good ? " ✓" : " ✕");
  return chip;
}

let lastOTA = null;
function otaBlocked(st) {
  // Disk state decides: the updater process may linger from a previous
  // boot and applies nothing while the key and the applier are ours.
  return !!st.scriptPresent && !!st.keyReplaced && !!st.applierStubbed && !st.updaterInConf;
}
function renderOTAStatus(e) {
  if (e.ip !== selectedIP) return;
  lastOTA = e;
  const st = e.status || {};
  const box = $("#otaChips");
  box.innerHTML = "";
  if (!st.scriptPresent) {
    box.innerHTML = '<span class="chip mid">скрипт ещё не установлен</span>';
  } else {
    box.appendChild(otaChip("ключ", !!st.keyReplaced));
    box.appendChild(otaChip("апдейтер", !!st.applierStubbed));
    box.appendChild(otaChip("launch.json", !st.updaterInConf));
    if (st.updaterRunning) {
      // Informational: the process predates the edit and applies nothing.
      const c = document.createElement("span");
      c.className = "chip mid";
      c.title = "maind --updatesd ещё работает с прошлой загрузки; применить обновление он не может — ключ и аплаер заменены";
      c.textContent = "процесс работает";
      box.appendChild(c);
    }
  }
  paintToggle($("#otaToggle"), otaBlocked(st), "Вернуть", "Отключить");
}

window.runtime?.EventsOn?.("log", appendLog);
window.runtime?.EventsOn?.("busy", setBusy);
window.runtime?.EventsOn?.("otaStatus", renderOTAStatus);

// ---------- SSH ----------
// A blank-password install does not use keys; the block stays hidden until
// "только ключи" is chosen again.
function syncSSHKeysBlock() {
  const blank = document.querySelector("input[name=sshSecurity]:checked")?.value === "blank";
  $("#sshKeysBlock").classList.toggle("hidden", blank);
}
all("input[name=sshSecurity]").forEach((r) => (r.onchange = syncSSHKeysBlock));
syncSSHKeysBlock();

window.runtime?.EventsOn?.("sshStatus", (e) => {
  if (e.ip !== selectedIP) return;
  const installed = !!e.installed;
  const port = e.port || 2222;
  const blank = !!e.blankPwd;
  const portVal = (port === 2222 || port === 22) ? String(port) : "custom";
  all("input[name=sshPort]").forEach((r) => {
    r.checked = r.value === portVal;
  });
  $("#sshPortCustom").classList.toggle("on", portVal === "custom");
  $("#sshPortCustom").disabled = portVal !== "custom";
  if (portVal === "custom") $("#sshPortCustom").value = String(port);
  all("input[name=sshSecurity]").forEach((r) => {
    r.checked = blank ? r.value === "blank" : r.value === "keyonly";
  });
  syncSSHKeysBlock();
  if (typeof e.keys === "string") {
    $("#keys").value = e.keys;
    if (e.keys.trim()) {
      const custom = document.querySelector("input[name=sshKeySrc][value=custom]");
      if (custom && !custom.checked) {
        custom.checked = true;
        custom.dispatchEvent(new Event("change"));
      }
    }
  }
  if (installed) {
    appendLog({ level: "info", msg: `SSH installed: port ${port}, ${blank ? "blank password" : "keys only"}` });
  }
});
window.runtime?.EventsOn?.("genkey", (e) => {
  const ta = $("#keys");
  const line = (e.pub || "").trim();
  if (line && !ta.value.includes(line.split(" ").slice(0, 2).join(" "))) {
    ta.value = (ta.value.trim() ? ta.value.trim() + "\n" : "") + line;
  }
  $("#privKey").value = e.path || $("#privKey").value;
  appendLog({ level: "ok", msg: "key added to the authorized_keys list" });
});
window.runtime?.EventsOn?.("scanProgress", (e) => {
  $("#scanProgress").textContent = `${e.checked}/${e.total} · найдено ${e.found}`;
});
window.runtime?.EventsOn?.("state", (e) => {
  if (e.privKey) $("#privKey").value = e.privKey;
  const p = e.payloads || {};
  const missing = Object.entries(p).filter(([, v]) => !v).map(([k]) => k);
  if (missing.length) {
    appendLog({ level: "warn", msg: "payloads not embedded: " + missing.join(", ") + " (see payloads/ in README). Some actions will not work." });
  }
  $("#allowSSHAgent").checked = !!e.allowSSHAgent;
  if (e.version) {
    $("#aboutVersion").textContent = "Yandex Station ToolKit " + e.version;
    $("#brandVersion").textContent = e.version;
  }
});
// The Go side can raise the in-app confirmation card (e.g. the adb
// download offer) from a goroutine; the modal below answers it.
window.runtime?.EventsOn?.("askUI", (e) => {
  ask(e.question).then((ok) => emit("askUIResult", { id: e.id, ok }));
});

$("#allowSSHAgent").onchange = () => {
  emit("setSSHAgentAllowed", { allow: $("#allowSSHAgent").checked });
};

// Cleanup of the downloaded external helpers (platform-tools + firmware
// files). The button asks first; Go reports the occupied disk back.
function renderCleanup(e) {
  const info = $("#cleanupInfo");
  const btn = $("#cleanupBtn");
  if (!info || !btn) return;
  const parts = [];
  if (e.adbBytes > 0) parts.push("adb " + (e.adbBytes / 1048576).toFixed(1) + " МиБ");
  if (e.fwBytes > 0) parts.push("прошивки " + (e.fwBytes / 1048576).toFixed(1) + " МиБ");
  info.textContent = parts.length ? parts.join(" · ") : "Ничего не скачано";
  btn.disabled = !parts.length;
}
window.runtime?.EventsOn?.("cleanupState", renderCleanup);
$("#cleanupBtn").onclick = () =>
  ask("Удалить скачанные adb и прошивки?").then((ok) => ok && emit("cleanup", { action: "run" }));

$("#rescan").onclick = () => emit("scan", { adapters: enabledAdapterNames() });
$("#connect").onclick = () => {
  const ip = $("#manualIP").value.trim();
  if (ip) emit("connect", { ip });
};
$("#manualIP").addEventListener("keydown", (ev) => ev.key === "Enter" && $("#connect").click());

$("#otaToggle").onclick = async () => {
  const st = (lastOTA && lastOTA.status) || {};
  if (otaBlocked(st)) {
    if (!await ask("Вернуть заводские настройки обновлений на " + selectedIP + "?")) return;
    emit("ota", { action: "restore", ip: selectedIP });
  } else {
    if (!await ask("Отключить OTA-обновления на " + selectedIP + "?")) return;
    emit("ota", { action: "disable", ip: selectedIP });
  }
};
$("#otaStatus").onclick = () => emit("ota", { action: "status", ip: selectedIP });

// ---------- ADB ----------
let lastADB = null;
function paintToggle(btn, on, onLabel, offLabel) {
  if (!btn) return;
  btn.textContent = on ? onLabel : offLabel;
  btn.classList.toggle("danger", on);
  btn.classList.toggle("primary", !on);
}
function renderADBBoot(e) {
  if (!e || e.ip !== selectedIP) return;
  lastADB = e;
  const box = $("#adbChips");
  box.innerHTML = "";
  box.appendChild(otaChip("adbd", !!e.running));
  box.appendChild(otaChip("автозапуск", !!e.autostart));
  paintToggle($("#adbRun"), !!e.running, "Стоп", "Старт");
  paintToggle($("#adbBoot"), !!e.autostart, "Авто выкл", "Автозапуск");
}
window.runtime?.EventsOn?.("adbBoot", renderADBBoot);
$("#adbRun").onclick = () => emit("adbboot", { action: lastADB && lastADB.running ? "stop" : "start", ip: selectedIP });
$("#adbBoot").onclick = async () => {
  const on = lastADB && lastADB.autostart;
  const q = on ? "Убрать автозапуск ADB на " : "Включить автозапуск ADB (:5555) на ";
  if (!await ask(q + selectedIP + "?")) return;
  emit("adbboot", { action: on ? "autostart-off" : "autostart-on", ip: selectedIP });
};
$("#genKey").onclick = () => emit("genkey", {});
$("#sshInstall").onclick = async () => {
  const portMode = document.querySelector("input[name=sshPort]:checked").value;
  const security = document.querySelector("input[name=sshSecurity]:checked").value;
  const keySrc = document.querySelector("input[name=sshKeySrc]:checked").value;
  let keys = "";
  let githubUser = "";
  if (security === "blank") {
    // Blank-password install does not use keys.
  } else if (keySrc === "custom") {
    keys = $("#keys").value.trim();
    if (!keys) {
      appendLog({ level: "err", msg: "provide at least one public key, or generate one" });
      return;
    }
  } else {
    githubUser = $("#githubUser").value.trim();
    if (!githubUser) {
      appendLog({ level: "err", msg: "enter a GitHub username to import keys" });
      return;
    }
  }
  const portLabel = portMode === "custom" ? ($("#sshPortCustom").value.trim() || "—") : portMode;
  let summary = `Установить Dropbear SSH на ${selectedIP}?\nпорт: ${portLabel}\nбезопасность: ${security === "blank" ? "пустой пароль (небезопасно)" : "только по ключам"}`;
  if (security !== "blank") summary += `\nключи: ${keySrc === "custom" ? "свои" : "GitHub: " + githubUser}`;
  if (!await ask(summary)) return;
  emit("ssh", {
    action: "install",
    ip: selectedIP,
    keys,
    privateKey: $("#privKey").value.trim(),
    portMode,
    portCustom: $("#sshPortCustom").value.trim(),
    security,
    githubUser,
  });
};
let sshKeyPath = "";
let sshCheckViaMode = "agent";
let sshKeyEncrypted = false;
function syncSSHCheck() {
  const via = sshCheckViaMode;
  $("#sshPickKey").classList.toggle("hidden", via !== "file");
  $("#sshKeyName").classList.toggle("hidden", via !== "file" || !sshKeyPath);
  $("#privKey").classList.toggle("hidden", via !== "paste");
  $("#sshPass").classList.toggle("hidden", !sshKeyEncrypted);
}
all("#sshCheckSeg button").forEach((b) => {
  b.onclick = () => {
    sshCheckViaMode = b.dataset.via;
    all("#sshCheckSeg button").forEach((x) => x.classList.toggle("active", x === b));
    sshKeyEncrypted = false;
    syncSSHCheck();
    if (sshCheckViaMode === "paste" && $("#privKey").value.trim()) inspectPastedKey();
    if (sshCheckViaMode === "file" && sshKeyPath) emit("inspectkey", { via: "file", material: sshKeyPath });
  };
});
syncSSHCheck();
$("#sshPickKey").onclick = () => emit("pickkey", {});
window.runtime?.EventsOn?.("pickKey", (e) => {
  sshKeyPath = e.path || "";
  $("#sshKeyName").textContent = sshKeyPath ? sshKeyPath.split(/[\\/]/).pop() : "";
  sshKeyEncrypted = false;
  syncSSHCheck();
  if (sshKeyPath) emit("inspectkey", { via: "file", material: sshKeyPath });
});
window.runtime?.EventsOn?.("keyInfo", (e) => {
  sshKeyEncrypted = !!e.encrypted;
  syncSSHCheck();
  if (e.err) appendLog({ level: "err", msg: e.err });
});
let pasteTimer = 0;
function inspectPastedKey() {
  const text = $("#privKey").value.trim();
  if (!text || !text.includes("PRIVATE KEY")) {
    sshKeyEncrypted = false;
    syncSSHCheck();
    return;
  }
  emit("inspectkey", { via: "paste", material: text });
}
$("#privKey").addEventListener("input", () => {
  clearTimeout(pasteTimer);
  pasteTimer = setTimeout(inspectPastedKey, 300);
});
$("#sshTest").onclick = () => {
  const via = sshCheckViaMode;
  emit("ssh", {
    action: "test",
    ip: selectedIP,
    via,
    privateKey: via === "file" ? sshKeyPath : (via === "paste" ? $("#privKey").value.trim() : ""),
    passphrase: sshKeyEncrypted ? $("#sshPass").value : "",
  });
};
$("#sshUninstall").onclick = async () => {
  if (!await ask("Удалить автозапуск SSH с " + selectedIP + "?")) return;
  emit("ssh", { action: "uninstall", ip: selectedIP });
};
all("input[name=sshPort]").forEach((r) => {
  r.onchange = () => {
    const custom = document.querySelector("input[name=sshPort]:checked").value === "custom";
    $("#sshPortCustom").classList.toggle("on", custom);
    $("#sshPortCustom").disabled = !custom;
  };
});
function syncKeySrc() {
  const src = document.querySelector("input[name=sshKeySrc]:checked").value;
  $("#keys").disabled = src !== "custom";
  $("#githubUser").disabled = src !== "github";
}
all("input[name=sshKeySrc]").forEach((r) => (r.onchange = syncKeySrc));
syncKeySrc();

$("#reboot").onclick = async () => {
  if (!await ask("Перезагрузить " + selectedIP + "?")) return;
  emit("reboot", { ip: selectedIP });
};

// ---------- apps ----------
let lastYSE = null;
function renderYSEChip(known, installed) {
  lastYSE = { known, installed };
  const box = $("#yseChips");
  box.innerHTML = "";
  const chip = document.createElement("span");
  if (!known) {
    chip.className = "chip";
    chip.textContent = "не проверено";
  } else {
    chip.className = "chip " + (installed ? "ok" : "bad");
    chip.textContent = installed ? "установлен ✓" : "нет ✕";
  }
  box.appendChild(chip);
  paintToggle($("#ysePkg"), !!installed, "Удалить", "Установить");
}
$("#ysePkg").onclick = async () => {
  const installed = lastYSE && lastYSE.installed;
  if (installed) {
    if (!await ask("Удалить yse и Entware/yap с " + selectedIP + "?")) return;
    emit("yse", { action: "uninstall", ip: selectedIP });
  } else {
    if (!await ask("Установить yse (Entware + .yap) на " + selectedIP + "?")) return;
    emit("yse", { action: "install", ip: selectedIP });
  }
};
function bindDaemon(cfg) {
  const act = (action) => emit(cfg.emit, { action, ip: selectedIP });
  let last = null;
  const apply = (e) => {
    last = e;
    const box = $(cfg.box);
    box.innerHTML = "";
    if (!e) {
      box.innerHTML = '<span class="chip">не проверено</span>';
      $(cfg.open).classList.add("hidden");
      $(cfg.run).classList.add("hidden");
      $(cfg.boot).classList.add("hidden");
      paintToggle($(cfg.pkg), false, "Удалить", "Установить");
      return;
    }
    const installed = !!e.installed;
    const running = !!e.running;
    $(cfg.open).classList.toggle("hidden", !running);
    $(cfg.run).classList.toggle("hidden", !installed);
    $(cfg.boot).classList.toggle("hidden", !installed);
    paintToggle($(cfg.pkg), installed, "Удалить", "Установить");
    if (!installed) {
      box.innerHTML = '<span class="chip bad">нет ✕</span>';
      return;
    }
    box.appendChild(otaChip(cfg.proc, running));
    box.appendChild(otaChip("автозапуск", !!e.autostart));
    paintToggle($(cfg.run), running, "Стоп", "Старт");
    paintToggle($(cfg.boot), !!e.autostart, "Авто выкл", "Автозапуск");
  };
  window.runtime?.EventsOn?.(cfg.event, (e) => {
    if (e.ip !== selectedIP) return;
    apply(e);
  });
  $(cfg.open).onclick = () => {
    if (!selectedIP) return;
    window.runtime?.BrowserOpenURL?.("http://" + selectedIP + ":8099");
  };
  $(cfg.pkg).onclick = async () => {
    const installed = last && last.installed;
    const q = installed ? cfg.askRemove : cfg.askInstall;
    if (!await ask(q + selectedIP + "?")) return;
    act(installed ? "uninstall" : "install");
  };
  $(cfg.run).onclick = () => act(last && last.running ? "stop" : "start");
  $(cfg.boot).onclick = async () => {
    const on = last && last.autostart;
    const q = on ? "Убрать автозапуск на " : "Включить автозапуск на ";
    if (!await ask(q + selectedIP + "?")) return;
    act(on ? "autostart-off" : "autostart-on");
  };
  reapplyDaemons.push(() => { if (last && last.ip === selectedIP) apply(last); });
  panelResetters.push(() => apply(null));
}
// YAM 0.2 is not a daemon: install/uninstall plus the optional web-panel
// package, so it uses the same light wiring as yse instead of bindDaemon.
let lastYAM = null;
function renderYAMChip(known, installed) {
  lastYAM = { known, installed };
  const box = $("#yamChips");
  box.innerHTML = "";
  const chip = document.createElement("span");
  if (!known) {
    chip.className = "chip";
    chip.textContent = "не проверено";
  } else {
    chip.className = "chip " + (installed ? "ok" : "bad");
    chip.textContent = installed ? "установлен ✓" : "нет ✕";
  }
  box.appendChild(chip);
  paintToggle($("#yamPkg"), !!installed, "Удалить", "Установить");
  $("#yamPanel").classList.toggle("hidden", !installed);
}
$("#yamPkg").onclick = async () => {
  const installed = lastYAM && lastYAM.installed;
  if (installed) {
    if (!await ask("Удалить YAM (/data/yam) с " + selectedIP + "?")) return;
    emit("yam", { action: "uninstall", ip: selectedIP });
  } else {
    if (!await ask("Установить YAM 0.2 (пакетный менеджер на колонке) на " + selectedIP + "?")) return;
    emit("yam", { action: "install", ip: selectedIP });
  }
};
$("#yamPanel").onclick = async () => {
  if (!await ask("Установить веб-панель (пакет yam/luna из подписанного реестра) на " + selectedIP + "?")) return;
  emit("yam", { action: "panel", ip: selectedIP });
};
window.runtime?.EventsOn?.("yamStatus", (e) => {
  if (e.ip !== selectedIP) return;
  const d = lastDevices.find((x) => x.ip === e.ip);
  if (d) {
    d.yamKnown = true;
    d.yamInstalled = !!e.installed;
  }
  renderYAMChip(true, !!e.installed);
});
bindDaemon({
  event: "byamStatus", emit: "betteryam", box: "#byamChips", proc: "betteryamd",
  open: "#byamOpen", run: "#byamRun", boot: "#byamBoot", pkg: "#byamPkg",
  askInstall: "Установить BetterYAM (:8099) на ", askRemove: "Удалить BetterYAM с ",
});
window.runtime?.EventsOn?.("yseStatus", (e) => {
  if (e.ip !== selectedIP) return;
  const d = lastDevices.find((x) => x.ip === e.ip);
  if (d) {
    d.yseKnown = true;
    d.yseInstalled = !!e.installed;
  }
  renderYSEChip(true, !!e.installed);
});

// ---------- resource widgets (from dimap/yandex-station-web, MIT) ----------
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const dec = (v, n) => v.toFixed(n).replace(".", ",");
function splitUptime(s) {
  s = Math.floor(+s);
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  if (d) return [d, `д ${h} ч`];
  if (h) return [h, `ч ${m} мин`];
  return [m, "мин"];
}
function setStat(id, value, unit) {
  $("#st-" + id).textContent = value;
  if (unit !== undefined) $("#st-" + id + "-u").textContent = unit;
}
function setBar(id, frac) {
  $("#" + id).style.width = frac === null ? "0" : clamp(frac * 100, 0, 100) + "%";
}
function setMeta(sel, text, title) {
  $(sel).textContent = text;
  $(sel).title = title || text;
}
// The memory number is occupied, the /data number is free — the marker word
// makes that explicit instead of leaving the reader to guess.
function setMetaHTML(sel, html, title) {
  $(sel).innerHTML = html;
  $(sel).title = title || $(sel).textContent;
}
let statsErrs = 0;
function resetStats() {
  statsErrs = 0;
  setStat("temp", "—");
  setStat("mem", "—", "МиБ");
  setStat("rssi", "—");
  setStat("data", "—", "");
  setStat("up", "—", "");
  ["st-temp-bar", "st-mem-bar", "st-rssi-bar", "st-data-bar", "st-load-bar"].forEach((id) => setBar(id, null));
  ["#st-mem-n", "#st-wifi-n", "#st-data-n", "#st-load-n"].forEach((sel) => setMeta(sel, "—"));
  $("#statsVia").textContent = "";
  $("#statsVia").title = "";
}
function pollStats() {
  if (!selectedIP || currentTab !== "overview" || busyNow || document.hidden) return;
  const d = lastDevices.find((x) => x.ip === selectedIP);
  if (!d) return;
  // Root is the gate: undetected root counts as none, so the poll does
  // not hammer a station it cannot read. (While a console session is
  // open — on any tab — the Go side holds the poll entirely.)
  if (!(d.rootKnown && d.root)) return;
  if (!(d.ports && (d.ports["5555"] || d.ports["2222"] || d.ports["22"]))) return;
  emit("stats", { ip: selectedIP });
}
setInterval(pollStats, 5000);
// One flaky poll must not blank the widgets: values survive, and the
// "нет данных" note appears only after several failures in a row.
window.runtime?.EventsOn?.("stats", (e) => {
  if (e.ip !== selectedIP) return;
  if (e.err) {
    statsErrs++;
    if (statsErrs >= 3) {
      $("#statsVia").textContent = "нет данных";
      $("#statsVia").title = e.err;
    }
    return;
  }
  statsErrs = 0;
  const s = e.stats || {};
  $("#statsVia").textContent = e.via ? "через " + e.via : "";
  $("#statsVia").title = "";
  // A field missing from one poll is not new information: the widgets keep
  // the last reading instead of blanking — the station's adb answers
  // command-by-command flaky sometimes, so "—" blips lie.
  const t = typeof s.tempC === "number" ? s.tempC : null;
  if (t !== null) {
    setStat("temp", t.toFixed(0));
    setBar("st-temp-bar", t / 85);
  }
  if (s.memTotalKB) {
    // The kernel reports kB = 1024 bytes: /1024 gives the same МиБ that
    // free, df -h and top print, so the widget matches system tools.
    const total = Math.round(s.memTotalKB / 1024);
    const avail = Math.round(s.memAvailKB / 1024);
    const used = total - avail;
    // Both size widgets show free space, the same way; the bars stay the
    // occupied share.
    setStat("mem", avail, "МиБ");
    setBar("st-mem-bar", used / total);
    setMetaHTML("#st-mem-n", `<span class="sem free">свободно</span> · ${total}`,
      `свободно ${avail} МиБ, занято ${used} МиБ, всего ${total} МиБ`);
  }
  const rssi = typeof s.rssi === "number" ? s.rssi : null;
  if (rssi !== null) {
    setStat("rssi", String(rssi).replace("-", "−"));
    setBar("st-rssi-bar", (rssi + 90) / 60);
  }
  // Signal and link speed only; the network name stays private.
  if (s.linkMbps) setMeta("#st-wifi-n", s.linkMbps + " Мбит/с");
  if (s.dataTotalKB) {
    const free = s.dataFreeKB, total = s.dataTotalKB;
    if (total < 1048576) {
      // AXG-станции: /data — это ubifs-том ~90 МиБ (bkupgrade).
      const f = Math.round(free / 1024), tt = Math.round(total / 1024);
      setStat("data", f, "МиБ");
      setMetaHTML("#st-data-n", `<span class="sem free">свободно</span> · ${tt}`,
        `свободно ${f} МиБ, занято ${tt - f} МиБ, всего ${tt} МиБ`);
    } else {
      const f = (free / 1048576).toFixed(1), tt = (total / 1048576).toFixed(1);
      setStat("data", f, "ГиБ");
      setMetaHTML("#st-data-n", `<span class="sem free">свободно</span> · ${tt}`,
        `свободно ${f} ГиБ, занято ${(tt - f).toFixed(1)} ГиБ, всего ${tt} ГиБ`);
    }
    // The fill is the occupied share, like every other usage bar; the
    // number stays the free space the widget exists for.
    setBar("st-data-bar", (total - free) / total);
  }
  if (s.uptimeSec) {
    const [v, u] = splitUptime(s.uptimeSec);
    setStat("up", v, u);
  }
  if (s.loadKnown) {
    setBar("st-load-bar", s.load[0] / 4);
    setMeta("#st-load-n", "нагрузка " + dec(s.load[0], 2), "нагрузка " + s.load.map((x) => dec(x, 2)).join(" · "));
  }
});

// ---------- Консоль: xterm.js ↔ adb shell / ssh pty, session lives while open ----------
// Borrowed from dimap/yandex-station-web (MIT): the terminal is dark in both
// themes, selection copies, Enter reopens a closed session.
let term = null, termFit = null, termOpen = false;
// Holds keystrokes typed while no session is open; flushed on connect.
let termBuf = "";
// Wails runs every event handler in its own goroutine, so writes can race
// and reorder. Each write carries a monotonic seq; Go reassembles in
// order. seqFrom on open tells the session where the stream starts.
let shellSeq = 0;

async function copyText(text) {
  try {
    if (navigator.clipboard && isSecureContext) await navigator.clipboard.writeText(text);
    else {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.cssText = "position:fixed;left:-9999px;top:0";
      document.body.append(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
  } catch {}
  term?.focus();
}

function termState(text, ok) {
  const b = $("#termState");
  b.textContent = text;
  b.className = "badge" + (ok ? " ok" : "");
}

function termInit() {
  if (term) return true;
  if (!window.Terminal || !window.FitAddon) {
    $("#term").textContent = "Не загрузился xterm.js";
    return false;
  }
  $("#term").textContent = "";
  term = new Terminal({
    fontFamily: "'JetBrains Mono', ui-monospace, Menlo, Consolas, monospace", fontSize: 13, lineHeight: 1.2,
    cursorBlink: true, scrollback: 5000, allowProposedApi: false,
    theme: { background: "#111116", foreground: "#E6E6EB", cursor: "#A78BFA", selectionBackground: "#6C47FF66",
             black: "#16161D", brightBlack: "#5F5F6E" },
  });
  termFit = new FitAddon.FitAddon();
  term.loadAddon(termFit);
  term.open($("#term"));
  const copySel = () => {
    const text = term.getSelection();
    if (text) copyText(text);
  };
  $("#term").addEventListener("mouseup", () => setTimeout(copySel, 0));
  term.onData((d) => {
    if (termOpen) {
      shellSend(d);
      return;
    }
    // Between sessions everything typed is held — Enter included, or the
    // flushed line would miss its newline and need a second Enter. Enter
    // also (re)opens the session; the buffer rides along when it opens.
    termBuf += d;
    if (d === "\r") termConnect();
  });
  term.onResize(({ cols, rows }) => emit("shell", { action: "resize", cols, rows }));
  new ResizeObserver(() => {
    if (currentTab === "console") { try { termFit.fit(); } catch {} }
  }).observe($("#term"));
  return true;
}

function shellSend(data) {
  emit("shell", { action: "write", data, seq: ++shellSeq });
}

function termConnect() {
  if (!termInit()) return;
  try { termFit.fit(); } catch {}
  if (!selectedIP) { termState("нет колонки", false); return; }
  const d = lastDevices.find((x) => x.ip === selectedIP);
  const has = d && d.ports && (d.ports["5555"] || d.ports["2222"] || d.ports["22"]);
  if (!has) {
    termState("нет канала", false);
    term.write("\r\n\x1b[90m[нет канала управления — включите ADB или SSH на колонке]\x1b[0m\r\n");
    return;
  }
  termState("подключение…", false);
  emit("shell", { action: "open", ip: selectedIP, cols: term.cols, rows: term.rows, seqFrom: shellSeq + 1 });
}

window.runtime?.EventsOn?.("shellState", (e) => {
  if (e.ip !== selectedIP) return;
  if (e.err) {
    termOpen = false;
    termState("ошибка", false);
    term.write("\r\n\x1b[90m[" + e.err + "]\x1b[0m\r\n");
    return;
  }
  termOpen = true;
  termState(e.via || "подключено", true);
  if (termBuf) {
    shellSend(termBuf);
    termBuf = "";
  }
  term?.focus();
});
window.runtime?.EventsOn?.("shellOut", (e) => {
  if (e.ip === selectedIP && term) term.write(e.data || "");
});
window.runtime?.EventsOn?.("shellExit", (e) => {
  if (e.ip !== selectedIP) return;
  termOpen = false;
  termState("закрыт", false);
  term?.write("\r\n\x1b[90m[сеанс закрыт — Enter, чтобы открыть новый]\x1b[0m\r\n");
});
$("#termNew").onclick = () => {
  emit("shell", { action: "close" });
  termOpen = false;
  termInit() && term.reset();
  termConnect();
};

// ---------- bootstrap Server (Первый шаг) ----------
const serverUI = { running: false, mode: "passthrough", err: "" };
const fwDownloading = {};

// «Запустить» button content; the start/stop state decides text and
// tone. No shield: the firewall verdict lives in the journal.
function renderServerBtn() {
  const b = $("#serverBtn");
  if (!b) return;
  const run = serverUI.running;
  b.textContent = run ? "Остановить" : "Запустить";
  b.classList.toggle("danger", run);
  b.classList.toggle("primary", !run);
}

function renderServerState(e) {
  Object.assign(serverUI, e || {});
  renderServerBtn();
  const st = $("#serverStateText");
  st.textContent = serverUI.running ? "работает" : "остановлен";
  st.className = "chip" + (serverUI.running ? " ok" : "");
  const err = $("#serverErr");
  err.textContent = serverUI.err || "";
  err.classList.toggle("hidden", !serverUI.err);
  all("#serverMode button").forEach((b) => b.classList.toggle("active", b.dataset.mode === serverUI.mode));
}

function renderFirmwareTargets(e) {
  const box = $("#fwTargets");
  box.innerHTML = "";
  const list = (e && e.list) || [];
  if (!list.length) {
    box.innerHTML = '<div class="fw-none">Нет моделей с проверенной версией прошивки.</div>';
    return;
  }
  for (const t of list) {
    const row = document.createElement("div");
    row.className = "fw-row" + (t.seen ? "" : " unseen");
    const name = document.createElement("span");
    name.className = "fw-name";
    name.title = t.version;
    name.innerHTML = `<b>${escapeHtml(t.device)}</b><small class="fw-code">${escapeHtml(t.platform)}</small>`;
    row.appendChild(name);
    const ver = document.createElement("small");
    ver.className = "fw-ver";
    ver.textContent = String(t.version).split(".").slice(0, 4).join(".");
    ver.title = t.version;
    row.appendChild(ver);
    if (t.seen) {
      const c = document.createElement("span");
      c.className = "chip mid";
      c.title = "модель найдена при сканировании сети";
      c.textContent = "найдена";
      row.appendChild(c);
    }
    if (t.has) {
      const c = document.createElement("span");
      c.className = "chip ok";
      c.title = "файл прошивки скачан и готов к отдаче";
      c.textContent = "скачана";
      row.appendChild(c);
    } else if (fwDownloading[t.platform]) {
      const c = document.createElement("span");
      c.className = "chip";
      c.textContent = "скачивается…";
      row.appendChild(c);
    } else {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "small";
      b.dataset.free = "";
      b.textContent = "Скачать";
      b.onclick = () => {
        fwDownloading[t.platform] = true;
        b.disabled = true;
        emit("Server", { action: "ensureFirmware", platform: t.platform });
        renderFirmwareTargets({ list });
      };
      row.appendChild(b);
    }
    box.appendChild(row);
  }
}

window.runtime?.EventsOn?.("serverState", renderServerState);
window.runtime?.EventsOn?.("firmwareTargets", renderFirmwareTargets);
window.runtime?.EventsOn?.("firmwareTargetsDone", (e) => {
  fwDownloading[e.platform] = false;
  emit("Server", { action: "status" });
});
$("#serverBtn").onclick = () => {
  if (serverUI.running) emit("Server", { action: "stop" });
  else emit("Server", { action: "start", mode: serverUI.mode });
};
all("#serverMode button").forEach((b) => {
  b.onclick = () => {
    serverUI.mode = b.dataset.mode;
    all("#serverMode button").forEach((x) => x.classList.toggle("active", x === b));
    if (serverUI.running) emit("Server", { action: "setMode", mode: serverUI.mode });
    renderServerState(serverUI);
  };
});

// ---------- journal actions ----------
$("#clearLog").onclick = () => ($("#log").textContent = "");
$("#copyLog").onclick = () => {
  const text = $("#log").textContent;
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(() => toast("Журнал скопирован"));
};

renderSwitcher();
showTab("devices");
if (!runtimeReady()) {
  $("#runtimeWarn").classList.remove("hidden");
  setBusy({ on: true, what: "нет связи с бэкендом" });
} else {
  setTimeout(() => emit("scan", { adapters: enabledAdapterNames() }), 300);
  emit("Server", { action: "status" });
}
