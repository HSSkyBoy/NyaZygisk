const PROP_PATH = "/data/adb/neozygisk/module.prop";
const GOOD_STATUSES = new Set(["running", "injected", "tracing"]);
const BAD_STATUSES = new Set(["stopped", "exited", "crashed", "not_injected"]);

const I18N = {
  en: {
    language_aria: "Language",
    status: "Status",
    info: "Basic Information",
    modules: "Active Modules",
    monitor: "Zygote Monitor",
    zygote: "Zygote",
    daemon: "Daemon",
    version: "Version",
    root: "Root",
    kernel: "Kernel",
    sdk: "Android SDK",
    abi: "ABI",
    running: "Running",
    tracing: "Tracing",
    stopped: "Stopped",
    exited: "Exited",
    injected: "Injected",
    not_injected: "Not Injected",
    crashed: "Crashed",
    unknown: "Unknown",
    reload: "Reload",
    none: "None",
    active: "Active",
    reloaded: "Reloaded",
    load_failed: "Failed to read module.prop",
    bridge_missing: "No supported WebUI bridge detected",
  },
  "zh-Hant": {
    language_aria: "\u8a9e\u8a00",
    status: "\u72c0\u614b",
    info: "\u57fa\u672c\u8cc7\u8a0a",
    modules: "\u555f\u7528\u6a21\u7d44",
    monitor: "Zygote \u76e3\u8996\u5668",
    zygote: "Zygote",
    daemon: "\u5b88\u8b77\u7a0b\u5e8f",
    version: "\u7248\u672c",
    root: "Root \u65b9\u6848",
    kernel: "\u6838\u5fc3",
    sdk: "Android SDK",
    abi: "ABI",
    running: "\u904b\u884c\u4e2d",
    tracing: "\u8ffd\u8e64\u4e2d",
    stopped: "\u5df2\u505c\u6b62",
    exited: "\u5df2\u9000\u51fa",
    injected: "\u5df2\u6ce8\u5165",
    not_injected: "\u672a\u6ce8\u5165",
    crashed: "\u5df2\u5d29\u6f70",
    unknown: "\u672a\u77e5",
    reload: "\u91cd\u65b0\u8f09\u5165",
    none: "\u7121",
    active: "\u555f\u7528",
    reloaded: "\u5df2\u91cd\u65b0\u8f09\u5165",
    load_failed: "\u8b80\u53d6 module.prop \u5931\u6557",
    bridge_missing: "\u627e\u4e0d\u5230\u652f\u63f4\u7684 WebUI bridge",
  },
  "zh-Hans": {
    language_aria: "\u8bed\u8a00",
    status: "\u72b6\u6001",
    info: "\u57fa\u672c\u4fe1\u606f",
    modules: "\u542f\u7528\u6a21\u5757",
    monitor: "Zygote \u76d1\u89c6\u5668",
    zygote: "Zygote",
    daemon: "\u5b88\u62a4\u8fdb\u7a0b",
    version: "\u7248\u672c",
    root: "Root \u65b9\u6848",
    kernel: "\u5185\u6838",
    sdk: "Android SDK",
    abi: "ABI",
    running: "\u8fd0\u884c\u4e2d",
    tracing: "\u8ffd\u8e2a\u4e2d",
    stopped: "\u5df2\u505c\u6b62",
    exited: "\u5df2\u9000\u51fa",
    injected: "\u5df2\u6ce8\u5165",
    not_injected: "\u672a\u6ce8\u5165",
    crashed: "\u5df2\u5d29\u6e83",
    unknown: "\u672a\u77e5",
    reload: "\u91cd\u65b0\u52a0\u8f7d",
    none: "\u65e0",
    active: "\u542f\u7528",
    reloaded: "\u5df2\u91cd\u65b0\u52a0\u8f7d",
    load_failed: "\u8bfb\u53d6 module.prop \u5931\u8d25",
    bridge_missing: "\u627e\u4e0d\u5230\u652f\u6301\u7684 WebUI bridge",
  },
};

let currentLang = pickInitialLanguage();
let toastTimer = null;

const $ = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  $("lang-select").value = currentLang;
  $("lang-select").addEventListener("change", (event) => {
    currentLang = event.target.value;
    applyTranslations();
    refresh(false);
  });

  $("btn-reload").addEventListener("click", () => {
    refresh(true);
  });

  applyTranslations();
  refresh(false);
});

function pickInitialLanguage() {
  const language = navigator.language || "en";
  if (language.startsWith("zh")) {
    return /hans|cn|sg/i.test(language) ? "zh-Hans" : "zh-Hant";
  }
  return "en";
}

function t(key) {
  const local = I18N[currentLang] || I18N.en;
  if (local[key] !== undefined) {
    return local[key];
  }
  if (I18N.en[key] !== undefined) {
    return I18N.en[key];
  }
  return key;
}

function applyTranslations() {
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    const key = element.getAttribute("data-i18n");
    element.textContent = t(key);
  });

  const emptyKey = $("module-list").dataset.emptyKey;
  if ($("module-list").classList.contains("empty")) {
    $("module-list").textContent = t(emptyKey);
  }
}

function parseProp(text) {
  const data = {};
  text.split(/\r?\n/).forEach((line) => {
    const match = line.trim().match(/^([^=]+)=(.*)$/);
    if (!match) {
      return;
    }
    data[match[1].trim()] = match[2].trim();
  });
  return data;
}

function renderStatus(id, status) {
  const element = $(id);
  const normalized = status || "unknown";
  element.textContent = t(normalized) || normalized;
  element.className = "value";
  if (GOOD_STATUSES.has(normalized)) {
    element.classList.add("value-good");
  } else if (BAD_STATUSES.has(normalized)) {
    element.classList.add("value-danger");
  }
}

function getAbiStatus(data, prefix) {
  const key = Object.keys(data).find(
    (name) => name.startsWith(`${prefix}_`) && name.endsWith("_status"),
  );
  if (!key) {
    return { rawAbi: "", status: "unknown" };
  }
  return {
    rawAbi: key.slice(prefix.length + 1, -"_status".length),
    status: data[key] || "unknown",
  };
}

function formatAbiLabel(rawAbi) {
  if (!rawAbi) {
    return "";
  }
  const known = {
    "64": "64-bit",
    "32": "32-bit",
    arm64: "64-bit",
    "arm64-v8a": "64-bit",
    "x86_64": "64-bit",
    x86: "32-bit",
    "armeabi-v7a": "32-bit",
  };
  return known[rawAbi] || rawAbi;
}

function renderModules(modules) {
  const list = $("module-list");
  if (!modules.length) {
    list.className = "module-list empty";
    list.textContent = t(list.dataset.emptyKey);
    return;
  }

  list.className = "module-list";
  list.innerHTML = modules.map((name) => (
    `<div class="list-item"><span>${escapeHtml(name)}</span><span class="chip">${t("active")}</span></div>`
  )).join("");
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function parseModules(data) {
  if (!data.modules_list) {
    return [];
  }

  try {
    const parsed = JSON.parse(data.modules_list);
    if (Array.isArray(parsed)) {
      return parsed.map((item) => String(item).trim()).filter(Boolean);
    }
  } catch (_) {
    return data.modules_list.split(",").map((item) => item.trim()).filter(Boolean);
  }

  return [];
}

function showToast(key, isError = false) {
  const toast = $("toast");
  toast.textContent = t(key);
  toast.className = `toast${isError ? " error" : ""}`;
  if (toastTimer) {
    clearTimeout(toastTimer);
  }
  toastTimer = setTimeout(() => {
    toast.className = "toast hidden";
  }, isError ? 1800 : 1000);
}

async function refresh(showSuccessToast) {
  const exec = window.NeoZygiskWebUi && window.NeoZygiskWebUi.exec;
  if (typeof exec !== "function") {
    renderFailure("No supported WebUI bridge detected");
    showToast("bridge_missing", true);
    return;
  }

  const result = await exec(`cat ${PROP_PATH} 2>/dev/null`);
  if (result.code !== 0) {
    renderFailure(result.stderr);
    showToast(result.stderr.includes("No supported") ? "bridge_missing" : "load_failed", true);
    return;
  }

  const data = parseProp(result.stdout);
  $("v-version").textContent = data.version || "-";
  $("v-root").textContent = data.root_implementation || "-";
  $("v-kernel").textContent = data.device_kernel || "-";
  $("v-sdk").textContent = data.device_sdk || "-";
  $("v-abi").textContent = data.device_abi || "-";

  renderStatus("v-monitor", data.monitor_status);

  const zygote = getAbiStatus(data, "zygote");
  const daemon = getAbiStatus(data, "daemon");
  const abiLabel = formatAbiLabel(zygote.rawAbi || daemon.rawAbi);
  $("l-zygote").textContent = abiLabel ? `${t("zygote")} (${abiLabel})` : t("zygote");
  $("l-daemon").textContent = abiLabel ? `${t("daemon")} (${abiLabel})` : t("daemon");
  renderStatus("v-zygote", zygote.status);
  renderStatus("v-daemon", daemon.status);

  const modules = parseModules(data);
  $("v-modules-count").textContent = String(data.modules_count || modules.length || 0);
  renderModules(modules);

  if (showSuccessToast) {
    showToast("reloaded");
  }
}

function renderFailure(stderr) {
  renderStatus("v-monitor", "unknown");
  renderStatus("v-zygote", "unknown");
  renderStatus("v-daemon", "unknown");
  $("v-version").textContent = "-";
  $("v-root").textContent = stderr ? stderr.slice(0, 48) : "-";
  $("v-kernel").textContent = "-";
  $("v-sdk").textContent = "-";
  $("v-abi").textContent = "-";
  $("v-modules-count").textContent = "0";
  $("l-zygote").textContent = t("zygote");
  $("l-daemon").textContent = t("daemon");
  renderModules([]);
}
