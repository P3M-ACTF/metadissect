/* Meta* shared shell helpers — tabs, drop zone, copy, exports */
(function (global) {
  "use strict";

  function $(id) {
    return document.getElementById(id);
  }

  function copyText(text, label) {
    if (!text) return;
    navigator.clipboard.writeText(text).catch(() => {});
    const st = $("status");
    if (st) st.textContent = label ? `Copiado: ${label}` : "Copiado";
  }

  function download(name, content, mime) {
    const blob = new Blob([content], { type: mime || "application/octet-stream" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function wireTabs(nav) {
    const tabs = [...nav.querySelectorAll("[role=tab]")];
    function activate(btn) {
      tabs.forEach((x) => {
        const on = x === btn;
        x.classList.toggle("active", on);
        x.setAttribute("aria-selected", on ? "true" : "false");
        x.tabIndex = on ? 0 : -1;
      });
      const panelId = btn.dataset.tab;
      document.querySelectorAll(".panel").forEach((p) => {
        const on = p.id === panelId;
        p.classList.toggle("active", on);
        p.hidden = !on;
      });
      const focus = btn.dataset.focus;
      if (focus) {
        const el = document.getElementById(focus + "-pane") || $(focus);
        if (el) el.focus();
      }
      btn.focus();
    }
    tabs.forEach((b) => {
      b.tabIndex = b.classList.contains("active") ? 0 : -1;
      b.addEventListener("click", () => activate(b));
      b.addEventListener("keydown", (e) => {
        const i = tabs.indexOf(b);
        if (e.key === "ArrowRight") {
          e.preventDefault();
          activate(tabs[(i + 1) % tabs.length]);
        } else if (e.key === "ArrowLeft") {
          e.preventDefault();
          activate(tabs[(i - 1 + tabs.length) % tabs.length]);
        } else if (e.key === "Home") {
          e.preventDefault();
          activate(tabs[0]);
        } else if (e.key === "End") {
          e.preventDefault();
          activate(tabs[tabs.length - 1]);
        }
      });
    });
    return { activate };
  }

  function wireDropZone(opts) {
    const drop = opts.dropEl || $("drop");
    const input = opts.inputEl || $("file");
    if (!drop || !input) return;
    const onFile = opts.onFile;
    drop.addEventListener("click", () => input.click());
    drop.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        input.click();
      }
    });
    input.addEventListener("click", (e) => e.stopPropagation());
    drop.addEventListener("dragover", (e) => {
      e.preventDefault();
      drop.classList.add("dragover");
    });
    drop.addEventListener("dragleave", () => drop.classList.remove("dragover"));
    drop.addEventListener("drop", (e) => {
      e.preventDefault();
      drop.classList.remove("dragover");
      const f = e.dataTransfer.files[0];
      if (f && onFile) onFile(f);
    });
    input.addEventListener("change", (e) => {
      const f = e.target.files[0];
      if (f && onFile) onFile(f);
    });
  }

  function renderChips(container, items) {
    if (!container) return;
    container.innerHTML = "";
    items.forEach(({ k, v, copy }) => {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "chip";
      chip.innerHTML = `<span class="chip-k">${k}</span><span class="chip-v">${v}</span>`;
      if (copy) chip.setAttribute("data-copy", copy);
      container.appendChild(chip);
    });
  }

  function wireCopyClicks(root) {
    root.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-copy]");
      if (!btn) return;
      e.preventDefault();
      copyText(btn.getAttribute("data-copy"), btn.getAttribute("data-label"));
    });
  }

  function toCsv(analysis) {
    const rows = ["section,key,value,namespace"];
    (analysis.sections || []).forEach((s) => {
      (s.fields || []).forEach((f) => {
        const ns = f.namespace || "";
        const val = String(f.value || "").replace(/"/g, '""');
        rows.push(`"${s.label}","${f.key}","${val}","${ns}"`);
      });
    });
    return rows.join("\n");
  }

  function toMd(analysis) {
    let out = `# ${analysis.filename || "analysis"}\n\n`;
    out += `- MIME: ${analysis.mime}\n- Size: ${analysis.size}\n`;
    if (analysis.hashes) out += `- SHA-256: ${analysis.hashes.sha256}\n`;
    (analysis.sections || []).forEach((s) => {
      out += `\n## ${s.label}\n\n`;
      (s.fields || []).forEach((f) => {
        out += `- **${f.key}**: ${f.value}`;
        if (f.namespace) out += ` (${f.namespace})`;
        out += "\n";
      });
    });
    return out;
  }

  global.MetaShell = {
    $,
    copyText,
    download,
    wireTabs,
    wireDropZone,
    renderChips,
    wireCopyClicks,
    toCsv,
    toMd,
  };
})(typeof window !== "undefined" ? window : globalThis);
