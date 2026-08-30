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

  function wireGlossaryOverlay(opts) {
    const explainAside = opts.explainEl || $("explain");
    const bodyEl = explainAside?.querySelector("#explain-body") || explainAside;
    const toggleKey = opts.toggleKey || "?";
    const mq = window.matchMedia("(max-width: 900px)");
    const toggleBtn = opts.toggleBtn || $("explain-toggle");

    let overlay = $("glossary-overlay");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "glossary-overlay";
      overlay.className = "glossary-overlay";
      overlay.hidden = true;
      overlay.innerHTML = `
        <div class="glossary-panel" role="dialog" aria-modal="true" aria-labelledby="glossary-overlay-title">
          <h2 id="glossary-overlay-title">¿Qué significa esto?</h2>
          <div id="explain-overlay-body"></div>
          <button type="button" class="glossary-close" id="glossary-close">Cerrar</button>
        </div>`;
      document.body.appendChild(overlay);
    }

    const overlayBody = $("explain-overlay-body");
    const closeBtn = $("glossary-close");

    function isNarrow() {
      return mq.matches;
    }

    function syncOverlay() {
      if (overlayBody && bodyEl) overlayBody.innerHTML = bodyEl.innerHTML;
    }

    function openOverlay() {
      syncOverlay();
      overlay.hidden = false;
      if (toggleBtn) toggleBtn.setAttribute("aria-expanded", "true");
      closeBtn?.focus();
    }

    function closeOverlay() {
      overlay.hidden = true;
      if (toggleBtn) toggleBtn.setAttribute("aria-expanded", "false");
    }

    function toggleOverlay() {
      if (overlay.hidden) openOverlay();
      else closeOverlay();
    }

    function resetAsideScroll() {
      if (explainAside) explainAside.scrollTop = 0;
    }

    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) closeOverlay();
    });
    closeBtn?.addEventListener("click", closeOverlay);
    toggleBtn?.addEventListener("click", toggleOverlay);

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !overlay.hidden) {
        e.preventDefault();
        closeOverlay();
        return;
      }
      if (e.key !== toggleKey || e.ctrlKey || e.metaKey || e.altKey) return;
      const tag = e.target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      if (!isNarrow()) return;
      e.preventDefault();
      toggleOverlay();
    });

    return { isNarrow, openOverlay, closeOverlay, toggleOverlay, syncOverlay, resetAsideScroll };
  }

  global.MetaShell = {
    $,
    copyText,
    download,
    wireTabs,
    wireDropZone,
    renderChips,
    wireCopyClicks,
    wireGlossaryOverlay,
    toCsv,
    toMd,
  };
})(typeof window !== "undefined" ? window : globalThis);
