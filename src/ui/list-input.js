// The list input: one chip-style control for every multi-value field in the
// web UI. Served at /ui/list-input.js.
//
// It enhances a plain <input data-list-kind="..."> in place. The original
// input is hidden and stays the value store (its .value is always the entries
// joined by the separator), so existing code that reads the input's value or
// listens for its "input" event keeps working unchanged.
//
//   <input id="x" data-list-kind="host" placeholder="api.example.com">
//
// Attributes:
//   data-list-kind   cidr | host | pathPrefix | policyPath | word | phrase
//   data-list-sep    separator used for the stored value (default ", ")
//
// Behaviour, modelled on the recipient field of a mail client:
//   Enter, comma, space, Tab or blur commits the typed text as an entry
//   (space does not commit for the "phrase" kind, whose entries have spaces).
//   Paste splits on the same separators. Backspace in an empty field removes
//   the last chip. Clicking a chip's text puts it back in the field to edit.
//   Each entry is validated; an invalid one is shown in red with the reason.

import { splitList, splitModeFor, validateEntry } from "/ui/list-validate.js";

const ENHANCED = "listEnhanced";

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function labelFor(input) {
  const own = input.getAttribute("aria-label");
  if (own) return own;
  const group = input.closest(".form-group, .detail-field") || input.parentElement;
  const label = group && group.querySelector("label");
  const text = label ? label.textContent.replace(/\*/g, "").trim() : "";
  return text || input.getAttribute("aria-label") || input.id || "list";
}

function enhance(input) {
  if (!input || input.dataset[ENHANCED]) return;
  const kind = input.dataset.listKind;
  if (!kind) return;
  input.dataset[ENHANCED] = "1";

  const mode = splitModeFor(kind);
  const sep = input.dataset.listSep !== undefined ? input.dataset.listSep : ", ";
  const name = labelFor(input);
  let entries = splitList(input.value, mode);

  const wrapper = document.createElement("div");
  wrapper.className = "tag-input-wrapper list-input";
  const field = document.createElement("input");
  field.type = "text";
  field.className = "tag-inline-input";
  field.spellcheck = false;
  field.autocomplete = "off";
  field.setAttribute("aria-label", name);
  if (input.id) field.id = `${input.id}--entry`;
  field.disabled = input.disabled;
  const basePlaceholder = input.getAttribute("placeholder") || "";
  const message = document.createElement("div");
  message.className = "list-input-error";
  message.setAttribute("role", "alert");

  wrapper.appendChild(field);
  input.insertAdjacentElement("beforebegin", wrapper);
  wrapper.insertAdjacentElement("afterend", message);
  input.type = "hidden";

  // Carry over spacing the original input set inline.
  if (input.style.marginTop) wrapper.style.marginTop = input.style.marginTop;
  if (input.style.marginBottom) wrapper.style.marginBottom = input.style.marginBottom;

  // Point the field's <label> at the visible text box.
  const explicit = input.id ? document.querySelector(`label[for="${input.id}"]`) : null;
  const group = input.closest(".form-group, .detail-field");
  const label = explicit || (group && group.querySelector("label"));
  if (label && field.id && (!label.htmlFor || label.htmlFor === input.id)) label.htmlFor = field.id;

  function errors() {
    return entries.map((e) => ({ entry: e, reason: validateEntry(kind, e) })).filter((x) => x.reason);
  }

  function sync(fire) {
    const value = entries.join(sep);
    const changed = input.value !== value;
    input.value = value;
    const errs = errors();
    if (errs.length) input.dataset.listInvalid = `${errs[0].entry}: ${errs[0].reason}`;
    else delete input.dataset.listInvalid;
    if (fire && changed) input.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function render() {
    wrapper.querySelectorAll(".tag-token").forEach((t) => t.remove());
    entries.forEach((entry, i) => {
      const reason = validateEntry(kind, entry);
      const chip = document.createElement("span");
      chip.className = "tag-token" + (reason ? " invalid" : "");
      if (reason) chip.title = reason;
      chip.innerHTML =
        `<span class="tag-token-text" data-i="${i}">${esc(entry)}</span>` +
        `<button type="button" class="tag-token-remove" data-i="${i}" aria-label="Remove ${esc(entry)}">&times;</button>`;
      wrapper.insertBefore(chip, field);
    });
    field.placeholder = entries.length ? "" : basePlaceholder;
    const errs = errors();
    message.textContent = errs.length ? `${errs[0].entry}: ${errs[0].reason}` : "";
    wrapper.classList.toggle("has-error", errs.length > 0);
  }

  function add(text) {
    const incoming = splitList(text, mode);
    if (incoming.length === 0) return false;
    for (const e of incoming) if (!entries.includes(e)) entries.push(e);
    sync(true);
    render();
    return true;
  }

  function commit() {
    if (!field.value.trim()) {
      field.value = "";
      return false;
    }
    const text = field.value;
    field.value = "";
    return add(text);
  }

  function removeAt(i) {
    entries.splice(i, 1);
    sync(true);
    render();
  }

  field.addEventListener("keydown", (e) => {
    const commitKey = e.key === "Enter" || e.key === "," || (e.key === " " && mode !== "comma");
    if (commitKey) {
      // Enter with nothing typed falls through, so it can still submit a form.
      if (e.key === "Enter" && !field.value.trim()) return;
      e.preventDefault();
      e.stopPropagation();
      commit();
      return;
    }
    if (e.key === "Tab") {
      commit(); // do not prevent default: focus moves on as usual
      return;
    }
    if (e.key === "Backspace" && field.value === "" && entries.length > 0) {
      e.preventDefault();
      removeAt(entries.length - 1);
    }
  });

  field.addEventListener("paste", (e) => {
    const text = (e.clipboardData || window.clipboardData)?.getData("text") ?? "";
    const pieces = splitList(text, mode);
    // A single plain token pastes normally so it can still be edited.
    if (pieces.length <= 1 && !/[,\n\r]/.test(text)) return;
    e.preventDefault();
    const pending = field.value;
    field.value = "";
    add(pending + (pending ? (mode === "comma" ? "," : " ") : "") + text);
  });

  field.addEventListener("blur", () => commit());

  wrapper.addEventListener("click", (e) => {
    const t = e.target;
    if (t.classList.contains("tag-token-remove")) {
      removeAt(Number(t.dataset.i));
      field.focus();
      return;
    }
    if (t.classList.contains("tag-token-text")) {
      // Put the entry back in the field for editing.
      const i = Number(t.dataset.i);
      commit();
      const [entry] = entries.splice(i, 1);
      sync(true);
      render();
      field.value = entry;
      field.focus();
      return;
    }
    field.focus();
  });

  // Let other code set the value programmatically: ListInput.set(input, "a, b").
  input._listInput = {
    set(value) {
      entries = splitList(String(value ?? ""), mode);
      field.value = "";
      sync(false);
      render();
    },
    commit,
  };

  sync(false);
  render();
}

function enhanceAll(root) {
  const scope = root && root.querySelectorAll ? root : document;
  if (scope.matches && scope.matches("input[data-list-kind]")) enhance(scope);
  scope.querySelectorAll("input[data-list-kind]").forEach(enhance);
}

/**
 * Commit any text still being typed in list inputs under `root`, then return
 * the first invalid entry as { label, detail }, or null when all are valid.
 * Save handlers call this before reading values.
 */
function firstError(root) {
  const scope = root && root.querySelectorAll ? root : document;
  for (const input of scope.querySelectorAll("input[data-list-kind]")) {
    if (input._listInput) input._listInput.commit();
    if (input.dataset.listInvalid) return { label: labelFor(input), detail: input.dataset.listInvalid };
  }
  return null;
}

function set(input, value) {
  if (input && input._listInput) input._listInput.set(value);
  else if (input) input.value = value;
}

if (typeof window !== "undefined") {
  window.ListInput = { enhance, enhanceAll, firstError, set };

  // Forms are built with innerHTML at arbitrary times, so enhance on insertion.
  const start = () => {
    enhanceAll(document);
    new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeType === 1) enhanceAll(node);
        }
      }
    }).observe(document.body, { childList: true, subtree: true });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
}
