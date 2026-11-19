// Shell behaviour shared by every page of the web UI. Served at /ui/shell.js.
//
//   Dialogs: Escape closes the top dialog, focus moves into it and is trapped
//   while it is open, focus returns to the opener when it closes, and each
//   dialog is announced as one (role, aria-modal, title).
//
//   Labels: a <label> with no "for" is tied to the single control in its
//   form group.
//
//   Phone layout: the menu button in the top bar opens the sidebar as a
//   drawer (the layout itself is CSS, under the 700px breakpoint).
//
// Dialogs are created all over index.html with innerHTML, so everything here
// works by observation and delegation rather than by patching each one.

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

let uid = 0;
const openers = new WeakMap();

function visible(el) {
  return el.offsetParent !== null || el.getClientRects().length > 0;
}

function focusables(root) {
  return Array.from(root.querySelectorAll(FOCUSABLE)).filter(visible);
}

function topOverlay() {
  const all = document.querySelectorAll(".modal-overlay");
  return all.length ? all[all.length - 1] : null;
}

function associateLabels(root) {
  root.querySelectorAll("label:not([for])").forEach((label) => {
    const group = label.closest(".form-group, .detail-field");
    if (!group) return;
    const controls = Array.from(group.querySelectorAll('input:not([type="hidden"]), select, textarea'));
    if (controls.length !== 1) return;
    const control = controls[0];
    if (!control.id) control.id = `gh-field-${++uid}`;
    label.htmlFor = control.id;
  });
}

function setUpDialog(overlay, opener) {
  if (overlay.dataset.shellReady) return;
  overlay.dataset.shellReady = "1";
  const dialog = overlay.querySelector(".modal") || overlay;
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  const title = dialog.querySelector(".modal-title, h2, h3");
  if (title) {
    if (!title.id) title.id = `gh-dialog-title-${++uid}`;
    dialog.setAttribute("aria-labelledby", title.id);
  }
  if (opener && opener !== document.body) openers.set(overlay, opener);
  associateLabels(overlay);

  // Move focus in, unless the dialog's own code already did.
  requestAnimationFrame(() => {
    if (!overlay.isConnected || overlay.contains(document.activeElement)) return;
    const fields = focusables(dialog);
    const first =
      fields.find((el) => el.matches("input, select, textarea")) ||
      fields.find((el) => !el.classList.contains("modal-close")) ||
      fields[0];
    if (first) first.focus();
    else {
      dialog.tabIndex = -1;
      dialog.focus();
    }
  });
}

function onKeydown(e) {
  if (e.key === "Escape") {
    // A dialog that handles Escape itself has already removed its overlay.
    const origin = e.target && e.target.closest ? e.target.closest(".modal-overlay") : null;
    if (origin && !origin.isConnected) return;

    const overlay = topOverlay();
    if (overlay) {
      // Escape means the same as clicking the backdrop, so each dialog's own
      // close logic runs (some confirm before discarding). A dialog with no
      // backdrop handler is deliberately modal and is left alone.
      if (overlay.hasAttribute("onclick")) {
        e.preventDefault();
        overlay.click();
      }
      return;
    }
    if (document.body.classList.contains("nav-open")) {
      document.body.classList.remove("nav-open");
    }
    return;
  }

  if (e.key === "Tab") {
    const overlay = topOverlay();
    if (!overlay) return;
    const items = focusables(overlay);
    if (items.length === 0) return;
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (!overlay.contains(active)) {
      e.preventDefault();
      first.focus();
    } else if (e.shiftKey && active === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  }
}

function watch() {
  let lastFocused = null;
  document.addEventListener(
    "focusin",
    (e) => {
      if (!e.target.closest || !e.target.closest(".modal-overlay")) lastFocused = e.target;
    },
    true
  );

  const scan = (node) => {
    if (node.nodeType !== 1) return;
    if (node.matches(".modal-overlay")) setUpDialog(node, lastFocused);
    node.querySelectorAll(".modal-overlay").forEach((o) => setUpDialog(o, lastFocused));
    if (!node.closest(".modal-overlay")) associateLabels(node);
  };

  new MutationObserver((mutations) => {
    for (const m of mutations) {
      m.addedNodes.forEach(scan);
      m.removedNodes.forEach((node) => {
        if (node.nodeType !== 1) return;
        const overlays = node.matches(".modal-overlay") ? [node] : Array.from(node.querySelectorAll(".modal-overlay"));
        for (const overlay of overlays) {
          const opener = openers.get(overlay);
          if (opener && opener.isConnected && !topOverlay()) opener.focus();
        }
      });
    }
  }).observe(document.body, { childList: true, subtree: true });

  associateLabels(document);
  document.querySelectorAll(".modal-overlay").forEach((o) => setUpDialog(o, null));
}

function navDrawer() {
  const toggle = document.getElementById("mobile-nav-toggle");
  const backdrop = document.getElementById("mobile-nav-backdrop");
  const setOpen = (open) => {
    document.body.classList.toggle("nav-open", open);
    if (toggle) toggle.setAttribute("aria-expanded", String(open));
  };
  if (toggle) toggle.addEventListener("click", () => setOpen(!document.body.classList.contains("nav-open")));
  if (backdrop) backdrop.addEventListener("click", () => setOpen(false));
  // Choosing a page closes the drawer.
  document.addEventListener("click", (e) => {
    if (e.target.closest && e.target.closest(".sidebar .nav-item")) setOpen(false);
  });
}

if (typeof window !== "undefined") {
  const start = () => {
    document.addEventListener("keydown", onKeydown);
    watch();
    navDrawer();
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
}
