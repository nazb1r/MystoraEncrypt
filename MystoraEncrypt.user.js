// ==UserScript==
// @name         MystoraEncrypt
// @namespace    https://github.com/nazb1r/MystoraEncrypt
// @version      1.0.0
// @description  Локальное сквозное шифрование текста и файлов на любом сайте (Telegram Web, MAX и др.). Ключи хранятся только на вашем устройстве.
// @author       nazb1r
// @match        http://*/*
// @match        https://*/*
// @run-at       document-idle
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_listValues
// @grant        GM_registerMenuCommand
// @noframes
// ==/UserScript==

(() => {
  "use strict";

  const GLOBAL_STATE_KEY = "__mystoraEncryptState";
  const g = typeof unsafeWindow !== "undefined" ? unsafeWindow : window;
  if (g[GLOBAL_STATE_KEY]) return;
  g[GLOBAL_STATE_KEY] = { initialized: true };

  const ENCRYPTED_PREFIX = "MystoraEncrypt:";
  const SALT_PREFIX = "MystoraEncrypt-v1-";
  const MAX_ENCRYPTED_PAYLOAD_LENGTH = 24000;
  const STORAGE_KEY = "mystoraUrlKeys";
  const ENCRYPTED_MARK_ATTR = "data-mystora-encrypted";
  const DECRYPTED_BADGE_CLASS = "mystora-decrypted-badge";
  const LOCKED_BADGE_CLASS = "mystora-locked-badge";
  const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEXTAREA", "INPUT", "IFRAME", "SVG", "CANVAS"]);
  const MAX_SCAN_NODES = 20000;

  function gmGet(key, def) {
    try {
      if (typeof GM !== "undefined" && GM.getValue) return Promise.resolve(GM.getValue(key, def));
    } catch {}
    try {
      if (typeof GM_getValue === "function") return Promise.resolve(GM_getValue(key, def));
    } catch {}
    return Promise.resolve(def);
  }
  function gmSet(key, value) {
    try {
      if (typeof GM !== "undefined" && GM.setValue) return Promise.resolve(GM.setValue(key, value));
    } catch {}
    try {
      if (typeof GM_setValue === "function") return Promise.resolve(GM_setValue(key, value));
    } catch {}
    return Promise.resolve();
  }

  async function getAllUrlKeys() {
    const raw = await gmGet(STORAGE_KEY, "{}");
    try {
      const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
      return sanitizeUrlKeys(parsed) || {};
    } catch {
      return {};
    }
  }
  async function saveAllUrlKeys(urlKeys) {
    await gmSet(STORAGE_KEY, JSON.stringify(urlKeys));
  }

  function normalizeKeyRecord(record) {
    if (!record || typeof record !== "object" || Array.isArray(record)) return null;
    const myKey = typeof record.myKey === "string" ? record.myKey : "";
    const peerKeys = {};
    if (record.peerKeys && typeof record.peerKeys === "object" && !Array.isArray(record.peerKeys)) {
      for (const [label, key] of Object.entries(record.peerKeys)) {
        if (typeof key === "string" && key && typeof label === "string" && label) {
          peerKeys[label] = key;
        }
      }
    }
    if (!myKey || Object.keys(peerKeys).length === 0) return null;
    if (myKey.length > 4096) return null;
    for (const k of Object.keys(peerKeys)) {
      if (peerKeys[k].length > 4096 || k.length > 200) delete peerKeys[k];
    }
    if (Object.keys(peerKeys).length === 0) return null;
    return { myKey, peerKeys };
  }

  function sanitizeUrlKeys(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const sanitized = {};
    for (const [rawUrl, record] of Object.entries(value)) {
      const urlPattern = normalizeUrlPattern(rawUrl);
      const normalized = normalizeKeyRecord(record);
      if (!urlPattern || !normalized) continue;
      sanitized[urlPattern] = normalized;
    }
    return sanitized;
  }

  function normalizeUrlPattern(url) {
    if (!url) return "";
    try {
      const parsed = new URL(String(url).trim());
      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return "";
      if (!parsed.host) return "";
      return `${parsed.protocol}//${parsed.host}/`;
    } catch {
      return "";
    }
  }

  function getUrlPattern() {
    return normalizeUrlPattern(window.location.href);
  }

  async function getKeysForCurrentPage() {
    const all = await getAllUrlKeys();
    return all[getUrlPattern()] || null;
  }

  let _cryptoBroken = null;

  function uint8ToBase64(bytes) {
    const CHUNK = 0x8000;
    const parts = [];
    for (let i = 0; i < bytes.length; i += CHUNK) {
      parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
    }
    return btoa(parts.join(""));
  }
  function base64ToUint8(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  function isLikelyBase64(value) {
    return /^[A-Za-z0-9+/]+={0,2}$/.test(value);
  }

  const _keyCache = new Map();
  async function getCachedKey(password, saltValue, usage, iterations = 210000) {
    if (_cryptoBroken) throw new Error(_cryptoBroken);
    const id = usage + ":" + iterations + ":" + saltValue + ":" + hashString64(password);
    if (_keyCache.has(id)) return _keyCache.get(id);
    try {
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
      );
      const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: enc.encode(saltValue), iterations, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, false, [usage]
      );
      if (_keyCache.size > 128) _keyCache.delete(_keyCache.keys().next().value);
      _keyCache.set(id, key);
      return key;
    } catch (error) {
      const msg = error?.message || String(error);
      _cryptoBroken = msg;
      console.error("[MystoraEncrypt] crypto.subtle недоступен на этой странице:", error);
      throw error;
    }
  }

  function parseEncryptedPayload(text) {
    const normalized = (text || "").trim();
    if (!normalized.startsWith(ENCRYPTED_PREFIX)) return null;
    if (normalized.length > MAX_ENCRYPTED_PAYLOAD_LENGTH) return null;
    const rest = normalized.slice(ENCRYPTED_PREFIX.length);
    const m = rest.match(/^<([^:>]+):([^>]+)>$/);
    if (!m) return null;
    if (!isLikelyBase64(m[1]) || !isLikelyBase64(m[2])) return null;
    try {
      const iv = base64ToUint8(m[1]);
      const data = base64ToUint8(m[2]);
      if (iv.length !== 12) return null;
      return { iv, data };
    } catch {
      return null;
    }
  }

  async function decryptTextWithSalt(text, password, urlPattern) {
    const payload = parseEncryptedPayload(text);
    if (!payload) return null;
    const key = await getCachedKey(password, SALT_PREFIX + urlPattern, "decrypt", 210000);
    try {
      const buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: payload.iv }, key, payload.data);
      return new TextDecoder().decode(buf);
    } catch {
      return null;
    }
  }

  async function encryptTextWithSalt(text, password, urlPattern) {
    const enc = new TextEncoder();
    const key = await getCachedKey(password, SALT_PREFIX + urlPattern, "encrypt", 210000);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text)));
    return `${ENCRYPTED_PREFIX}<${uint8ToBase64(iv)}:${uint8ToBase64(ciphertext)}>`;
  }

  async function decryptWithAnyKey(text, keys, urlPattern) {
    if (!keys) return null;
    let result = await decryptTextWithSalt(text, keys.myKey, urlPattern);
    if (result !== null) return result;
    for (const peerKey of Object.values(keys.peerKeys || {})) {
      result = await decryptTextWithSalt(text, peerKey, urlPattern);
      if (result !== null) return result;
    }
    return null;
  }

  async function decryptWithAnyKeyLabeled(text, keys, urlPattern) {
    if (!keys) return null;
    let result = await decryptTextWithSalt(text, keys.myKey, urlPattern);
    if (result !== null) return { text: result, sender: "__ME__" };
    for (const [label, peerKey] of Object.entries(keys.peerKeys || {})) {
      result = await decryptTextWithSalt(text, peerKey, urlPattern);
      if (result !== null) return { text: result, sender: label };
    }
    return null;
  }

  async function decryptBatchLabeled(texts, keys) {
    const urlPattern = getUrlPattern();
    return Promise.all(texts.map((text) => decryptWithAnyKeyLabeled(text, keys, urlPattern)));
  }

  function cryptoBlockedMessage(error) {
    return (
      "Этот сайт блокирует доступ браузерных скриптов к криптографии (Web Crypto API) — " +
      "MystoraEncrypt здесь работать не может. Подробности: " + (error?.message || String(error))
    );
  }

  async function encryptForCurrentPage(text, sourceField, editingEntryId) {
    const keys = await getKeysForCurrentPage();
    if (!keys) return { success: false, message: "Ключи не настроены для этого сайта." };
    try {
      const encryptedText = await encryptTextWithSalt(text, keys.myKey, getUrlPattern());
      registerOutgoingMessage(text, encryptedText, sourceField || null, editingEntryId || null);
      return { success: true, encryptedText };
    } catch (error) {
      return { success: false, message: cryptoBlockedMessage(error) };
    }
  }

  function hashString64(str) {
    let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (h1 >>> 0).toString(36) + (h2 >>> 0).toString(36);
  }
  function keysFingerprint(keys) {
    return hashString64(`${keys.myKey}|${Object.values(keys.peerKeys || {}).sort().join(",")}`);
  }

  const TEXT_INPUT_TYPES = new Set(["text", "search", "email", "url", "tel"]);

  function isContentEditableElement(el) {
    if (!el || el.nodeType !== 1) return false;
    if (el.isContentEditable === true) return true;
    const attr = el.getAttribute && el.getAttribute("contenteditable");
    return attr === "true" || attr === "";
  }
  function isEditableElement(el) {
    if (!el || el.nodeType !== 1) return false;
    const tag = el.tagName;
    if (tag === "TEXTAREA") return !el.disabled && !el.readOnly;
    if (tag === "INPUT") {
      const type = (el.getAttribute("type") || "text").toLowerCase();
      return TEXT_INPUT_TYPES.has(type) && !el.disabled && !el.readOnly;
    }
    return isContentEditableElement(el);
  }
  function isVisible(el) {
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    const style = window.getComputedStyle(el);
    return style.visibility !== "hidden" && style.display !== "none";
  }
  function findEditableRoot(el) {
    let cur = el;
    while (cur && cur.nodeType === 1) {
      if (cur.tagName === "TEXTAREA" || cur.tagName === "INPUT") {
        return isEditableElement(cur) ? cur : null;
      }
      if (isContentEditableElement(cur) && !isContentEditableElement(cur.parentElement)) {
        return cur;
      }
      cur = cur.parentElement;
    }
    return null;
  }
  function getInputField() {
    const active = document.activeElement;
    if (active) {
      const root = findEditableRoot(active);
      if (root && isVisible(root)) return root;
    }
    if (_lastFocusedField && document.contains(_lastFocusedField) && isEditableElement(_lastFocusedField) && isVisible(_lastFocusedField)) {
      return _lastFocusedField;
    }
    const candidates = Array.from(
      document.querySelectorAll(
        'textarea, input[type="text"], input[type="search"], input[type="email"], ' +
        'input[type="url"], input[type="tel"], input:not([type]), [contenteditable="true"], [contenteditable=""]'
      )
    ).filter((el) => isEditableElement(el) && isVisible(el));
    if (!candidates.length) return null;
    candidates.sort((a, b) => {
      const ra = a.getBoundingClientRect();
      const rb = b.getBoundingClientRect();
      return rb.width * rb.height - ra.width * ra.height;
    });
    return candidates[0];
  }

  let _lastFocusedField = null;
  function isOwnUiElement(el) {
    return !!(el && el.closest && (
      el.closest(`#${OVERLAY_HOST_ID}`) ||
      el.closest(`#${SETTINGS_HOST_ID}`) ||
      el.closest(`#${TOOLBAR_HOST_ID}`)
    ));
  }
  document.addEventListener("focusin", (e) => {
    const el = e.target;
    if (!el || el.nodeType !== 1 || isOwnUiElement(el)) return;
    const root = findEditableRoot(el) || (isEditableElement(el) ? el : null);
    if (root) _lastFocusedField = root;
  }, true);
  function getFieldText(el) {
    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") return el.value || "";
    return el.innerText || el.textContent || "";
  }
  function setNativeInputValue(el, value) {
    const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  function wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function clearBrowserSelection() {
    try {
      const sel = window.getSelection();
      if (sel) sel.removeAllRanges();
    } catch {}
  }

  async function setFieldText(el, text) {
    el.scrollIntoView({ block: "nearest", behavior: "smooth" });
    el.focus();

    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
      setNativeInputValue(el, text);
      await wait(30);
      return el.value === text;
    }

    const selectAll = () => {
      const sel = window.getSelection();
      sel.removeAllRanges();
      const range = document.createRange();
      range.selectNodeContents(el);
      sel.addRange(range);
    };
    const currentText = () => (el.innerText || el.textContent || "").trim();
    const matches = () => currentText() === text.trim();

    selectAll();
    try {
      const dt = new DataTransfer();
      dt.setData("text/plain", text);
      el.dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }));
    } catch {}
    await wait(60);
    if (matches()) { clearBrowserSelection(); return true; }

    if (currentText().length > 0) {
      await clearField(el);
      el.focus();
    }

    selectAll();
    try { document.execCommand("insertText", false, text); } catch {}
    await wait(40);
    if (matches()) { clearBrowserSelection(); return true; }

    if (currentText().length > 0) {
      await clearField(el);
      el.focus();
    }

    el.textContent = text;
    el.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: text }));
    await wait(40);
    const result = matches();
    clearBrowserSelection();
    return result;
  }

  async function clearField(el) {
    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
      setNativeInputValue(el, "");
      await wait(30);
      return;
    }
    el.focus();
    const selectAll = () => {
      const sel = window.getSelection();
      sel.removeAllRanges();
      const range = document.createRange();
      range.selectNodeContents(el);
      sel.addRange(range);
    };
    const isEmpty = () => (el.innerText || el.textContent || "").trim().length === 0;

    for (let attempt = 0; attempt < 3 && !isEmpty(); attempt++) {
      selectAll();
      try { document.execCommand("delete", false); } catch {}
      await wait(40);
      if (isEmpty()) break;

      selectAll();
      try { document.execCommand("insertText", false, ""); } catch {}
      await wait(40);
      if (isEmpty()) break;

      el.textContent = "";
      el.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "deleteContentBackward" }));
      await wait(40);
    }
    clearBrowserSelection();
  }

  function panelStyles() {
    return `
      * { box-sizing: border-box; }
      .backdrop {
        position: fixed; inset: 0; background: rgba(10,14,17,0.55);
        display: flex; align-items: center; justify-content: center;
        z-index: 2147483647; font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
      }
      .modal {
        width: min(480px, 92vw); max-height: 88vh; overflow-y: auto;
        background: #162127; color: #e8f0f2;
        border-radius: 12px; border: 1px solid #30414a; box-shadow: 0 24px 60px rgba(0,0,0,0.45);
        padding: 16px; box-sizing: border-box;
      }
      .modal.wide { width: min(520px, 94vw); }
      @media (prefers-color-scheme: light) {
        .modal { background: #ffffff; color: #12212a; border-color: #d7e1e6; }
        textarea, input { background: #ffffff !important; color: #12212a !important; border-color: #cfdbe1 !important; }
      }
      .title { font-size: 14px; font-weight: 760; margin-bottom: 10px; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
      .title .close-x { cursor: pointer; opacity: 0.7; font-size: 16px; line-height: 1; background: none; border: 0; color: inherit; padding: 2px 6px; border-radius: 6px; }
      .title .close-x:hover { opacity: 1; background: rgba(255,255,255,0.08); }
      textarea, input[type="text"], input[type="password"], input[type="url"] {
        width: 100%; box-sizing: border-box; padding: 8px 10px; border-radius: 8px;
        border: 1px solid #33464f; background: #111a20; color: #e8f0f2;
        font: inherit; font-size: 13px; outline: none;
      }
      textarea { min-height: 120px; max-height: 40vh; resize: vertical; }
      textarea:focus, input:focus { outline: 2px solid #2db8a8; outline-offset: 1px; }
      .hint { margin-top: 6px; font-size: 11px; color: #9aaab2; }
      .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }
      button.btn { font: inherit; cursor: pointer; border: 0; border-radius: 7px; padding: 8px 14px; font-weight: 700; font-size: 13px; }
      button.btn-cancel { background: transparent; color: inherit; border: 1px solid #30414a; }
      button.btn-submit { background: #2db8a8; color: #06201d; }
      button.btn-submit:disabled { opacity: 0.45; cursor: not-allowed; }
      button.btn-secondary { background: transparent; color: #2db8a8; border: 1px solid #2db8a8; }
      button.btn-secondary:hover { background: rgba(45,184,168,0.12); }
      button.btn-danger { background: transparent; color: #f29b91; border: 1px solid #76413b; padding: 5px 8px; font-size: 11px; }
      button.icon-btn { width: 32px; height: 32px; flex: 0 0 auto; display: grid; place-items: center; background: #111a20; color: inherit; border: 1px solid #33464f; border-radius: 7px; cursor: pointer; font-size: 13px; }
      @media (prefers-color-scheme: light) { button.icon-btn { background: #edf3f5; } }
      .status { margin-top: 8px; font-size: 12px; min-height: 16px; }
      .status.error { color: #f29b91; }
      .status.ok { color: #7be0a4; }
      .section { margin-top: 14px; padding-top: 12px; border-top: 1px solid #30414a; }
      .section:first-of-type { border-top: 0; margin-top: 0; padding-top: 0; }
      .section-title { font-size: 11px; font-weight: 760; letter-spacing: 0.06em; text-transform: uppercase; color: #9aaab2; margin-bottom: 8px; }
      label { display: block; margin-bottom: 4px; font-size: 11px; font-weight: 700; letter-spacing: 0.04em; color: #9aaab2; }
      .field { margin-top: 9px; }
      .field:first-child { margin-top: 0; }
      .key-row { display: flex; gap: 6px; align-items: center; margin-top: 6px; }
      .key-row input { flex: 1 1 auto; min-width: 0; }
      .key-row .label-input { flex: 0 0 34%; }
      .peer-list { display: flex; flex-direction: column; gap: 8px; }
      .add-peer-btn { margin-top: 10px; width: 100%; padding: 7px; border-radius: 7px; border: 1px dashed #33464f; background: transparent; color: inherit; cursor: pointer; font: inherit; font-size: 12px; }
      .saved-list { display: grid; gap: 6px; max-height: 160px; overflow-y: auto; padding-right: 15px; }
      .saved-item { display: grid; grid-template-columns: 1fr auto; align-items: center; gap: 8px; padding: 6px 0; border-bottom: 1px solid #30414a; font-size: 12px; }
      .tabs { display: flex; gap: 6px; margin-bottom: 14px; }
      .tab-btn, .toggle-btn { flex: 1 1 auto; font: inherit; cursor: pointer; border: 1px solid #30414a; background: transparent; color: inherit; border-radius: 7px; padding: 7px 10px; font-size: 12px; font-weight: 700; opacity: 0.7; }
      .tab-btn.active, .toggle-btn.active { opacity: 1; background: rgba(45,184,168,0.12); border-color: #2db8a8; color: #2db8a8; }
      .tab-page { display: none; }
      .tab-page.active { display: block; }
      .toggle-group { display: flex; gap: 6px; margin-bottom: 8px; }
      .dropzone { border: 1px dashed #33464f; border-radius: 8px; padding: 20px 10px; text-align: center; font-size: 12px; color: #9aaab2; cursor: pointer; }
      .dropzone.drag { border-color: #2db8a8; color: #2db8a8; background: rgba(45,184,168,0.08); }
      .file-chip { margin-top: 8px; font-size: 12px; padding: 7px 10px; border-radius: 7px; background: #111a20; border: 1px solid #33464f; word-break: break-all; }
      @media (prefers-color-scheme: light) { .file-chip { background: #edf3f5; } }
      select { width: 100%; box-sizing: border-box; padding: 8px 10px; border-radius: 8px; border: 1px solid #33464f; background: #111a20; color: #e8f0f2; font: inherit; font-size: 13px; outline: none; }
      select:focus { outline: 2px solid #2db8a8; outline-offset: 1px; }
      @media (prefers-color-scheme: light) { select { background: #ffffff !important; color: #12212a !important; border-color: #cfdbe1 !important; } }
    `;
  }

  const OVERLAY_HOST_ID = "mystora-encrypt-overlay-host";
  let _overlayState = null;

  function closeOverlay() {
    if (!_overlayState) return;
    _overlayState.host.remove();
    _overlayState = null;
  }

  function openEncryptOverlay(targetField, initialText, editingEntryId) {
    if (_overlayState) {
      _overlayState.textarea.value = initialText || _overlayState.textarea.value;
      _overlayState.setTargetField(targetField);
      _overlayState.setEditingEntryId(editingEntryId || null);
      _overlayState.textarea.focus();
      return;
    }

    let currentTargetField = targetField;
    let currentEditingEntryId = editingEntryId || null;

    const host = document.createElement("div");
    host.id = OVERLAY_HOST_ID;
    const shadow = host.attachShadow({ mode: (typeof window !== "undefined" && window.__MYSTORA_TEST__) ? "open" : "closed" });
    const style = document.createElement("style");
    style.textContent = panelStyles();
    shadow.appendChild(style);

    const backdrop = document.createElement("div");
    backdrop.className = "backdrop";
    const modal = document.createElement("div");
    modal.className = "modal";
    const title = document.createElement("div");
    title.className = "title";
    const titleSpan = document.createElement("span");
    titleSpan.textContent = "🔒 MystoraEncrypt — безопасный ввод";
    title.appendChild(titleSpan);
    const closeX = document.createElement("button");
    closeX.className = "close-x";
    closeX.type = "button";
    closeX.textContent = "✕";
    closeX.addEventListener("click", () => closeOverlay());
    title.appendChild(closeX);

    const textarea = document.createElement("textarea");
    textarea.value = initialText || "";
    textarea.placeholder = "Наберите сообщение здесь";
    textarea.spellcheck = false;
    textarea.autocomplete = "off";
    textarea.setAttribute("autocapitalize", "off");
    textarea.setAttribute("autocorrect", "off");

    const fieldHint = document.createElement("div");
    fieldHint.className = "hint";

    const status = document.createElement("div");
    status.className = "status";
    const actions = document.createElement("div");
    actions.className = "actions";
    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "btn btn-cancel";
    cancelBtn.textContent = "Отмена";
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn btn-secondary";
    copyBtn.textContent = "Скопировать в буфер";
    const submitBtn = document.createElement("button");
    submitBtn.type = "button";
    submitBtn.className = "btn btn-submit";
    submitBtn.textContent = "Зашифровать и вставить";

    actions.append(cancelBtn, copyBtn, submitBtn);
    modal.append(title, textarea, fieldHint, status, actions);
    backdrop.appendChild(modal);
    shadow.appendChild(backdrop);
    document.documentElement.appendChild(host);

    function updateFieldAvailability() {
      const available = !!(currentTargetField && document.contains(currentTargetField));
      submitBtn.disabled = !available;
      submitBtn.title = available ? "" : "Поле ввода на странице не найдено.";
      fieldHint.textContent = available
        ? "Текст никуда не отправляется, пока вы сами не нажмёте «Зашифровать и вставить»."
        : "Поле ввода на странице не найдено — вставка недоступна. Скопируйте зашифрованный текст в буфер и вставьте вручную в нужное поле.";
    }

    function setTargetField(field) {
      currentTargetField = field;
      updateFieldAvailability();
    }
    function setEditingEntryId(id) {
      currentEditingEntryId = id || null;
    }

    async function submit() {
      if (!currentTargetField) return;
      const text = textarea.value;
      if (!text.trim()) { closeOverlay(); return; }
      submitBtn.disabled = true;
      status.textContent = "";
      status.className = "status";
      try {
        const response = await encryptForCurrentPage(text, currentTargetField, currentEditingEntryId);
        if (!response.success) {
          status.textContent = response.message || "Ошибка шифрования.";
          status.className = "status error";
          submitBtn.disabled = false;
          return;
        }
        let inserted = false;
        try { inserted = await setFieldText(currentTargetField, response.encryptedText); }
        catch (error) { console.error("[MystoraEncrypt] failed to write into field", error); }

        if (!inserted) {
          try {
            await navigator.clipboard.writeText(response.encryptedText);
            status.textContent = "Не удалось вставить автоматически — текст скопирован в буфер (Ctrl+V).";
          } catch {
            status.textContent = "Не удалось вставить текст. Кликните в поле ввода сайта и повторите.";
          }
          status.className = "status error";
          submitBtn.disabled = false;
          return;
        }
        closeOverlay();
      } catch (error) {
        console.error("[MystoraEncrypt] overlay encryption failed", error);
        status.textContent = "Ошибка: " + (error?.message || String(error));
        status.className = "status error";
        submitBtn.disabled = false;
      }
    }

    async function copyToClipboard() {
      const text = textarea.value;
      if (!text.trim()) { closeOverlay(); return; }
      copyBtn.disabled = true;
      status.textContent = "";
      status.className = "status";
      try {
        const response = await encryptForCurrentPage(text, currentTargetField, currentEditingEntryId);
        if (!response.success) {
          status.textContent = response.message || "Ошибка шифрования.";
          status.className = "status error";
          return;
        }
        try {
          await navigator.clipboard.writeText(response.encryptedText);
          status.textContent = "Зашифрованный текст скопирован в буфер обмена.";
          status.className = "status ok";
        } catch (error) {
          console.error("[MystoraEncrypt] clipboard write failed", error);
          status.textContent = "Не удалось скопировать в буфер: " + (error?.message || String(error));
          status.className = "status error";
        }
      } catch (error) {
        console.error("[MystoraEncrypt] overlay copy-to-clipboard failed", error);
        status.textContent = "Ошибка: " + (error?.message || String(error));
        status.className = "status error";
      } finally {
        copyBtn.disabled = false;
      }
    }

    updateFieldAvailability();
    cancelBtn.addEventListener("click", () => closeOverlay());
    submitBtn.addEventListener("click", submit);
    copyBtn.addEventListener("click", copyToClipboard);
    backdrop.addEventListener("mousedown", (e) => { if (e.target === backdrop) closeOverlay(); });

    _overlayState = { host, shadow, textarea, setTargetField, setEditingEntryId };
    setTimeout(() => textarea.focus(), 0);
  }

  function injectPageStyles() {
    if (document.getElementById("mystora-encrypt-styles")) return;
    const style = document.createElement("style");
    style.id = "mystora-encrypt-styles";
    style.textContent = `
      .${DECRYPTED_BADGE_CLASS}, .${LOCKED_BADGE_CLASS} {
        display: inline-block; margin-right: 3px; font-size: 0.85em; line-height: 1;
        vertical-align: baseline; user-select: none;
      }
      .${LOCKED_BADGE_CLASS} { cursor: pointer; }
      [${ENCRYPTED_MARK_ATTR}] { cursor: pointer; }
      [${ENCRYPTED_MARK_ATTR}]:hover { background: rgba(15,118,110,0.08); border-radius: 4px; }
    `;
    document.head.appendChild(style);
  }

  function insertBadgeIcon(textNode, className, icon, title) {
    const prev = textNode.previousSibling;
    if (prev && prev.nodeType === 1 && prev.classList && (prev.classList.contains(DECRYPTED_BADGE_CLASS) || prev.classList.contains(LOCKED_BADGE_CLASS))) {
      prev.className = className;
      prev.textContent = icon;
      prev.title = title;
      return prev;
    }
    const badge = document.createElement("span");
    badge.className = className;
    badge.textContent = icon;
    badge.title = title;
    badge.setAttribute("aria-hidden", "true");
    textNode.parentNode.insertBefore(badge, textNode);
    return badge;
  }

  let _decryptedNodes = new WeakMap();
  const _cipherToEntryId = new Map();

  function isCandidateTextNode(node) {
    const raw = (node.data || "").trim();
    if (!raw) return false;
    if (_decryptedNodes.has(node)) return false;
    return raw.startsWith(ENCRYPTED_PREFIX);
  }

  function collectRawCandidateTextNodes(includeAlreadyHandled) {
    const root = document.body;
    if (!root) return [];
    const raw = [];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent || SKIP_TAGS.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
        if (parent.classList && (parent.classList.contains(DECRYPTED_BADGE_CLASS) || parent.classList.contains(LOCKED_BADGE_CLASS))) {
          return NodeFilter.FILTER_REJECT;
        }
        if (parent.closest('[contenteditable="true"], [contenteditable=""], textarea, input')) {
          return NodeFilter.FILTER_REJECT;
        }
        if (parent.closest('a[href]')) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    let visited = 0;
    let node = walker.nextNode();
    while (node && visited < MAX_SCAN_NODES) {
      visited++;
      const isCandidate = includeAlreadyHandled
        ? (node.data || "").trim().startsWith(ENCRYPTED_PREFIX)
        : isCandidateTextNode(node);
      if (isCandidate) raw.push(node);
      node = walker.nextNode();
    }
    return raw;
  }

  function collectCandidateTextNodes() {
    return filterToTrustedFeed(collectRawCandidateTextNodes(false));
  }

  function computeTrustedFeedRoot(candidates) {
    if (candidates.length < 3) return null;
    const threshold = Math.max(2, Math.ceil(candidates.length * 0.6));
    const counts = new Map();
    for (const node of candidates) {
      let el = node.parentElement;
      let depth = 0;
      while (el && depth < 24) {
        let set = counts.get(el);
        if (!set) { set = new Set(); counts.set(el, set); }
        set.add(node);
        el = el.parentElement;
        depth++;
      }
    }
    let best = null;
    let bestSize = Infinity;
    for (const [el, set] of counts) {
      if (set.size >= threshold && set.size < bestSize) {
        best = el;
        bestSize = set.size;
      }
    }
    return best;
  }

  function knownDecryptedFeedNodes(limit) {
    const nodes = [];
    for (let i = _panelEntries.length - 1; i >= 0 && nodes.length < limit; i--) {
      const entry = _panelEntries[i];
      if (entry.node && entry.node.isConnected) nodes.push(entry.node);
    }
    nodes.reverse();
    return nodes;
  }
  const ANCHOR_SIGNATURE_DEPTH = 5;
  const ANCHOR_SIGNATURE_MIN_MATCH = 3;
  const ANCHOR_LIMIT = 200;

  function ancestorSignatureSet(node, depth) {
    const set = new Set();
    let el = node.parentElement;
    for (let d = 0; d < depth && el; d++) {
      const cls = typeof el.className === "string"
        ? el.className.trim().split(/\s+/).filter(Boolean).sort().join(" ")
        : "";
      set.add(el.tagName + "|" + cls);
      el = el.parentElement;
    }
    return set;
  }

  let _ancestorSignatureCache = new WeakMap();
  function cachedAncestorSignature(node, depth) {
    let sig = _ancestorSignatureCache.get(node);
    if (!sig) {
      sig = ancestorSignatureSet(node, depth);
      _ancestorSignatureCache.set(node, sig);
    }
    return sig;
  }

  function countSetOverlap(setA, setB) {
    let count = 0;
    for (const item of setA) {
      if (setB.has(item)) count++;
    }
    return count;
  }

  function filterToTrustedFeed(candidates) {
    const anchors = knownDecryptedFeedNodes(ANCHOR_LIMIT);
    if (anchors.length) {
      const anchorSignatures = anchors.map((a) => cachedAncestorSignature(a, ANCHOR_SIGNATURE_DEPTH));
      return candidates.filter((node) => {
        const sig = cachedAncestorSignature(node, ANCHOR_SIGNATURE_DEPTH);
        return anchorSignatures.some((asig) => countSetOverlap(sig, asig) >= ANCHOR_SIGNATURE_MIN_MATCH);
      });
    }

    const fresh = candidates.filter((node) => !_failedFingerprints.has(node));
    const root = fresh.length ? computeTrustedFeedRoot(fresh) : null;
    if (!root) return candidates;
    return candidates.filter((node) => root.contains(node));
  }

  function findEncryptedTextNodeIn(el) {
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    let node = walker.nextNode();
    while (node) {
      if (isCandidateTextNode(node)) return node;
      node = walker.nextNode();
    }
    return null;
  }

  const _failedFingerprints = new WeakMap();
  let _reprocessingAfterFailure = false;

  function isInReversedFlexContainer(node) {
    let el = node && node.nodeType === Node.TEXT_NODE ? node.parentElement : node;
    let depth = 0;
    while (el && depth < 15) {
      try {
        if (getComputedStyle(el).flexDirection === "column-reverse") return true;
      } catch {}
      el = el.parentElement;
      depth++;
    }
    return false;
  }

  let _domOrderReversedEmpirical = null;

  function calibrateDomOrderFromOwnMessage(newNode, referenceNodes) {
    if (_domOrderReversedEmpirical !== null) return;
    if (!referenceNodes) return;
    for (const other of referenceNodes) {
      if (!other || other === newNode || !other.isConnected) continue;
      const pos = other.compareDocumentPosition(newNode);
      if (pos & Node.DOCUMENT_POSITION_FOLLOWING) {
        _domOrderReversedEmpirical = false;
        return;
      }
      if (pos & Node.DOCUMENT_POSITION_PRECEDING) {
        _domOrderReversedEmpirical = true;
        return;
      }
    }
  }

  function findPanelInsertIndex(newNode) {
    const reversed = _domOrderReversedEmpirical !== null
      ? _domOrderReversedEmpirical
      : isInReversedFlexContainer(newNode);
    for (let i = _panelEntries.length - 1; i >= 0; i--) {
      const otherNode = _panelEntries[i].node;
      if (!otherNode || !otherNode.isConnected) continue;
      const pos = otherNode.compareDocumentPosition(newNode);
      const otherIsEarlier = reversed
        ? !!(pos & Node.DOCUMENT_POSITION_PRECEDING)
        : !!(pos & Node.DOCUMENT_POSITION_FOLLOWING);
      if (otherIsEarlier) return i + 1;
    }
    return 0;
  }

  function relinkDecryptedNode(textNode, id) {
    if (_decryptedNodes.has(textNode)) return;
    _decryptedNodes.set(textNode, id);
    for (const entry of _panelEntries) {
      if (entry.id === id) { entry.node = textNode; break; }
    }
    const badge = insertBadgeIcon(textNode, DECRYPTED_BADGE_CLASS, "🔓", "Расшифровано — нажмите, чтобы открыть в панели MystoraEncrypt");
    if (badge) badge.dataset.mystoraEntryId = id;
    const parent = textNode.parentElement;
    if (parent) parent.removeAttribute(ENCRYPTED_MARK_ATTR);
  }

  function stableEntryId(cipherText) {
    return "m" + hashString64(cipherText);
  }

  function recordDecryptedMessage(textNode, decryptedText, rawCipherText, sender) {
    if (_decryptedNodes.has(textNode)) return _decryptedNodes.get(textNode);

    let id = rawCipherText ? _cipherToEntryId.get(rawCipherText) : undefined;
    if (id !== undefined) {
      relinkDecryptedNode(textNode, id);
      return id;
    }

    id = rawCipherText ? stableEntryId(rawCipherText) : "m" + (++_panelEntrySeq) + "_" + Date.now().toString(36);
    const entry = { id, text: decryptedText, sender: sender || null, node: textNode };
    _panelEntries.splice(findPanelInsertIndex(textNode), 0, entry);
    _panelUnread++;
    if (rawCipherText) _cipherToEntryId.set(rawCipherText, id);
    updatePanelBadge();
    if (_panelState) renderPanelEntries(_panelState.listEl);

    relinkDecryptedNode(textNode, id);
    return id;
  }

  const _pendingOutgoing = new Map();

  function registerOutgoingMessage(plainText, cipherText, sourceField, editingEntryId) {
    if (!cipherText || _cipherToEntryId.has(cipherText)) return;
    _pendingOutgoing.set(cipherText, {
      plainText,
      sourceField: sourceField || null,
      editingEntryId: editingEntryId || null,
    });
  }

  function cancelPendingOutgoing(cipherText) {
    const pending = _pendingOutgoing.get(cipherText);
    if (pending) pending.cancelled = true;
  }

  function isStillUnsentDraft(cipherText, pending) {
    const field = pending.sourceField;
    if (field && document.contains(field)) {
      try {
        if (getFieldText(field).trim() === cipherText) return true;
      } catch {}
    }
    try {
      const fields = document.querySelectorAll(
        'textarea, input[type="text"], input[type="search"], input[type="email"], ' +
        'input[type="url"], input[type="tel"], input:not([type]), [contenteditable="true"], [contenteditable=""]'
      );
      for (const el of fields) {
        if (getFieldText(el).trim() === cipherText) return true;
      }
    } catch {}
    return false;
  }

  function recordOwnSentMessage(textNode, plainText, cipherText, referenceNodes) {
    if (_decryptedNodes.has(textNode)) return _decryptedNodes.get(textNode);
    calibrateDomOrderFromOwnMessage(textNode, referenceNodes);
    const id = stableEntryId(cipherText);
    const entry = { id, text: plainText, sender: "__ME__", node: textNode };
    _panelEntries.push(entry);
    _cipherToEntryId.set(cipherText, id);
    _panelUnread++;
    updatePanelBadge();
    if (_panelState) renderPanelEntries(_panelState.listEl);
    relinkDecryptedNode(textNode, id);
    return id;
  }

  function updateOwnEditedMessage(textNode, plainText, cipherText, entryId) {
    if (_decryptedNodes.has(textNode)) return _decryptedNodes.get(textNode);

    const entry = _panelEntries.find((e) => e.id === entryId);
    if (!entry) {
      return recordOwnSentMessage(textNode, plainText, cipherText, collectCandidateTextNodes());
    }

    entry.text = plainText;
    entry.sender = "__ME__";
    _cipherToEntryId.set(cipherText, entryId);
    updatePanelBadge();
    if (_panelState) renderPanelEntries(_panelState.listEl);
    relinkDecryptedNode(textNode, entryId);
    return entryId;
  }

  function markLocked(textNode, failed) {
    insertBadgeIcon(
      textNode, LOCKED_BADGE_CLASS, "🔒",
      failed ? "Не удалось расшифровать текущими ключами. Нажмите, чтобы попробовать снова" : "Зашифрованный текст. Нажмите, чтобы расшифровать"
    );
    const parent = textNode.parentElement;
    if (parent) parent.setAttribute(ENCRYPTED_MARK_ATTR, "1");
  }

  function markEncryptedInFeed(nodes) {
    const list = nodes || collectCandidateTextNodes();
    for (const node of list) {
      markLocked(node, _failedFingerprints.has(node));
    }
  }

  function resetPanelState() {
    _panelEntries.length = 0;
    _cipherToEntryId.clear();
    _decryptedNodes = new WeakMap();
    _domOrderReversedEmpirical = null;
    _panelUnread = 0;
    _ancestorSignatureCache = new WeakMap();
    updatePanelBadge();
    if (_panelState) renderPanelEntries(_panelState.listEl);
  }

  let _lastLocationHref = typeof location !== "undefined" ? location.href : "";

  function checkForConversationChange() {
    if (typeof location === "undefined") return;
    if (location.href === _lastLocationHref) return;
    _lastLocationHref = location.href;
    resetPanelState();
  }

  function detectContentFeedReplaced() {
    if (!_panelEntries.length) return false;
    return !_panelEntries.some((entry) => entry.node && entry.node.isConnected);
  }

  async function processMessages() {
    checkForConversationChange();
    if (detectContentFeedReplaced()) resetPanelState();

    const keys = await getKeysForCurrentPage();
    if (!keys) return { found: 0, decrypted: 0, noKeys: true };

    const hadAnchorsAtStart = knownDecryptedFeedNodes(1).length > 0;
    const allCandidates = collectCandidateTextNodes();

    if (_cryptoBroken) {
      markEncryptedInFeed(allCandidates);
      return { found: allCandidates.length, decrypted: 0, cryptoBlocked: true, cryptoError: _cryptoBroken };
    }

    const fingerprint = keysFingerprint(keys);

    const toDecrypt = [];
    for (const node of allCandidates) {
      if (_failedFingerprints.get(node) === fingerprint) continue;
      const raw = (node.data || "").trim();
      const knownId = _cipherToEntryId.get(raw);
      if (knownId !== undefined) {
        relinkDecryptedNode(node, knownId);
        continue;
      }
      const pending = _pendingOutgoing.get(raw);
      if (pending !== undefined) {
        if (pending.cancelled) {
          continue;
        }
        if (isStillUnsentDraft(raw, pending)) {
          continue;
        }
        _pendingOutgoing.delete(raw);
        if (pending.editingEntryId) {
          updateOwnEditedMessage(node, pending.plainText, raw, pending.editingEntryId);
        } else {
          recordOwnSentMessage(node, pending.plainText, raw, allCandidates);
        }
        continue;
      }
      toDecrypt.push(node);
    }

    if (!toDecrypt.length) {
      markEncryptedInFeed(allCandidates.filter((node) => !_decryptedNodes.has(node)));
      return { found: allCandidates.length, decrypted: 0 };
    }

    const texts = toDecrypt.map((node) => (node.data || "").trim());
    let results;
    try {
      results = await decryptBatchLabeled(texts, keys);
    } catch (error) {
      console.error("[MystoraEncrypt] decrypt failed", error);
      markEncryptedInFeed(allCandidates);
      return { found: allCandidates.length, decrypted: 0, cryptoBlocked: true, cryptoError: error?.message || String(error) };
    }

    let newlyDecrypted = 0;
    let newlyFailed = 0;
    toDecrypt.forEach((node, i) => {
      const decrypted = results[i];
      if (decrypted && typeof decrypted.text === "string") {
        recordDecryptedMessage(node, decrypted.text, texts[i], decrypted.sender);
        newlyDecrypted++;
      } else {
        _failedFingerprints.set(node, fingerprint);
        markLocked(node, true);
        newlyFailed++;
      }
    });

    markEncryptedInFeed(allCandidates.filter((node) => !_decryptedNodes.has(node)));

    if (newlyFailed > 0 && !hadAnchorsAtStart && !_reprocessingAfterFailure) {
      _reprocessingAfterFailure = true;
      try {
        const retry = await processMessages();
        return { found: Math.max(allCandidates.length, retry.found), decrypted: newlyDecrypted + retry.decrypted };
      } finally {
        _reprocessingAfterFailure = false;
      }
    }

    return { found: allCandidates.length, decrypted: newlyDecrypted };
  }

  let _showToast = null;

  async function runDiagnostics() {
    const keys = await getKeysForCurrentPage();
    const rawNodes = collectRawCandidateTextNodes(true);
    const stillUnhandled = rawNodes.filter((node) => !_decryptedNodes.has(node));
    const trustedNodes = new Set(filterToTrustedFeed(stillUnhandled));
    const fingerprint = keys ? keysFingerprint(keys) : null;

    const anchors = knownDecryptedFeedNodes(ANCHOR_LIMIT);
    const anchorSignaturesForDiag = anchors.map((a) => ancestorSignatureSet(a, ANCHOR_SIGNATURE_DEPTH));

    const rows = rawNodes.map((node, i) => {
      const text = (node.data || "").trim();
      const preview = text.length > 44 ? text.slice(0, 44) + "…" : text;

      let status;
      if (_decryptedNodes.has(node)) {
        status = "расшифровано (🔓)";
      } else if (_failedFingerprints.has(node)) {
        status = _failedFingerprints.get(node) === fingerprint
          ? "не расшифровалось текущими ключами (🔒)"
          : "не расшифровалось СТАРЫМИ ключами — будет проверено заново";
      } else if (_pendingOutgoing.has(text)) {
        status = "своё исходящее, ждёт подтверждения отправки";
      } else {
        status = "ещё не обработано";
      }

      let el = node.parentElement;
      const pathParts = [];
      for (let d = 0; d < 4 && el; d++) {
        const clsRaw = typeof el.className === "string" ? el.className.trim() : "";
        const cls = clsRaw ? "." + clsRaw.split(/\s+/).slice(0, 2).join(".") : "";
        pathParts.push(el.tagName.toLowerCase() + cls);
        el = el.parentElement;
      }

      let anchorMatch = "—";
      if (!_decryptedNodes.has(node)) {
        if (anchorSignaturesForDiag.length) {
          const sig = ancestorSignatureSet(node, ANCHOR_SIGNATURE_DEPTH);
          const best = Math.max(0, ...anchorSignaturesForDiag.map((asig) => countSetOverlap(sig, asig)));
          anchorMatch = `${best} из ${ANCHOR_SIGNATURE_DEPTH} (порог ${ANCHOR_SIGNATURE_MIN_MATCH})`;
        } else {
          anchorMatch = "якорей ещё нет";
        }
      }

      return {
        "№": i + 1,
        "Текст (превью)": preview,
        "В доверенной ленте": _decryptedNodes.has(node)
          ? "да (уже обработано)"
          : (trustedNodes.has(node) ? "да" : "НЕТ — отфильтровано"),
        Статус: status,
        "Совпадение с якорем": anchorMatch,
        "DOM-путь (снизу вверх)": pathParts.join(" ‹ "),
      };
    });

    console.log("%c[MystoraEncrypt] Диагностика ленты сообщений", "font-weight:bold;font-size:13px;");
    console.log({
      "Ключи для этого сайта настроены": !!keys,
      "Всего найдено узлов с шифротекстом": rawNodes.length,
      "Из них уже успешно расшифровано ранее": rawNodes.length - stillUnhandled.length,
      "Ещё не обработано и прошло фильтр «доверенная лента»": trustedNodes.size,
      "Отфильтровано, не будет расшифровано": stillUnhandled.length - trustedNodes.size,
    });
    if (rows.length) console.table(rows);
    else console.log("Ни одного узла с шифротекстом на странице сейчас не найдено.");
    console.log(
      "Подсказка: строки с «НЕТ — отфильтровано» — это узлы, которые эвристика сочла НЕ " +
      "настоящей лентой переписки (например, превью в сайдбаре списка чатов). Если среди " +
      "них есть настоящие сообщения — скопируйте эту таблицу целиком (можно правой кнопкой " +
      "по таблице → Copy)."
    );

    _showToast?.("Диагностика выведена в консоль (F12 → Console).", false);
    return { total: rawNodes.length, trusted: trustedNodes.size, rows };
  }

  async function handleFeedMessageClick(e) {
    const container = e.target.closest ? e.target.closest(`[${ENCRYPTED_MARK_ATTR}]`) : null;
    const badgeClicked = e.target.closest ? e.target.closest(`.${LOCKED_BADGE_CLASS}`) : null;
    if (!container && !badgeClicked) return;
    const scope = container || badgeClicked.parentElement;
    if (!scope) return;
    const textNode = findEncryptedTextNodeIn(scope);
    if (!textNode) return;

    e.preventDefault();
    e.stopPropagation();

    const keys = await getKeysForCurrentPage();
    if (!keys) return;
    const fingerprint = keysFingerprint(keys);
    const raw = (textNode.data || "").trim();

    const knownId = _cipherToEntryId.get(raw);
    if (knownId !== undefined) {
      relinkDecryptedNode(textNode, knownId);
      openDecryptedPanel(knownId);
      return;
    }
    const pending = _pendingOutgoing.get(raw);
    if (pending !== undefined && !pending.cancelled && !isStillUnsentDraft(raw, pending)) {
      _pendingOutgoing.delete(raw);
      const ownId = pending.editingEntryId
        ? updateOwnEditedMessage(textNode, pending.plainText, raw, pending.editingEntryId)
        : recordOwnSentMessage(textNode, pending.plainText, raw, collectCandidateTextNodes());
      openDecryptedPanel(ownId);
      return;
    }

    let decrypted;
    try {
      decrypted = await decryptWithAnyKeyLabeled(raw, keys, getUrlPattern());
    } catch (error) {
      console.error("[MystoraEncrypt] click-to-decrypt failed", error);
      return;
    }

    if (!decrypted || typeof decrypted.text !== "string") {
      _failedFingerprints.set(textNode, fingerprint);
      markLocked(textNode, true);
      return;
    }
    const id = recordDecryptedMessage(textNode, decrypted.text, raw, decrypted.sender);
    openDecryptedPanel(id);
  }

  async function handleDecryptedBadgeClick(e) {
    const badge = e.target.closest ? e.target.closest(`.${DECRYPTED_BADGE_CLASS}`) : null;
    if (!badge) return;
    e.preventDefault();
    e.stopPropagation();
    openDecryptedPanel(badge.dataset.mystoraEntryId || null);
  }

  let _observerTimer = null;
  let _mutationObserver = null;
  let _observerStarted = false;

  function startMessageObserver() {
    if (!document.body || _mutationObserver) return;
    _mutationObserver = new MutationObserver(() => {
      if (_observerTimer) clearTimeout(_observerTimer);
      _observerTimer = setTimeout(() => { processMessages().catch(() => {}); }, 300);
    });
    _mutationObserver.observe(document.body, { childList: true, characterData: true, subtree: true });
  }

  async function maybeStartObserver() {
    if (_observerStarted) return;
    const keys = await getKeysForCurrentPage();
    if (!keys) return;
    _observerStarted = true;
    startMessageObserver();
    await processMessages();
  }

  async function actionEncrypt() {
    const inputField = getInputField();

    if (!inputField) {
      openEncryptOverlay(null, "");
      return { success: true, message: null };
    }

    const keys = await getKeysForCurrentPage();
    if (!keys) return { success: false, message: "Ключи не настроены для этого сайта." };

    const existingText = getFieldText(inputField).trim();

    if (!existingText) {
      openEncryptOverlay(inputField, "");
      return { success: true, message: "Введите текст в открывшемся окне." };
    }

    if (existingText.startsWith(ENCRYPTED_PREFIX)) {
      return { success: false, message: "Текст уже зашифрован." };
    }

    const response = await encryptForCurrentPage(existingText, inputField);
    if (!response.success) return { success: false, message: response.message || "Ошибка шифрования." };

    let inserted = false;
    try { inserted = await setFieldText(inputField, response.encryptedText); }
    catch (error) { console.error("[MystoraEncrypt] failed to write into field", error); }

    if (inserted) return { success: true, message: "Текст зашифрован." };

    try {
      await navigator.clipboard.writeText(response.encryptedText);
      return { success: false, message: "Текст скопирован в буфер. Вставьте в поле ввода (Ctrl+V)." };
    } catch {
      return { success: false, message: "Кликните в поле ввода и нажмите «Зашифровать» снова." };
    }
  }

  function findUndecryptedNodeWithCipher(cipherText) {
    for (const node of collectCandidateTextNodes()) {
      if ((node.data || "").trim() === cipherText) return node;
    }
    return null;
  }

  async function actionDecryptField() {
    const inputField = getInputField();
    const existingText = inputField ? getFieldText(inputField).trim() : "";
    const isEncryptedField = existingText.startsWith(ENCRYPTED_PREFIX);
    if (!inputField || !isEncryptedField) return { handled: false };

    const keys = await getKeysForCurrentPage();
    if (!keys) return { handled: true, success: false, message: "Ключи не настроены для этого сайта." };

    let decrypted;
    try {
      decrypted = await decryptWithAnyKey(existingText, keys, getUrlPattern());
    } catch (error) {
      return { handled: true, success: false, message: cryptoBlockedMessage(error) };
    }
    if (typeof decrypted !== "string") {
      return { handled: true, success: false, message: "Не удалось расшифровать текущими ключами." };
    }

    let editingEntryId = _cipherToEntryId.get(existingText);
    if (editingEntryId === undefined) {
      const feedNode = findUndecryptedNodeWithCipher(existingText);
      editingEntryId = feedNode ? recordDecryptedMessage(feedNode, decrypted, existingText, "__ME__") : null;
    }

    cancelPendingOutgoing(existingText);

    try { await clearField(inputField); } catch {}
    openEncryptOverlay(inputField, decrypted, editingEntryId);
    return { handled: true, success: true, message: "Текст в поле расшифрован для редактирования." };
  }

  async function decryptButtonAction() {
    const fieldResult = await actionDecryptField();
    if (fieldResult.handled) return { success: fieldResult.success, message: fieldResult.message };
    openDecryptedPanel();
    return { success: true, message: null };
  }

  const SETTINGS_HOST_ID = "mystora-settings-host";
  let _settingsState = null;

  function closeSettings() {
    if (!_settingsState) return;
    _settingsState.host.remove();
    _settingsState = null;
  }

  function makeKeyRow(label, value, { removable, onGenerate, onRemove }) {
    const row = document.createElement("div");
    row.className = "key-row";

    let labelInput = null;
    if (label !== undefined) {
      labelInput = document.createElement("input");
      labelInput.type = "text";
      labelInput.className = "label-input";
      labelInput.placeholder = "Имя";
      labelInput.value = label;
      row.appendChild(labelInput);
    }

    const keyInput = document.createElement("input");
    keyInput.type = "password";
    keyInput.value = value || "";
    keyInput.placeholder = "Ключ";
    keyInput.autocomplete = "off";
    row.appendChild(keyInput);

    const genBtn = document.createElement("button");
    genBtn.type = "button";
    genBtn.className = "icon-btn";
    genBtn.title = "Сгенерировать случайный ключ";
    genBtn.textContent = "✦";
    genBtn.addEventListener("click", () => {
      keyInput.value = generateKey();
      keyInput.type = "text";
      toggleBtn.textContent = "🙈";
      onGenerate?.();
    });
    row.appendChild(genBtn);

    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "icon-btn";
    toggleBtn.title = "Показать/скрыть";
    toggleBtn.textContent = "👁";
    toggleBtn.addEventListener("click", () => {
      const show = keyInput.type === "password";
      keyInput.type = show ? "text" : "password";
      toggleBtn.textContent = show ? "🙈" : "👁";
    });
    row.appendChild(toggleBtn);

    if (removable) {
      const removeBtn = document.createElement("button");
      removeBtn.type = "button";
      removeBtn.className = "icon-btn";
      removeBtn.title = "Удалить";
      removeBtn.textContent = "✕";
      removeBtn.addEventListener("click", () => { row.remove(); onRemove?.(); });
      row.appendChild(removeBtn);
    }

    return { row, labelInput, keyInput };
  }

  function generateKey(length = 32) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    const maxValidByte = 256 - (256 % chars.length);
    let result = "";
    while (result.length < length) {
      const arr = new Uint8Array(length * 2);
      crypto.getRandomValues(arr);
      for (const byte of arr) {
        if (byte >= maxValidByte) continue;
        result += chars[byte % chars.length];
        if (result.length === length) break;
      }
    }
    return result;
  }

  async function openSettingsPanel(initialTab) {
    if (_settingsState) { _settingsState.host.scrollIntoView?.(); _settingsState.activateTab?.(initialTab); return; }

    const host = document.createElement("div");
    host.id = SETTINGS_HOST_ID;
    const shadow = host.attachShadow({ mode: (typeof window !== "undefined" && window.__MYSTORA_TEST__) ? "open" : "closed" });
    const style = document.createElement("style");
    style.textContent = panelStyles();
    shadow.appendChild(style);

    const backdrop = document.createElement("div");
    backdrop.className = "backdrop";
    const modal = document.createElement("div");
    modal.className = "modal wide";

    const title = document.createElement("div");
    title.className = "title";
    const settingsTitleSpan = document.createElement("span");
    settingsTitleSpan.textContent = "⚙ MystoraEncrypt — ключи";
    title.appendChild(settingsTitleSpan);
    const closeX = document.createElement("button");
    closeX.className = "close-x";
    closeX.type = "button";
    closeX.textContent = "✕";
    closeX.addEventListener("click", () => closeSettings());
    title.appendChild(closeX);
    modal.appendChild(title);

    const tabs = document.createElement("div");
    tabs.className = "tabs";
    const tabKeysBtn = document.createElement("button");
    tabKeysBtn.type = "button";
    tabKeysBtn.className = "tab-btn";
    tabKeysBtn.textContent = "🔑 Ключи";
    const tabFilesBtn = document.createElement("button");
    tabFilesBtn.type = "button";
    tabFilesBtn.className = "tab-btn";
    tabFilesBtn.textContent = "📁 Файлы";
    tabs.append(tabKeysBtn, tabFilesBtn);
    modal.appendChild(tabs);

    const tabPageKeys = document.createElement("div");
    tabPageKeys.className = "tab-page";
    const tabPageFiles = document.createElement("div");
    tabPageFiles.className = "tab-page";
    modal.append(tabPageKeys, tabPageFiles);

    function activateTab(name) {
      const filesActive = name === "files";
      tabKeysBtn.classList.toggle("active", !filesActive);
      tabFilesBtn.classList.toggle("active", filesActive);
      tabPageKeys.classList.toggle("active", !filesActive);
      tabPageFiles.classList.toggle("active", filesActive);
      settingsTitleSpan.textContent = filesActive ? "⚙ MystoraEncrypt — файлы" : "⚙ MystoraEncrypt — ключи";
      if (filesActive) refreshFileKeyOptions().catch(() => {});
    }
    tabKeysBtn.addEventListener("click", () => activateTab("keys"));
    tabFilesBtn.addEventListener("click", () => activateTab("files"));

    const siteSection = document.createElement("div");
    siteSection.className = "section";
    const siteLabel = document.createElement("label");
    siteLabel.textContent = "Сайт (URL)";
    siteSection.appendChild(siteLabel);
    const urlInput = document.createElement("input");
    urlInput.type = "url";
    urlInput.placeholder = "https://example.com/";
    urlInput.value = normalizeUrlPattern(window.location.href) || "";
    siteSection.appendChild(urlInput);
    tabPageKeys.appendChild(siteSection);

    const mySection = document.createElement("div");
    mySection.className = "section";
    const myTitle = document.createElement("div");
    myTitle.className = "section-title";
    myTitle.textContent = "Ваш ключ";
    mySection.appendChild(myTitle);
    const myRow = makeKeyRow(undefined, "", { removable: false });
    mySection.appendChild(myRow.row);
    tabPageKeys.appendChild(mySection);

    const peersSection = document.createElement("div");
    peersSection.className = "section";
    const peersTitle = document.createElement("div");
    peersTitle.className = "section-title";
    peersTitle.textContent = "Ключи собеседников";
    peersSection.appendChild(peersTitle);
    const peerList = document.createElement("div");
    peerList.className = "peer-list";
    peersSection.appendChild(peerList);
    const addPeerBtn = document.createElement("button");
    addPeerBtn.type = "button";
    addPeerBtn.className = "add-peer-btn";
    addPeerBtn.textContent = "+ Добавить ключ собеседника";
    peersSection.appendChild(addPeerBtn);
    tabPageKeys.appendChild(peersSection);

    function addPeerRow(label, value) {
      const { row } = makeKeyRow(label ?? `Собеседник ${peerList.children.length + 1}`, value ?? "", {
        removable: true,
      });
      peerList.appendChild(row);
    }
    addPeerBtn.addEventListener("click", () => addPeerRow());

    const saveBtn = document.createElement("button");
    saveBtn.type = "button";
    saveBtn.className = "btn btn-submit";
    saveBtn.style.width = "100%";
    saveBtn.style.marginTop = "12px";
    saveBtn.textContent = "Сохранить ключи";
    tabPageKeys.appendChild(saveBtn);
    const keysStatus = document.createElement("div");
    keysStatus.className = "status";
    tabPageKeys.appendChild(keysStatus);

    const backupSection = document.createElement("div");
    backupSection.className = "section";
    const backupTitle = document.createElement("div");
    backupTitle.className = "section-title";
    backupTitle.textContent = "Бэкап";
    backupSection.appendChild(backupTitle);
    const backupLabel = document.createElement("label");
    backupLabel.textContent = "Пароль резервной копии";
    backupSection.appendChild(backupLabel);
    const backupRow = document.createElement("div");
    backupRow.className = "key-row";
    const backupPass = document.createElement("input");
    backupPass.type = "password";
    backupPass.autocomplete = "off";
    backupPass.placeholder = "Для экспорта и импорта";
    backupRow.appendChild(backupPass);
    const backupToggle = document.createElement("button");
    backupToggle.type = "button";
    backupToggle.className = "icon-btn";
    backupToggle.textContent = "👁";
    backupToggle.addEventListener("click", () => {
      const show = backupPass.type === "password";
      backupPass.type = show ? "text" : "password";
      backupToggle.textContent = show ? "🙈" : "👁";
    });
    backupRow.appendChild(backupToggle);
    backupSection.appendChild(backupRow);
    const backupActions = document.createElement("div");
    backupActions.className = "actions";
    backupActions.style.justifyContent = "flex-start";
    const exportBtn = document.createElement("button");
    exportBtn.type = "button";
    exportBtn.className = "btn btn-cancel";
    exportBtn.textContent = "Экспорт";
    const importBtn = document.createElement("button");
    importBtn.type = "button";
    importBtn.className = "btn btn-cancel";
    importBtn.textContent = "Импорт";
    const importFile = document.createElement("input");
    importFile.type = "file";
    importFile.accept = ".json";
    importFile.style.display = "none";
    backupActions.append(exportBtn, importBtn, importFile);
    backupSection.appendChild(backupActions);
    const backupStatus = document.createElement("div");
    backupStatus.className = "status";
    backupSection.appendChild(backupStatus);
    tabPageKeys.appendChild(backupSection);

    const savedSection = document.createElement("div");
    savedSection.className = "section";
    const savedTitle = document.createElement("div");
    savedTitle.className = "section-title";
    savedTitle.textContent = "Сохранённые сайты";
    savedSection.appendChild(savedTitle);
    const savedList = document.createElement("div");
    savedList.className = "saved-list";
    savedSection.appendChild(savedList);
    tabPageKeys.appendChild(savedSection);

    const filesSection = document.createElement("div");
    filesSection.className = "section";
    const filesTitle = document.createElement("div");
    filesTitle.className = "section-title";
    filesTitle.textContent = "Файл";
    filesSection.appendChild(filesTitle);

    const dropzone = document.createElement("div");
    dropzone.className = "dropzone";
    dropzone.tabIndex = 0;
    dropzone.textContent = "Перетащите файл сюда или нажмите, чтобы выбрать";
    filesSection.appendChild(dropzone);
    const fileInput = document.createElement("input");
    fileInput.type = "file";
    fileInput.style.display = "none";
    filesSection.appendChild(fileInput);

    const fileChip = document.createElement("div");
    fileChip.className = "file-chip";
    fileChip.style.display = "none";
    filesSection.appendChild(fileChip);
    const fileModeHint = document.createElement("div");
    fileModeHint.className = "hint";
    filesSection.appendChild(fileModeHint);
    tabPageFiles.appendChild(filesSection);

    const filePwSection = document.createElement("div");
    filePwSection.className = "section";
    const filePwTitle = document.createElement("div");
    filePwTitle.className = "section-title";
    filePwTitle.textContent = "Пароль";
    filePwSection.appendChild(filePwTitle);

    const pwToggle = document.createElement("div");
    pwToggle.className = "toggle-group";
    const pwCustomBtn = document.createElement("button");
    pwCustomBtn.type = "button";
    pwCustomBtn.className = "toggle-btn active";
    pwCustomBtn.textContent = "Свой пароль";
    const pwSiteBtn = document.createElement("button");
    pwSiteBtn.type = "button";
    pwSiteBtn.className = "toggle-btn";
    pwSiteBtn.textContent = "Ключ с сайта";
    pwToggle.append(pwCustomBtn, pwSiteBtn);
    filePwSection.appendChild(pwToggle);

    const { row: customPwRow, keyInput: customPwInput } = makeKeyRow(undefined, "", { removable: false });
    customPwInput.placeholder = "Пароль для файла";
    filePwSection.appendChild(customPwRow);

    const sitePwWrap = document.createElement("div");
    sitePwWrap.style.display = "none";
    const sitePwSelect = document.createElement("select");
    sitePwWrap.appendChild(sitePwSelect);
    const sitePwHint = document.createElement("div");
    sitePwHint.className = "hint";
    sitePwWrap.appendChild(sitePwHint);
    filePwSection.appendChild(sitePwWrap);
    tabPageFiles.appendChild(filePwSection);

    pwCustomBtn.addEventListener("click", () => {
      pwCustomBtn.classList.add("active");
      pwSiteBtn.classList.remove("active");
      customPwRow.style.display = "";
      sitePwWrap.style.display = "none";
    });
    pwSiteBtn.addEventListener("click", () => {
      pwSiteBtn.classList.add("active");
      pwCustomBtn.classList.remove("active");
      customPwRow.style.display = "none";
      sitePwWrap.style.display = "";
      refreshFileKeyOptions().catch(() => {});
    });

    const fileActionBtn = document.createElement("button");
    fileActionBtn.type = "button";
    fileActionBtn.className = "btn btn-submit";
    fileActionBtn.style.width = "100%";
    fileActionBtn.style.marginTop = "12px";
    fileActionBtn.textContent = "Зашифровать и скачать";
    fileActionBtn.disabled = true;
    tabPageFiles.appendChild(fileActionBtn);
    const fileStatus = document.createElement("div");
    fileStatus.className = "status";
    tabPageFiles.appendChild(fileStatus);

    activateTab(initialTab === "files" ? "files" : "keys");

    backdrop.appendChild(modal);
    shadow.appendChild(backdrop);
    document.documentElement.appendChild(host);
    backdrop.addEventListener("mousedown", (e) => { if (e.target === backdrop) closeSettings(); });
    _settingsState = { host, activateTab };

    async function refreshSavedList() {
      const all = await getAllUrlKeys();
      savedList.replaceChildren();
      Object.keys(all).sort().forEach((url) => {
        const item = document.createElement("div");
        item.className = "saved-item";
        const span = document.createElement("span");
        span.textContent = url;
        const del = document.createElement("button");
        del.type = "button";
        del.className = "btn btn-danger";
        del.textContent = "Удалить";
        del.addEventListener("click", async () => {
          const current = await getAllUrlKeys();
          delete current[url];
          await saveAllUrlKeys(current);
          refreshSavedList();
          if (normalizeUrlPattern(urlInput.value) === url) loadKeysIntoForm(url);
        });
        item.append(span, del);
        savedList.appendChild(item);
      });
    }

    async function loadKeysIntoForm(urlPattern) {
      const all = await getAllUrlKeys();
      const record = all[urlPattern];
      myRow.keyInput.value = record?.myKey || "";
      peerList.replaceChildren();
      if (record?.peerKeys && Object.keys(record.peerKeys).length) {
        for (const [label, key] of Object.entries(record.peerKeys)) addPeerRow(label, key);
      } else {
        addPeerRow();
      }
    }

    let selectedFile = null;
    let selectedFileBytes = null;
    let fileMode = "encrypt";

    async function refreshFileKeyOptions() {
      const urlPattern = normalizeUrlPattern(urlInput.value);
      sitePwSelect.replaceChildren();
      if (!urlPattern) {
        sitePwHint.textContent = "Сначала укажите корректный сайт во вкладке «Ключи».";
        return;
      }
      const all = await getAllUrlKeys();
      const record = all[urlPattern];
      if (!record) {
        sitePwHint.textContent = `Для сайта ${urlPattern} ещё нет сохранённых ключей — сохраните их во вкладке «Ключи» или используйте свой пароль.`;
        return;
      }
      const myOpt = document.createElement("option");
      myOpt.value = record.myKey;
      myOpt.textContent = "Мой ключ";
      sitePwSelect.appendChild(myOpt);
      for (const [label, key] of Object.entries(record.peerKeys || {})) {
        const opt = document.createElement("option");
        opt.value = key;
        opt.textContent = label;
        sitePwSelect.appendChild(opt);
      }
      sitePwHint.textContent = `Ключи сайта ${urlPattern}.`;
    }

    async function handlePickedFile(file) {
      if (!file) return;
      fileStatus.textContent = "";
      fileStatus.className = "status";
      fileActionBtn.disabled = true;
      selectedFile = null;
      selectedFileBytes = null;
      fileChip.style.display = "";
      fileChip.textContent = `${file.name} · ${formatFileSize(file.size)}`;

      if (file.size > WEBCRYPTO_MAX_BYTES) {
        fileModeHint.textContent = "";
        fileStatus.textContent = fileTooLargeMessage(file.size);
        fileStatus.className = "status error";
        return;
      }

      fileModeHint.textContent = "Читаем файл…";
      let buf;
      try {
        buf = new Uint8Array(await file.arrayBuffer());
      } catch (error) {
        fileStatus.textContent = "Не удалось прочитать файл: " + (error?.message || String(error));
        fileStatus.className = "status error";
        fileModeHint.textContent = "";
        return;
      }
      selectedFile = file;
      selectedFileBytes = buf;
      const isEncrypted = looksLikeEncryptedFileContainer(buf);
      fileMode = isEncrypted ? "decrypt" : "encrypt";
      fileActionBtn.textContent = isEncrypted ? "Расшифровать и скачать" : "Зашифровать и скачать";
      let hint = isEncrypted
        ? "Похоже, этот файл уже зашифрован MystoraEncrypt — будет выполнена расшифровка."
        : "Обычный файл — будет выполнено шифрование.";
      if (buf.length > 250 * 1024 * 1024) {
        hint += " Файл большого размера — обработка может занять время и потребовать много памяти браузера.";
      }
      fileModeHint.textContent = hint;
      fileActionBtn.disabled = false;
    }

    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
    });
    fileInput.addEventListener("change", (e) => {
      handlePickedFile(e.target.files[0]);
      e.target.value = "";
    });
    dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("drag"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag");
      const file = e.dataTransfer?.files?.[0];
      if (file) handlePickedFile(file);
    });

    fileActionBtn.addEventListener("click", async () => {
      if (!selectedFile || !selectedFileBytes) return;
      const password = pwSiteBtn.classList.contains("active") ? sitePwSelect.value : customPwInput.value;
      if (!password) {
        fileStatus.textContent = "Укажите пароль.";
        fileStatus.className = "status error";
        return;
      }
      const originalLabel = fileActionBtn.textContent;
      fileActionBtn.disabled = true;
      fileActionBtn.textContent = fileMode === "encrypt" ? "Шифруем…" : "Расшифровываем…";
      fileStatus.textContent = "";
      fileStatus.className = "status";
      try {
        if (fileMode === "encrypt") {
          const meta = {
            name: selectedFile.name,
            type: selectedFile.type || "application/octet-stream",
            size: selectedFileBytes.length,
          };
          const container = await encryptFileBuffer(selectedFileBytes, meta, password);
          downloadBytes(container, selectedFile.name + FILE_EXTENSION, "application/octet-stream");
          fileStatus.textContent = "Файл зашифрован и скачан.";
          fileStatus.className = "status ok";
        } else {
          const { meta, data } = await decryptFileContainer(selectedFileBytes, password);
          downloadBytes(data, meta?.name || "decrypted-file", meta?.type || "application/octet-stream");
          fileStatus.textContent = "Файл расшифрован и скачан.";
          fileStatus.className = "status ok";
        }
      } catch (error) {
        fileStatus.textContent = _cryptoBroken ? cryptoBlockedMessage(error) : (error?.message || String(error));
        fileStatus.className = "status error";
      } finally {
        fileActionBtn.disabled = false;
        fileActionBtn.textContent = originalLabel;
      }
    });

    urlInput.addEventListener("change", () => {
      const p = normalizeUrlPattern(urlInput.value);
      if (p) loadKeysIntoForm(p);
      refreshFileKeyOptions().catch(() => {});
    });

    saveBtn.addEventListener("click", async () => {
      const urlPattern = normalizeUrlPattern(urlInput.value);
      if (!urlPattern) { keysStatus.textContent = "Укажите корректный URL сайта (http:// или https://)."; keysStatus.className = "status error"; return; }
      const myKey = myRow.keyInput.value;
      if (!myKey) { keysStatus.textContent = "Введите свой ключ."; keysStatus.className = "status error"; return; }

      const peerKeys = {};
      let peerIndex = 1;
      let filledRowCount = 0;
      for (const row of peerList.children) {
        const inputs = row.querySelectorAll("input");
        const label = (inputs[0]?.value || `Собеседник ${peerIndex}`).trim();
        const key = inputs[1]?.value || "";
        if (key) {
          filledRowCount++;
          peerKeys[label || `Собеседник ${peerIndex}`] = key;
          peerIndex++;
        }
      }

      if (Object.keys(peerKeys).length === 0) {
        keysStatus.textContent = "Добавьте хотя бы один ключ собеседника.";
        keysStatus.className = "status error";
        return;
      }
      if (Object.keys(peerKeys).length < filledRowCount) {
        keysStatus.textContent = "У нескольких собеседников совпадает имя. Задайте разные имена и сохраните снова.";
        keysStatus.className = "status error";
        return;
      }

      const all = await getAllUrlKeys();
      all[urlPattern] = { myKey, peerKeys };
      await saveAllUrlKeys(all);
      keysStatus.textContent = "Ключи сохранены!";
      keysStatus.className = "status ok";
      refreshSavedList();
      _observerStarted = false;
      maybeStartObserver().catch(() => {});
    });

    exportBtn.addEventListener("click", async () => {
      const passphrase = backupPass.value;
      if (!passphrase || passphrase.length < 8) {
        backupStatus.textContent = "Введите пароль резервной копии (минимум 8 символов).";
        backupStatus.className = "status error";
        return;
      }
      const all = await getAllUrlKeys();
      if (Object.keys(all).length === 0) {
        backupStatus.textContent = "Нет ключей для экспорта.";
        backupStatus.className = "status error";
        return;
      }
      try {
        const encrypted = await encryptBackup(all, passphrase);
        const blob = new Blob([JSON.stringify(encrypted, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "mystora-encrypt-backup.json";
        a.click();
        URL.revokeObjectURL(url);
        backupStatus.textContent = "Зашифрованный бэкап экспортирован.";
        backupStatus.className = "status ok";
      } catch (error) {
        backupStatus.textContent = "Не удалось экспортировать: " + (error?.message || String(error));
        backupStatus.className = "status error";
      }
    });

    importBtn.addEventListener("click", () => importFile.click());
    importFile.addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (file.size > 2 * 1024 * 1024) {
        backupStatus.textContent = "Файл слишком большой для резервной копии ключей (максимум 2 МБ).";
        backupStatus.className = "status error";
        e.target.value = "";
        return;
      }
      const reader = new FileReader();
      reader.onload = async () => {
        try {
          const parsed = JSON.parse(reader.result);
          let payload = parsed;
          if (parsed?.type === "MystoraEncrypt.encryptedBackup.v1") {
            const passphrase = backupPass.value;
            if (!passphrase) { backupStatus.textContent = "Введите пароль резервной копии перед импортом."; backupStatus.className = "status error"; return; }
            payload = await decryptBackup(parsed, passphrase);
          }
          const imported = sanitizeUrlKeys(payload.urlKeys || payload);
          if (!imported || Object.keys(imported).length === 0) {
            backupStatus.textContent = "В файле нет корректных ключей.";
            backupStatus.className = "status error";
            return;
          }
          const current = await getAllUrlKeys();
          await saveAllUrlKeys({ ...current, ...imported });
          backupStatus.textContent = `Импортировано записей: ${Object.keys(imported).length}.`;
          backupStatus.className = "status ok";
          refreshSavedList();
        } catch (error) {
          backupStatus.textContent = "Не удалось прочитать файл или пароль неверный.";
          backupStatus.className = "status error";
        }
      };
      reader.readAsText(file);
      e.target.value = "";
    });

    await loadKeysIntoForm(normalizeUrlPattern(urlInput.value));
    await refreshSavedList();
  }

  const BACKUP_TYPE = "MystoraEncrypt.encryptedBackup.v1";
  const BACKUP_KDF_ITERATIONS = 210000;

  async function encryptBackup(urlKeys, passphrase) {
    const saltB64 = uint8ToBase64(crypto.getRandomValues(new Uint8Array(16)));
    const payload = { version: 1, exportedAt: new Date().toISOString(), urlKeys };
    const enc = new TextEncoder();
    const key = await getCachedKey(passphrase, saltB64, "encrypt", BACKUP_KDF_ITERATIONS);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(payload))));
    return {
      type: BACKUP_TYPE,
      kdf: { name: "PBKDF2-HMAC-SHA-256", iterations: BACKUP_KDF_ITERATIONS, salt: saltB64 },
      cipher: { name: "AES-GCM", iv: uint8ToBase64(iv) },
      data: uint8ToBase64(ciphertext),
    };
  }

  async function decryptBackup(backup, passphrase) {
    if (!backup || backup.type !== BACKUP_TYPE) {
      throw new Error("Некорректный формат резервной копии.");
    }
    const iterations = backup.kdf?.iterations || BACKUP_KDF_ITERATIONS;
    const dec = new TextDecoder();
    const key = await getCachedKey(passphrase, backup.kdf.salt, "decrypt", iterations);
    let plaintextBuf;
    try {
      plaintextBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64ToUint8(backup.cipher.iv) },
        key,
        base64ToUint8(backup.data)
      );
    } catch {
      throw new Error("Не удалось расшифровать — неверный пароль или повреждённый файл.");
    }
    return JSON.parse(dec.decode(plaintextBuf));
  }

  const FILE_MAGIC_STR = "MYSTFILE";
  const FILE_FORMAT_VERSION = 1;
  const FILE_HEADER_LEN = FILE_MAGIC_STR.length + 1 + 16 + 12;
  const FILE_KDF_ITERATIONS = 210000;
  const FILE_EXTENSION = ".mystora";
  const WEBCRYPTO_MAX_BYTES = 2 * 1000 * 1000 * 1000;

  function fileTooLargeMessage(bytesLength) {
    return (
      `Файл слишком большой (${formatFileSize(bytesLength)}) для шифрования в браузере: ` +
      `Web Crypto API (встроенное шифрование браузера) не поддерживает обработку файлов ` +
      `больше 2 ГБ за один раз.`
    );
  }

  function isWebCryptoSizeLimitError(error) {
    const msg = String(error?.message || error || "");
    return /larger than.*\d+\s*GB|2\s*GB|exceeds?.*(length|size)|QuotaExceededError/i.test(msg);
  }

  function concatBytes(parts) {
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  function looksLikeEncryptedFileContainer(bytes) {
    if (!bytes || bytes.length < FILE_HEADER_LEN) return false;
    for (let i = 0; i < FILE_MAGIC_STR.length; i++) {
      if (bytes[i] !== FILE_MAGIC_STR.charCodeAt(i)) return false;
    }
    return bytes[FILE_MAGIC_STR.length] === FILE_FORMAT_VERSION;
  }

  async function encryptFileBuffer(fileBytes, meta, password) {
    if (fileBytes.length > WEBCRYPTO_MAX_BYTES) throw new Error(fileTooLargeMessage(fileBytes.length));

    const enc = new TextEncoder();
    const metaBytes = enc.encode(JSON.stringify(meta));
    const metaLenBytes = new Uint8Array(4);
    new DataView(metaLenBytes.buffer).setUint32(0, metaBytes.length, true);
    const plaintext = concatBytes([metaLenBytes, metaBytes, fileBytes]);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await getCachedKey(password, uint8ToBase64(salt), "encrypt", FILE_KDF_ITERATIONS);
    let ciphertext;
    try {
      ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
    } catch (error) {
      if (isWebCryptoSizeLimitError(error)) throw new Error(fileTooLargeMessage(plaintext.length));
      throw error;
    }

    return concatBytes([enc.encode(FILE_MAGIC_STR), new Uint8Array([FILE_FORMAT_VERSION]), salt, iv, ciphertext]);
  }

  async function decryptFileContainer(containerBytes, password) {
    if (!looksLikeEncryptedFileContainer(containerBytes)) {
      throw new Error("Это не файл, зашифрованный MystoraEncrypt (не совпадает формат контейнера).");
    }
    if (containerBytes.length > WEBCRYPTO_MAX_BYTES) throw new Error(fileTooLargeMessage(containerBytes.length));
    let offset = FILE_MAGIC_STR.length + 1;
    const salt = containerBytes.subarray(offset, offset + 16); offset += 16;
    const iv = containerBytes.subarray(offset, offset + 12); offset += 12;
    const ciphertext = containerBytes.subarray(offset);

    const key = await getCachedKey(password, uint8ToBase64(salt), "decrypt", FILE_KDF_ITERATIONS);
    let plaintextBuf;
    try {
      plaintextBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    } catch (error) {
      if (isWebCryptoSizeLimitError(error)) throw new Error(fileTooLargeMessage(containerBytes.length));
      throw new Error("Не удалось расшифровать — неверный пароль или повреждённый файл.");
    }
    const plaintext = new Uint8Array(plaintextBuf);
    if (plaintext.length < 4) throw new Error("Повреждённый файл: слишком короткое содержимое.");
    const metaLen = new DataView(plaintext.buffer, plaintext.byteOffset, 4).getUint32(0, true);
    if (metaLen < 0 || 4 + metaLen > plaintext.length) {
      throw new Error("Повреждённый файл: некорректные метаданные.");
    }
    let meta;
    try {
      meta = JSON.parse(new TextDecoder().decode(plaintext.subarray(4, 4 + metaLen)));
    } catch {
      throw new Error("Повреждённый файл: не удалось прочитать метаданные.");
    }
    return { meta, data: plaintext.subarray(4 + metaLen) };
  }

  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + " Б";
    const units = ["КБ", "МБ", "ГБ", "ТБ"];
    let value = bytes / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
    return (value >= 10 ? Math.round(value) : Math.round(value * 10) / 10) + " " + units[i];
  }

  function downloadBytes(bytes, filename, mimeType) {
    const blob = new Blob([bytes], { type: mimeType || "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  let _panelEntrySeq = 0;
  const _panelEntries = [];
  let _panelUnread = 0;
  let _panelState = null;
  const _panelBadgeEls = [];

  function updatePanelBadge() {
    for (const el of _panelBadgeEls) {
      el.textContent = _panelUnread > 99 ? "99+" : String(_panelUnread);
      el.classList.toggle("show", _panelUnread > 0);
    }
  }

  function senderDisplayName(sender) {
    if (sender === "__ME__") return null;
    return sender || "Собеседник";
  }

  function renderPanelEntries(listEl) {
    listEl.textContent = "";
    if (!_panelEntries.length) {
      const empty = document.createElement("div");
      empty.className = "hint";
      empty.textContent = "Пока нет расшифрованных сообщений в этой сессии.";
      listEl.appendChild(empty);
      return;
    }
    let lastSender = undefined;
    for (const entry of _panelEntries) {
      const isMine = entry.sender === "__ME__";
      const row = document.createElement("div");
      row.className = "msg-row " + (isMine ? "mine" : "theirs");
      row.dataset.entryId = entry.id;

      const col = document.createElement("div");
      col.className = "msg-col";

      const label = senderDisplayName(entry.sender);
      if (label && lastSender !== entry.sender) {
        const nameEl = document.createElement("div");
        nameEl.className = "msg-sender";
        nameEl.textContent = label;
        col.appendChild(nameEl);
      }

      const bubbleWrap = document.createElement("div");
      bubbleWrap.className = "msg-bubble-wrap";
      const bubble = document.createElement("div");
      bubble.className = "msg-bubble " + (isMine ? "mine" : "theirs");
      bubble.textContent = entry.text;
      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "msg-copy-btn";
      copyBtn.title = "Скопировать текст";
      copyBtn.textContent = "⧉";
      copyBtn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(entry.text);
          copyBtn.textContent = "✓";
          setTimeout(() => { copyBtn.textContent = "⧉"; }, 1200);
        } catch {}
      });
      bubbleWrap.append(bubble, copyBtn);
      col.appendChild(bubbleWrap);
      row.appendChild(col);
      listEl.appendChild(row);
      lastSender = entry.sender;
    }
    listEl.scrollTop = listEl.scrollHeight;
  }

  function highlightPanelEntry(id) {
    if (!_panelState || !id) return;
    const el = _panelState.listEl.querySelector(`[data-entry-id="${CSS.escape(id)}"]`);
    if (!el) return;
    el.scrollIntoView({ block: "center" });
    el.classList.add("highlight");
    setTimeout(() => el.classList.remove("highlight"), 1600);
  }

  const PANEL_HOST_ID = "mystora-encrypt-panel-host";

  function closeDecryptedPanel() {
    if (!_panelState) return;
    _panelState.host.remove();
    _panelState = null;
  }

  function openDecryptedPanel(highlightId) {
    _panelUnread = 0;
    updatePanelBadge();

    if (_panelState) {
      renderPanelEntries(_panelState.listEl);
      if (highlightId) highlightPanelEntry(highlightId);
      return;
    }

    const host = document.createElement("div");
    host.id = PANEL_HOST_ID;
    const shadow = host.attachShadow({ mode: (typeof window !== "undefined" && window.__MYSTORA_TEST__) ? "open" : "closed" });
    const style = document.createElement("style");
    style.textContent = panelStyles() + `
      .modal.messenger { display: flex; flex-direction: column; }
      .panel-list {
        display: flex; flex-direction: column; gap: 2px; margin-top: 0;
        max-height: 55vh; overflow-y: auto; padding: 4px 14px 4px 6px;
      }
      .msg-row { display: flex; margin: 3px 0; }
      .msg-row.mine { justify-content: flex-end; }
      .msg-row.theirs { justify-content: flex-start; }
      .msg-col { display: flex; flex-direction: column; max-width: 78%; }
      .msg-row.mine .msg-col { align-items: flex-end; }
      .msg-row.theirs .msg-col { align-items: flex-start; }
      .msg-sender { font-size: 10.5px; font-weight: 700; color: #2db8a8; margin: 6px 2px 2px; }
      .msg-bubble-wrap { display: flex; align-items: flex-end; gap: 4px; }
      .msg-row.mine .msg-bubble-wrap { flex-direction: row-reverse; }
      .msg-bubble {
        padding: 7px 11px; border-radius: 14px; font-size: 13px; line-height: 1.35;
        white-space: pre-wrap; word-break: break-word;
        border: 1.5px solid transparent; box-shadow: 0 1px 2px rgba(0,0,0,0.3);
      }
      .msg-bubble.mine { background: #2db8a8; color: #06201d; border-color: #14544c; border-bottom-right-radius: 4px; }
      .msg-bubble.theirs { background: #24343c; color: #e8f0f2; border-color: #45606c; border-bottom-left-radius: 4px; }
      @media (prefers-color-scheme: light) {
        .msg-bubble.theirs { background: #e8eef0; color: #12212a; border-color: #b7c8cf; }
        .msg-bubble.mine { border-color: #16665c; }
      }
      .msg-row.highlight .msg-bubble { outline: 2px solid #ffcb47; outline-offset: 1px; }
      .msg-copy-btn {
        opacity: 0; flex: 0 0 auto; width: 26px; height: 26px; border-radius: 7px; border: 0;
        background: transparent; color: inherit; cursor: pointer; font-size: 14px;
        display: grid; place-items: center; transition: opacity 0.12s ease, background 0.12s ease;
      }
      .msg-row:hover .msg-copy-btn { opacity: 0.65; }
      .msg-copy-btn:hover { opacity: 1 !important; background: rgba(255,255,255,0.1); }
      /* На сенсорных экранах наведения не существует — кнопка должна быть
         видна сразу и быть достаточно крупной для пальца (рекомендация
         Apple/Google — цель нажатия не меньше 44px), а не появляться по hover. */
      @media (pointer: coarse) {
        .msg-copy-btn { opacity: 0.6 !important; width: 44px; height: 44px; font-size: 21px; border-radius: 10px; }
        .msg-copy-btn:active { opacity: 1 !important; background: rgba(255,255,255,0.14); }
      }
      .panel-divider { height: 1px; border: 0; background: #30414a; margin: 12px 0; }
      @media (prefers-color-scheme: light) { .panel-divider { background: #d7e1e6; } }
      .panel-bottom-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 0; }
      .panel-clear-btn { margin-top: 0; }
    `;
    shadow.appendChild(style);

    const backdrop = document.createElement("div");
    backdrop.className = "backdrop";
    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) closeDecryptedPanel(); });

    const modal = document.createElement("div");
    modal.className = "modal wide messenger";

    const title = document.createElement("div");
    title.className = "title";
    const titleSpan = document.createElement("span");
    titleSpan.textContent = "📥 Расшифрованные сообщения";
    const closeX = document.createElement("button");
    closeX.className = "close-x";
    closeX.type = "button";
    closeX.textContent = "✕";
    closeX.addEventListener("click", () => closeDecryptedPanel());
    title.append(titleSpan, closeX);

    const hint = document.createElement("div");
    hint.className = "hint";
    hint.textContent = "Список сообщений хранится в памяти вкладки и очищается при перезагрузке страницы.";

    const listEl = document.createElement("div");
    listEl.className = "panel-list";

    const refreshBtn = document.createElement("button");
    refreshBtn.type = "button";
    refreshBtn.className = "btn btn-cancel panel-clear-btn";
    refreshBtn.textContent = "Обновить";
    refreshBtn.title = "Полностью пересканировать текущую страницу";
    refreshBtn.addEventListener("click", () => {
      resetPanelState();
      processMessages().catch(() => {});
    });

    const bottomActions = document.createElement("div");
    bottomActions.className = "panel-bottom-actions";
    bottomActions.append(refreshBtn);

    const dividerTop = document.createElement("hr");
    dividerTop.className = "panel-divider";
    const dividerBottom = document.createElement("hr");
    dividerBottom.className = "panel-divider";

    modal.append(title, hint, dividerTop, listEl, dividerBottom, bottomActions);
    backdrop.appendChild(modal);
    shadow.appendChild(backdrop);
    document.documentElement.appendChild(host);

    _panelState = { host, shadow, listEl };
    renderPanelEntries(listEl);
    if (highlightId) highlightPanelEntry(highlightId);
  }

  const TOOLBAR_POS_KEY = "mystoraToolbarPos";

  const TOOLBAR_HOST_ID = "mystora-toolbar-host";

  function createToolbar() {
    if (document.getElementById(TOOLBAR_HOST_ID)) return;
    const host = document.createElement("div");
    host.id = TOOLBAR_HOST_ID;
    const shadow = host.attachShadow({ mode: (typeof window !== "undefined" && window.__MYSTORA_TEST__) ? "open" : "closed" });
    const style = document.createElement("style");
    style.textContent = `
      .wrap {
        position: fixed; left: 0; top: 0; z-index: 2147483000;
        touch-action: none;
      }
      .bar {
        display: flex; gap: 6px; align-items: center;
        background: rgba(22,33,39,0.92); border: 1px solid #30414a; border-radius: 999px;
        padding: 6px; box-shadow: 0 10px 30px rgba(0,0,0,0.35);
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
        opacity: 0.55; transition: opacity 0.15s ease;
        cursor: grab;
      }
      .bar:hover, .bar.dragging { opacity: 1; }
      @media (prefers-color-scheme: light) { .bar { background: rgba(255,255,255,0.95); border-color: #d7e1e6; } }
      button {
        width: 34px; height: 34px; border-radius: 999px; border: 0; cursor: pointer;
        display: grid; place-items: center; font-size: 15px; background: transparent; color: #e8f0f2;
        touch-action: none;
      }
      @media (prefers-color-scheme: light) { button { color: #12212a; } }
      button:hover { background: rgba(255,255,255,0.12); }
      /* На сенсорных экранах цель нажатия крупнее (рекомендация Apple/Google — не меньше 44px) */
      @media (pointer: coarse) {
        button { width: 44px; height: 44px; font-size: 19px; }
        .bar { padding: 8px; gap: 8px; opacity: 0.7; }
      }
      .panel-btn-wrap { position: relative; }
      .panel-count-badge {
        display: none; position: absolute; top: -2px; right: -2px; min-width: 15px; height: 15px;
        padding: 0 3px; border-radius: 999px; background: #e0554a; color: #fff;
        font-size: 9px; font-weight: 700; line-height: 15px; text-align: center;
        pointer-events: none; font-family: inherit;
      }
      .panel-count-badge.show { display: block; }
      .toast {
        position: fixed; z-index: 2147483000;
        max-width: 280px; padding: 8px 12px; border-radius: 8px; font-size: 12px;
        background: rgba(22,33,39,0.95); color: #e8f0f2; border: 1px solid #30414a;
        box-shadow: 0 10px 30px rgba(0,0,0,0.35); opacity: 0; transform: translateY(6px);
        transition: opacity 0.15s ease, transform 0.15s ease;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
        pointer-events: none;
      }
      .toast.show { opacity: 1; transform: translateY(0); }
      .toast.error { border-color: #76413b; color: #f29b91; }
      @media (prefers-color-scheme: light) { .toast { background: rgba(255,255,255,0.97); color: #12212a; } }
    `;
    shadow.appendChild(style);

    const wrap = document.createElement("div");
    wrap.className = "wrap";
    const bar = document.createElement("div");
    bar.className = "bar";
    const encBtn = document.createElement("button");
    encBtn.type = "button";
    encBtn.title = "Зашифровать";
    encBtn.textContent = "🔒";

    const decBtn = document.createElement("button");
    decBtn.type = "button";
    decBtn.title = "Расшифровать поле ввода / открыть расшифрованные сообщения";
    decBtn.classList.add("panel-btn-wrap");
    const decIcon = document.createElement("span");
    decIcon.textContent = "🔓";
    decIcon.style.pointerEvents = "none";
    const decCountBadge = document.createElement("span");
    decCountBadge.className = "panel-count-badge";
    decBtn.append(decIcon, decCountBadge);
    _panelBadgeEls.push(decCountBadge);
    updatePanelBadge();

    const settingsBtn = document.createElement("button");
    settingsBtn.type = "button";
    settingsBtn.title = "Настройки ключей";
    settingsBtn.textContent = "⚙";
    bar.append(encBtn, decBtn, settingsBtn);
    wrap.appendChild(bar);
    shadow.appendChild(wrap);

    const toast = document.createElement("div");
    toast.className = "toast";
    shadow.appendChild(toast);
    document.documentElement.appendChild(host);

    const isCoarsePointer = !!(window.matchMedia && window.matchMedia("(pointer: coarse)").matches);
    const EDGE_MARGIN = isCoarsePointer ? 18 : 14;

    function barSize() {
      const r = bar.getBoundingClientRect();
      return { w: r.width || (isCoarsePointer ? 160 : 130), h: r.height || (isCoarsePointer ? 60 : 46) };
    }
    function clampToViewport(pos) {
      const { w, h } = barSize();
      const maxLeft = Math.max(EDGE_MARGIN, window.innerWidth - w - EDGE_MARGIN);
      const maxTop = Math.max(EDGE_MARGIN, window.innerHeight - h - EDGE_MARGIN);
      return {
        left: Math.min(Math.max(EDGE_MARGIN, pos.left), maxLeft),
        top: Math.min(Math.max(EDGE_MARGIN, pos.top), maxTop),
      };
    }
    function defaultPosition() {
      const { w, h } = barSize();
      if (isCoarsePointer) {
        return { left: window.innerWidth - w - EDGE_MARGIN, top: Math.round(window.innerHeight / 2 - h / 2) };
      }
      return { left: window.innerWidth - w - EDGE_MARGIN, top: window.innerHeight - h - EDGE_MARGIN };
    }
    let currentPos = { left: EDGE_MARGIN, top: EDGE_MARGIN };
    function applyPosition(pos) {
      currentPos = pos;
      wrap.style.left = pos.left + "px";
      wrap.style.top = pos.top + "px";
    }

    (async () => {
      let saved = null;
      try {
        const raw = await gmGet(TOOLBAR_POS_KEY, null);
        if (raw) saved = JSON.parse(raw);
      } catch {}
      applyPosition(clampToViewport(saved || defaultPosition()));
    })();

    window.addEventListener("resize", () => {
      applyPosition(clampToViewport(currentPos));
    });

    let drag = null;
    let justDragged = false;
    bar.addEventListener("pointerdown", (e) => {
      drag = {
        pointerId: e.pointerId,
        startX: e.clientX,
        startY: e.clientY,
        origLeft: currentPos.left,
        origTop: currentPos.top,
        moved: false,
      };
    });
    bar.addEventListener("pointermove", (e) => {
      if (!drag || drag.pointerId !== e.pointerId) return;
      const dx = e.clientX - drag.startX;
      const dy = e.clientY - drag.startY;
      if (!drag.moved && Math.hypot(dx, dy) > 6) {
        drag.moved = true;
        bar.classList.add("dragging");
        try { bar.setPointerCapture(e.pointerId); } catch {}
      }
      if (drag.moved) {
        applyPosition(clampToViewport({ left: drag.origLeft + dx, top: drag.origTop + dy }));
      }
    });
    async function endDrag(e) {
      if (!drag || drag.pointerId !== e.pointerId) return;
      bar.classList.remove("dragging");
      if (drag.moved) {
        justDragged = true;
        setTimeout(() => { justDragged = false; }, 0);
        try { bar.releasePointerCapture(e.pointerId); } catch {}
        try {
          await gmSet(TOOLBAR_POS_KEY, JSON.stringify(currentPos));
        } catch {}
      }
      drag = null;
    }
    bar.addEventListener("pointerup", endDrag);
    bar.addEventListener("pointercancel", endDrag);
    bar.addEventListener(
      "click",
      (e) => {
        if (justDragged) {
          e.preventDefault();
          e.stopPropagation();
        }
      },
      true
    );

    let toastTimer = null;
    function positionToast() {
      const barRect = bar.getBoundingClientRect();
      const gap = 8;
      const toastRect = toast.getBoundingClientRect();
      const toastWidth = toastRect.width || 200;
      const toastHeight = toastRect.height || 34;

      const spaceRight = window.innerWidth - barRect.right;
      const spaceLeft = barRect.left;
      const anchorRight = spaceRight <= spaceLeft;
      let left = anchorRight ? barRect.right - toastWidth : barRect.left;
      left = Math.min(Math.max(4, left), window.innerWidth - toastWidth - 4);

      const spaceAbove = barRect.top;
      const spaceBelow = window.innerHeight - barRect.bottom;
      let top;
      if (spaceAbove >= toastHeight + gap) {
        top = barRect.top - toastHeight - gap;
      } else if (spaceBelow >= toastHeight + gap) {
        top = barRect.bottom + gap;
      } else {
        top = spaceAbove > spaceBelow ? barRect.top - toastHeight - gap : barRect.bottom + gap;
      }
      top = Math.min(Math.max(4, top), window.innerHeight - toastHeight - 4);

      toast.style.left = left + "px";
      toast.style.top = top + "px";
    }
    function showToast(message, isError) {
      toast.textContent = message;
      toast.className = "toast" + (isError ? " error" : "");
      positionToast();
      toast.classList.add("show");
      if (toastTimer) clearTimeout(toastTimer);
      toastTimer = setTimeout(() => { toast.className = "toast"; }, 3500);
    }
    _showToast = showToast;
    try {
      if (typeof window !== "undefined" && window.__MYSTORA_TEST__) {
        window.__mystoraTestShowToast = showToast;
      }
    } catch {}

    encBtn.addEventListener("click", async () => {
      const res = await actionEncrypt();
      if (res.message) showToast(res.message, !res.success);
    });
    decBtn.addEventListener("click", async () => {
      const res = await decryptButtonAction();
      if (res.message) showToast(res.message, !res.success);
    });
    settingsBtn.addEventListener("click", () => openSettingsPanel());
  }

  try {
    if (typeof GM_registerMenuCommand === "function") {
      GM_registerMenuCommand("⚙ MystoraEncrypt: ключи", () => openSettingsPanel());
      GM_registerMenuCommand("📁 MystoraEncrypt: файлы", () => openSettingsPanel("files"));
      GM_registerMenuCommand("🔒 Зашифровать", () => actionEncrypt());
      GM_registerMenuCommand("🔓 Расшифровать / открыть сообщения", () => decryptButtonAction());
      GM_registerMenuCommand("🩺 MystoraEncrypt: диагностика (в консоль)", () => runDiagnostics());
    }
  } catch {}

  try {
    if (typeof window !== "undefined" && window.__MYSTORA_TEST__) {
      window.__mystoraTestActionEncrypt = actionEncrypt;
      window.__mystoraTestActionDecrypt = decryptButtonAction;
      window.__mystoraTestOpenSettings = openSettingsPanel;
      window.__mystoraTestNormalizeKeyRecord = normalizeKeyRecord;
      window.__mystoraTestGetAllUrlKeys = getAllUrlKeys;
      window.__mystoraTestEncryptWithSalt = encryptTextWithSalt;
      window.__mystoraTestDecryptRaw = decryptTextWithSalt;
      window.__mystoraTestOpenDecryptedPanel = openDecryptedPanel;
      window.__mystoraTestGetPanelEntries = () => _panelEntries.slice();
      window.__mystoraTestGetCipherToEntryId = () => new Map(_cipherToEntryId);
      window.__mystoraTestGetPendingOutgoing = () => new Map(_pendingOutgoing);
      window.__mystoraTestDetectContentFeedReplaced = detectContentFeedReplaced;
      window.__mystoraTestFilterToTrustedFeed = filterToTrustedFeed;
      window.__mystoraTestResetPanelState = resetPanelState;
      window.__mystoraTestEncryptFileBuffer = encryptFileBuffer;
      window.__mystoraTestDecryptFileContainer = decryptFileContainer;
      window.__mystoraTestLooksLikeEncryptedFileContainer = looksLikeEncryptedFileContainer;
      window.__mystoraTestStableEntryId = stableEntryId;
      window.__mystoraTestRecordDecryptedMessage = recordDecryptedMessage;
      window.__mystoraTestUpdateOwnEditedMessage = updateOwnEditedMessage;
      window.__mystoraTestRegisterOutgoingMessage = registerOutgoingMessage;
      window.__mystoraTestProcessMessages = processMessages;
      window.__mystoraTestActionDecryptField = actionDecryptField;
      window.__mystoraTestRunDiagnostics = runDiagnostics;
      window.__mystoraTestCollectRawCandidateTextNodes = collectRawCandidateTextNodes;
    }
  } catch {}

  async function boot() {
    try {
      console.log("[MystoraEncrypt] v1.0.0 loaded on", window.location.host);
      injectPageStyles();
      createToolbar();
      if (document.body) {
        document.body.addEventListener("click", handleFeedMessageClick, true);
        document.body.addEventListener("click", handleDecryptedBadgeClick, true);
      }
      markEncryptedInFeed();
      await maybeStartObserver();
    } catch (error) {
      console.error("[MystoraEncrypt] boot error", error);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }

  setInterval(() => {
    if (_observerStarted) processMessages().catch(() => {});
    else maybeStartObserver().catch(() => {});
  }, 5000);
})();