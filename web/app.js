// Browser logic for the .ion registry.
//
// The site is fully static. GitHub supplies the login, an OAuth Worker swaps
// the temporary code for a token, and the zone repository stores every signed
// domain file. Private keys stay in localStorage and are never sent anywhere.

import {
  ISSUE_MARKER,
  decodeBase64Url,
  dumpDomainToml,
  encodeBase64Url,
  expandGithubPages,
  generateIdentity,
  identityFromSeed,
  parsePagesRepo,
  relativeName,
  secondLevel,
  signDomain,
  validateName,
  validateRecords,
  ZoneError,
  MAX_TTL,
} from "./zone.js";

const config = window.ION_CONFIG || {};
const STORAGE = {
  identity: "ion.identity.v1",
  token: "ion.token.v1",
  state: "ion.oauth.state",
};
const RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA"];
// The GitHub Pages entry is an editor preset, not a DNS type: it is expanded
// into A/AAAA or CNAME records before signing.
const PAGES_TYPE = "GITHUB_PAGES";
const RECORD_TYPE_OPTIONS = [PAGES_TYPE, ...RECORD_TYPES];
const TYPE_PLACEHOLDERS = {
  A: "192.0.2.10 (one address or several, comma separated)",
  AAAA: "2001:db8::1 (one address or several, comma separated)",
  CNAME: "target.example.com.",
  TXT: "any text value",
  MX: "mail.example.com.",
  NS: "ns1.example.com.",
  SRV: "service.example.com.",
  CAA: "letsencrypt.org",
  [PAGES_TYPE]: "owner/repository",
};
const COOLDOWN_MS = 48 * 60 * 60 * 1000;

const state = {
  token: null,
  user: null,
  identity: null,
  ledger: [],
  pending: [],
  editing: null,
  busy: false,
  ledgerPromise: null,
};

const $ = (id) => document.getElementById(id);

function zoneName() {
  return String(config.zoneName || "ion").replace(/^\.+/, "");
}

function zoneRepo() {
  return String(config.zoneRepo || "").trim();
}

function repoUrl() {
  return `https://github.com/${zoneRepo()}`;
}

function isConfigured() {
  return (
    /^[^/\s]+\/[^/\s]+$/.test(zoneRepo()) &&
    !zoneRepo().startsWith("OWNER/") &&
    typeof config.oauthClientId === "string" &&
    !config.oauthClientId.startsWith("SETUP") &&
    typeof config.oauthWorkerUrl === "string" &&
    !config.oauthWorkerUrl.includes("SETUP")
  );
}

function login() {
  return state.user ? String(state.user.login) : "";
}

function apiHeaders(token) {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

function showFlash(message, kind = "") {
  const element = $("flash");
  element.textContent = message;
  element.className = `flash${kind ? ` is-${kind}` : ""}`;
  element.hidden = false;
}

function hideFlash() {
  $("flash").hidden = true;
}

function formStatus(message, kind = "") {
  const element = $("form-status");
  element.textContent = message;
  element.className = `form-status${kind ? ` is-${kind}` : ""}`;
}

function relativeTime(value) {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) {
    return "unknown time";
  }
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 60) {
    return "just now";
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }
  return `${Math.floor(hours / 24)}d ago`;
}

function formatDuration(milliseconds) {
  const minutes = Math.max(0, Math.ceil(milliseconds / 60000));
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  if (hours > 0) {
    return `${hours}h ${rest}m`;
  }
  return `${rest}m`;
}

function isoNow() {
  return new Date().toISOString();
}

function inputName() {
  let name = relativeName($("domain-name").value);
  const suffix = `.${zoneName()}`;
  if (name.endsWith(suffix)) {
    name = name.slice(0, -suffix.length);
  }
  return name;
}

function updateLinks() {
  const url = repoUrl();
  for (const id of ["repo-link", "hero-repo", "footer-repo"]) {
    const element = $(id);
    if (element) {
      element.href = url;
    }
  }
}

// ---------------------------------------------------------------------------
// Identity storage

function readIdentityStore() {
  try {
    const raw = JSON.parse(localStorage.getItem(STORAGE.identity) || "{}");
    if (raw && raw.version === 1 && raw.identities && typeof raw.identities === "object") {
      return raw;
    }
  } catch {
    // A corrupt store is replaced below.
  }
  return { version: 1, identities: {} };
}

function writeIdentityStore(store) {
  localStorage.setItem(STORAGE.identity, JSON.stringify(store));
}

function loadIdentity(user) {
  const key = String(user).toLowerCase();
  const store = readIdentityStore();
  const saved = store.identities[key];
  if (saved && typeof saved.seed === "string") {
    try {
      const identity = identityFromSeed(decodeBase64Url(saved.seed));
      if (identity.publicKey === saved.publicKey) {
        return { ...identity, createdAt: saved.createdAt || null };
      }
    } catch {
      // Fall through and create a fresh identity.
    }
  }
  const identity = generateIdentity();
  store.identities[key] = {
    publicKey: identity.publicKey,
    seed: identity.seed,
    createdAt: isoNow(),
  };
  writeIdentityStore(store);
  return { ...identity, createdAt: store.identities[key].createdAt };
}

function saveIdentity(identity) {
  if (!state.user) {
    return;
  }
  const store = readIdentityStore();
  store.identities[String(state.user.login).toLowerCase()] = {
    publicKey: identity.publicKey,
    seed: identity.seed,
    createdAt: identity.createdAt || isoNow(),
  };
  writeIdentityStore(store);
}

async function keyFingerprint(publicKey) {
  const raw = decodeBase64Url(String(publicKey).replace(/^ed25519:/, ""));
  if (globalThis.crypto && crypto.subtle) {
    const digest = await crypto.subtle.digest("SHA-256", raw);
    return [...new Uint8Array(digest).slice(0, 8)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }
  const digest = globalThis.nacl.hash(raw);
  return [...digest.slice(0, 8)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// OAuth

function redirectUri() {
  return `${location.origin}${location.pathname}`;
}

function startLogin() {
  if (!isConfigured()) {
    showFlash(
      "This site is not configured yet. Edit web/config.js and deploy the OAuth Worker.",
      "error",
    );
    return;
  }
  const random = crypto.getRandomValues(new Uint8Array(16));
  const stateValue = encodeBase64Url(random);
  sessionStorage.setItem(STORAGE.state, stateValue);
  const params = new URLSearchParams({
    client_id: config.oauthClientId,
    redirect_uri: redirectUri(),
    scope: "public_repo",
    state: stateValue,
    allow_signup: "true",
  });
  location.assign(`https://github.com/login/oauth/authorize?${params.toString()}`);
}

async function handleOAuthCallback() {
  const params = new URLSearchParams(location.search);
  if (params.has("error")) {
    showFlash(
      `GitHub sign-in was cancelled: ${params.get("error_description") || params.get("error")}`,
      "error",
    );
    history.replaceState(null, "", location.pathname + location.hash);
    return;
  }
  const code = params.get("code");
  if (!code) {
    return;
  }
  const expected = sessionStorage.getItem(STORAGE.state);
  if (!expected || params.get("state") !== expected) {
    showFlash("Sign-in state did not match. Please try again.", "error");
    history.replaceState(null, "", location.pathname + location.hash);
    return;
  }
  sessionStorage.removeItem(STORAGE.state);
  showFlash("Signing in with GitHub…");
  try {
    const response = await fetch(config.oauthWorkerUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, redirect_uri: redirectUri() }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.access_token) {
      throw new Error(data.error || `OAuth Worker returned ${response.status}`);
    }
    sessionStorage.setItem(STORAGE.token, data.access_token);
    history.replaceState(null, "", location.pathname + location.hash);
    await loadUser(data.access_token);
    hideFlash();
  } catch (error) {
    showFlash(`GitHub sign-in failed: ${error.message}`, "error");
    history.replaceState(null, "", location.pathname + location.hash);
  }
}

async function loadUser(token) {
  try {
    const response = await fetch("https://api.github.com/user", {
      headers: apiHeaders(token),
    });
    if (!response.ok) {
      throw new Error(`GitHub API returned ${response.status}`);
    }
    state.user = await response.json();
    state.token = token;
    state.identity = loadIdentity(state.user.login);
    showCabinet();
    await loadLedger({ quiet: true });
    await loadPending();
  } catch (error) {
    sessionStorage.removeItem(STORAGE.token);
    state.user = null;
    state.token = null;
    state.identity = null;
    showSignedOut();
    showFlash(`Could not load your GitHub profile: ${error.message}`, "error");
  }
}

function signOut() {
  sessionStorage.removeItem(STORAGE.token);
  state.user = null;
  state.token = null;
  state.identity = null;
  state.pending = [];
  state.editing = null;
  showSignedOut();
  resetForm();
  showFlash("Signed out. Your identity key stays in this browser.", "ok");
}

// ---------------------------------------------------------------------------
// Ledger and GitHub data

async function fetchLedger() {
  if (!isConfigured()) {
    return [];
  }
  const url =
    `https://raw.githubusercontent.com/${zoneRepo()}/${config.branch || "main"}` +
    `/registry/registrations.json?t=${Date.now()}`;
  const response = await fetch(url, { cache: "no-store" });
  if (response.status === 404) {
    return [];
  }
  if (!response.ok) {
    throw new Error(`ledger request returned ${response.status}`);
  }
  const data = await response.json();
  return Array.isArray(data.registrations) ? data.registrations : [];
}

async function loadLedger({ quiet = false } = {}) {
  if (state.ledgerPromise) {
    return state.ledgerPromise;
  }
  state.ledgerPromise = (async () => {
    try {
      state.ledger = await fetchLedger();
      renderStats();
      renderDomains();
      renderCooldown();
      updateNameState();
    } catch (error) {
      if (!quiet) {
        showFlash(`Could not load the registration ledger: ${error.message}`, "error");
      }
    } finally {
      state.ledgerPromise = null;
    }
  })();
  return state.ledgerPromise;
}

async function loadPending() {
  if (!state.user || !isConfigured()) {
    return;
  }
  const container = $("pending-list");
  try {
    const response = await fetch(
      `https://api.github.com/repos/${zoneRepo()}/issues?state=open&creator=${encodeURIComponent(
        login(),
      )}&per_page=50`,
      { headers: apiHeaders(state.token) },
    );
    if (!response.ok) {
      throw new Error(`GitHub API returned ${response.status}`);
    }
    const issues = await response.json();
    state.pending = issues.filter(
      (issue) => typeof issue.title === "string" && issue.title.startsWith("[register]"),
    );
  } catch (error) {
    container.textContent = "";
    const note = document.createElement("p");
    note.className = "muted small";
    note.textContent = `Could not load pending requests: ${error.message}`;
    container.append(note);
    return;
  }
  renderPending();
}

function renderStats() {
  const entries = state.ledger;
  $("stat-domains").textContent = String(entries.length);
  $("stat-second").textContent = String(
    entries.filter((entry) => entry.kind === "second_level").length,
  );
  $("stat-sub").textContent = String(
    entries.filter((entry) => entry.kind === "subdomain").length,
  );
}

function renderPending() {
  const container = $("pending-list");
  container.textContent = "";
  if (!state.pending.length) {
    const note = document.createElement("p");
    note.className = "muted small";
    note.textContent = "No pending registration issues.";
    container.append(note);
    return;
  }
  for (const issue of state.pending) {
    const item = document.createElement("article");
    item.className = "domain-item";
    const link = document.createElement("a");
    link.href = issue.html_url;
    link.target = "_blank";
    link.rel = "noreferrer";
    link.textContent = `#${issue.number} ${issue.title}`;
    const meta = document.createElement("div");
    meta.className = "domain-meta";
    meta.textContent = `Opened ${relativeTime(issue.created_at)}. The bot will validate and commit.`;
    item.append(link, meta);
    container.append(item);
  }
}

// ---------------------------------------------------------------------------
// Cabinet rendering

function showSignedOut() {
  $("signed-out").hidden = false;
  $("cabinet").hidden = true;
  $("login-button").hidden = false;
}

function showCabinet() {
  $("signed-out").hidden = true;
  $("cabinet").hidden = false;
  $("login-button").hidden = true;

  $("user-avatar").src = state.user.avatar_url || "";
  $("user-avatar").alt = `Avatar of ${state.user.login}`;
  $("user-link").textContent = `@${state.user.login}`;
  $("user-link").href = state.user.html_url || `https://github.com/${state.user.login}`;
  renderIdentity();
  renderDomains();
  renderCooldown();
  updateNameState();
}

async function renderIdentity() {
  if (!state.identity) {
    return;
  }
  $("public-key").textContent = state.identity.publicKey;
  $("key-fingerprint").textContent = await keyFingerprint(state.identity.publicKey);
}

function cooldownRemaining() {
  if (!state.user) {
    return 0;
  }
  const name = login().toLowerCase();
  const times = state.ledger
    .filter(
      (entry) =>
        entry.kind === "second_level" &&
        String(entry.user || "").toLowerCase() === name,
    )
    .map((entry) => Date.parse(entry.registered_at))
    .filter((value) => Number.isFinite(value));
  if (!times.length) {
    return 0;
  }
  return Math.max(0, Math.max(...times) + COOLDOWN_MS - Date.now());
}

function renderCooldown() {
  if (!state.user) {
    return;
  }
  const banner = $("cooldown-banner");
  const remaining = cooldownRemaining();
  if (!remaining) {
    banner.hidden = true;
    banner.className = "notice";
    return;
  }
  banner.hidden = false;
  banner.className = "notice";
  const until = new Date(Date.now() + remaining);
  banner.textContent =
    `You can register one second-level domain every 48 hours. ` +
    `The next second-level name is available in ${formatDuration(remaining)} ` +
    `(${until.toISOString().replace(".000Z", "Z")}). ` +
    `Subdomains and updates are not limited.`;
}

function renderDomains() {
  const container = $("domain-list");
  container.textContent = "";
  if (!state.user) {
    return;
  }
  const mine = state.ledger
    .filter((entry) => String(entry.user || "").toLowerCase() === login().toLowerCase())
    .sort((left, right) => String(left.domain).localeCompare(String(right.domain)));
  $("domain-count").textContent = String(mine.length);
  if (!mine.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "No domains yet. Register one on the left.";
    container.append(empty);
    return;
  }
  for (const entry of mine) {
    container.append(domainItem(entry));
  }
}

function domainItem(entry) {
  const item = document.createElement("article");
  item.className = "domain-item";

  const main = document.createElement("div");
  main.className = "domain-main";
  const name = document.createElement("span");
  name.className = "domain-name";
  name.textContent = entry.fqdn || `${entry.domain}.${zoneName()}`;
  const badge = document.createElement("span");
  badge.className = `badge${entry.kind === "subdomain" ? " is-sub" : ""}`;
  badge.textContent = entry.kind === "second_level" ? "second level" : "subdomain";
  main.append(name, badge);

  const meta = document.createElement("div");
  meta.className = "domain-meta";
  const count = Array.isArray(entry.records) ? entry.records.length : 0;
  meta.textContent = `${count} record${count === 1 ? "" : "s"} · updated ${relativeTime(
    entry.updated_at || entry.registered_at,
  )}`;

  const records = document.createElement("div");
  records.className = "domain-records";
  records.textContent = (entry.records || [])
    .slice(0, 3)
    .map(recordSummary)
    .join(" · ") || "no records";

  const actions = document.createElement("div");
  actions.className = "domain-actions";
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "button button-small button-ghost";
  edit.textContent = "Edit records";
  edit.addEventListener("click", () => beginEdit(entry));
  actions.append(edit);
  if (entry.issue) {
    const issue = document.createElement("a");
    issue.className = "button button-small button-quiet";
    issue.href = `${repoUrl()}/issues/${entry.issue}`;
    issue.target = "_blank";
    issue.rel = "noreferrer";
    issue.textContent = `Issue #${entry.issue}`;
    actions.append(issue);
  }

  item.append(main, meta, records, actions);
  return item;
}

function recordSummary(record) {
  const value = record.value ?? (Array.isArray(record.values) ? record.values.join(" ") : "");
  const text = `${record.type} ${value}`.trim();
  return text.length > 42 ? `${text.slice(0, 39)}…` : text;
}

// ---------------------------------------------------------------------------
// Record editor

function addRecordRow(record = {}) {
  const editor = $("record-editor");
  const row = document.createElement("div");
  row.className = "record-row";

  const top = document.createElement("div");
  top.className = "record-top";

  const select = document.createElement("select");
  select.className = "record-type";
  select.setAttribute("aria-label", "Record type");
  for (const type of RECORD_TYPE_OPTIONS) {
    const option = document.createElement("option");
    option.value = type;
    option.textContent = type === PAGES_TYPE ? "GitHub Pages" : type;
    select.append(option);
  }

  const value = document.createElement("input");
  value.className = "record-value";
  value.type = "text";
  value.autocomplete = "off";
  value.spellcheck = false;
  value.setAttribute("aria-label", "Record value");

  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "icon-button remove-record";
  remove.setAttribute("aria-label", "Remove record");
  remove.textContent = "×";

  top.append(select, value, remove);

  const extra = document.createElement("div");
  extra.className = "record-extra";
  extra.append(
    field("record-ttl", "TTL", "number", { min: 1, max: MAX_TTL, placeholder: "default" }),
    field("opt-priority", "Priority", "number", { min: 0, max: 65535 }),
    field("opt-weight", "Weight", "number", { min: 0, max: 65535 }),
    field("opt-port", "Port", "number", { min: 0, max: 65535 }),
    field("opt-flags", "Flags", "number", { min: 0, max: 255 }),
    field("opt-tag", "Tag", "text", { placeholder: "issue" }),
  );

  const note = document.createElement("p");
  note.className = "record-pages-note";
  note.hidden = true;

  row.append(top, extra, note);
  editor.append(row);

  select.value = RECORD_TYPE_OPTIONS.includes(String(record.type).toUpperCase())
    ? String(record.type).toUpperCase()
    : "A";
  if (Array.isArray(record.values) && record.values.length) {
    value.value =
      String(record.type).toUpperCase() === "A" ||
      String(record.type).toUpperCase() === "AAAA"
        ? record.values.join(", ")
        : record.values[0];
  } else {
    value.value = record.value ?? "";
  }
  row.querySelector(".record-ttl input").value = record.ttl ?? "";
  row.querySelector(".opt-priority input").value = record.priority ?? "";
  row.querySelector(".opt-weight input").value = record.weight ?? "";
  row.querySelector(".opt-port input").value = record.port ?? "";
  row.querySelector(".opt-flags input").value = record.flags ?? "";
  row.querySelector(".opt-tag input").value = record.tag ?? "";

  select.addEventListener("change", () => updateRowType(row));
  value.addEventListener("input", () => updatePagesNote(row));
  remove.addEventListener("click", () => {
    if (editor.querySelectorAll(".record-row").length === 1) {
      value.value = "";
      return;
    }
    row.remove();
  });

  updateRowType(row);
  return row;
}

function field(className, labelText, type, attributes = {}) {
  const label = document.createElement("label");
  label.className = className;
  label.textContent = labelText;
  const input = document.createElement("input");
  input.type = type;
  input.autocomplete = "off";
  for (const [key, value] of Object.entries(attributes)) {
    if (value !== undefined) {
      input.setAttribute(key, String(value));
    }
  }
  label.append(input);
  return label;
}

function updateRowType(row) {
  const select = row.querySelector(".record-type");
  const type = select.value;
  row.dataset.type = type;
  const value = row.querySelector(".record-value");
  const pages = type === PAGES_TYPE;
  value.placeholder = TYPE_PLACEHOLDERS[type] || "";
  value.setAttribute("aria-label", pages ? "GitHub repository" : "Record value");
  const visible = {
    "opt-priority": type === "MX" || type === "SRV",
    "opt-weight": type === "SRV",
    "opt-port": type === "SRV",
    "opt-flags": type === "CAA",
    "opt-tag": type === "CAA",
  };
  for (const [className, show] of Object.entries(visible)) {
    row.querySelector(`.${className}`).classList.toggle("is-visible", show);
  }
  updatePagesNote(row);
}

// Explain what the GitHub Pages preset will sign. The domain name is used to
// choose between the apex address set and a single CNAME.
function updatePagesNote(row) {
  const note = row.querySelector(".record-pages-note");
  if (!note) {
    return;
  }
  if (row.dataset.type !== PAGES_TYPE) {
    note.hidden = true;
    return;
  }
  note.hidden = false;
  const name = inputName();
  const fqdn = name ? `${name}.${zoneName()}` : "this name";
  let owner = "";
  try {
    owner = parsePagesRepo(row.querySelector(".record-value").value, login()).owner;
  } catch {
    // Incomplete input: keep the generic text below.
  }
  const target = owner ? `${owner}.github.io` : "<owner>.github.io";
  const created = name.includes(".")
    ? `Creates one CNAME record for ${fqdn} pointing to ${target}.`
    : `Creates four A and four AAAA records for ${fqdn}. ` +
      `Register www.${name || "name"}.${zoneName()} the same way if you want the www host.`;
  note.textContent =
    `${created} The repository must belong to @${login() || "you"} and use this ` +
    "domain in the GitHub Pages settings of the repository.";
}

function readNumber(row, selector, label, { required = false, min = 0, max = 65535 } = {}) {
  const raw = row.querySelector(selector).value.trim();
  if (!raw) {
    if (required) {
      throw new ZoneError(`${label} is required.`);
    }
    return undefined;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ZoneError(`${label} must be a whole number between ${min} and ${max}.`);
  }
  return value;
}

function collectRecords() {
  const rows = [...document.querySelectorAll("#record-editor .record-row")];
  const records = [];
  for (const row of rows) {
    const type = row.querySelector(".record-type").value;
    const value = row.querySelector(".record-value").value.trim();
    const ttl = readNumber(row, ".record-ttl input", "TTL", { min: 1, max: MAX_TTL });

    if (type === PAGES_TYPE) {
      if (!value) {
        throw new ZoneError(
          "GitHub Pages: enter the repository name, for example your-name/your-site.",
        );
      }
      for (const generated of expandGithubPages(inputName(), value, login())) {
        if (ttl !== undefined) {
          generated.ttl = ttl;
        }
        records.push(generated);
      }
      continue;
    }

    const record = { type };
    // A and AAAA accept several addresses in one row, separated by commas or
    // spaces. This keeps a GitHub Pages apex set readable and compact.
    const multi = type === "A" || type === "AAAA";
    const parts = multi ? value.split(/[\s,]+/).filter(Boolean) : [];
    if (parts.length > 1) {
      record.values = parts;
    } else if (value || type === "TXT") {
      record.value = value;
    }
    if (ttl !== undefined) {
      record.ttl = ttl;
    }
    if (type === "MX" || type === "SRV") {
      const priority = readNumber(row, ".opt-priority input", "Priority");
      if (priority !== undefined) {
        record.priority = priority;
      }
    }
    if (type === "SRV") {
      const weight = readNumber(row, ".opt-weight input", "Weight");
      if (weight !== undefined) {
        record.weight = weight;
      }
      record.port = readNumber(row, ".opt-port input", "Port", { required: true });
    }
    if (type === "CAA") {
      const flags = readNumber(row, ".opt-flags input", "Flags", { min: 0, max: 255 });
      if (flags !== undefined) {
        record.flags = flags;
      }
      const tag = row.querySelector(".opt-tag input").value.trim();
      if (tag) {
        record.tag = tag;
      }
    }
    if (!value && type !== "TXT") {
      continue;
    }
    records.push(record);
  }
  return records;
}

function populateRecords(records) {
  $("record-editor").textContent = "";
  const list = Array.isArray(records) && records.length ? records : [{ type: "A" }];
  for (const record of list) {
    addRecordRow(record);
  }
}

// ---------------------------------------------------------------------------
// Registration form

function beginEdit(entry) {
  state.editing = entry;
  $("domain-name").value = entry.domain;
  $("domain-name").disabled = true;
  $("form-title").textContent = `Update ${entry.fqdn || `${entry.domain}.${zoneName()}`}`;
  $("form-subtitle").textContent =
    "Records are signed with the same owner key. The 48-hour limit does not apply to updates.";
  $("cancel-edit").hidden = false;
  populateRecords(entry.records || []);
  formStatus("");
  updateNameState();
  $("register").scrollIntoView({ behavior: "smooth", block: "start" });
}

function resetForm() {
  state.editing = null;
  $("domain-name").value = "";
  $("domain-name").disabled = false;
  $("form-title").textContent = "Register a domain";
  $("form-subtitle").textContent =
    "Sign a domain file and open a registration issue. A bot validates it and commits the result.";
  $("cancel-edit").hidden = true;
  populateRecords([]);
  formStatus("");
  updateNameState();
}

function updateNameState() {
  const name = inputName();
  const kind = name.includes(".") ? "subdomain" : "second level";
  const badge = $("kind-badge");
  badge.textContent = state.editing ? "editing" : kind;
  badge.classList.toggle("is-sub", !state.editing && name.includes("."));

  const existing = state.ledger.find(
    (entry) => String(entry.domain).toLowerCase() === name && name !== "",
  );
  const remaining = cooldownRemaining();
  const blocked =
    !state.editing &&
    !existing &&
    name !== "" &&
    !name.includes(".") &&
    remaining > 0;
  const submit = $("submit-registration");
  submit.disabled = state.busy || blocked;
  submit.textContent = state.editing
    ? "Sign and open update issue"
    : "Sign and open registration issue";

  const hint = $("name-hint");
  if (state.editing) {
    hint.textContent = "The name is fixed while editing. Cancel to register a different name.";
  } else if (blocked) {
    hint.textContent =
      `The 48-hour limit is active for ${formatDuration(remaining)}. ` +
      "You can still update an existing domain or register a subdomain.";
  } else if (name.includes(".")) {
    hint.textContent = "Subdomains are unlimited but need an owned second-level parent.";
  } else {
    hint.textContent =
      "A second-level name counts toward the 48-hour limit. Subdomains do not.";
  }

  for (const row of document.querySelectorAll(
    `#record-editor .record-row[data-type="${PAGES_TYPE}"]`,
  )) {
    updatePagesNote(row);
  }
}

function buildIssueBody(document, recordCount, action) {
  return [
    "### .ion registration request",
    "",
    ISSUE_MARKER,
    "",
    `- Domain: \`${document.name}.${zoneName()}\``,
    `- Action: ${action}`,
    `- Owner key: \`${document.owner}\``,
    `- Records: ${recordCount}`,
    "",
    "```toml",
    dumpDomainToml(document).trimEnd(),
    "```",
    "",
    "<sub>Signed in the browser. The signature covers the canonical JSON of this file.</sub>",
  ].join("\n");
}

async function submitRegistration(event) {
  event.preventDefault();
  if (state.busy) {
    return;
  }
  if (!state.user || !state.identity) {
    formStatus("Sign in with GitHub first.", "error");
    return;
  }

  const name = inputName();
  const nameErrors = validateName(name);
  if (nameErrors.length) {
    formStatus(nameErrors.join(" "), "error");
    return;
  }

  let records;
  try {
    records = collectRecords();
  } catch (error) {
    formStatus(error.message, "error");
    return;
  }
  const recordErrors = validateRecords(records);
  if (recordErrors.length) {
    formStatus(recordErrors.join(" "), "error");
    return;
  }

  const existing = state.ledger.find(
    (entry) => String(entry.domain).toLowerCase() === name,
  );
  if (existing) {
    if (String(existing.user).toLowerCase() !== login().toLowerCase()) {
      formStatus("This domain is registered by another GitHub account.", "error");
      return;
    }
    if (existing.owner !== state.identity.publicKey) {
      formStatus(
        "This domain belongs to a different owner key. Import the key that signed it.",
        "error",
      );
      return;
    }
  }
  if (state.editing && existing && existing.domain !== state.editing.domain) {
    formStatus("The edited name changed unexpectedly. Cancel and try again.", "error");
    return;
  }

  if (!existing && !name.includes(".")) {
    const remaining = cooldownRemaining();
    if (remaining > 0) {
      formStatus(
        `One second-level domain per 48 hours. Try again in ${formatDuration(remaining)}.`,
        "error",
      );
      return;
    }
  }

  if (name.includes(".")) {
    const parent = secondLevel(name);
    const parentEntry = state.ledger.find(
      (entry) => String(entry.domain).toLowerCase() === parent,
    );
    if (!parentEntry) {
      formStatus(`Register ${parent}.${zoneName()} before adding subdomains.`, "error");
      return;
    }
    if (String(parentEntry.user).toLowerCase() !== login().toLowerCase()) {
      formStatus("Only the owner of the parent domain can add subdomains.", "error");
      return;
    }
    if (parentEntry.owner !== state.identity.publicKey) {
      formStatus("Subdomains must be signed with the parent domain key.", "error");
      return;
    }
  }

  const created =
    (existing && existing.created) ||
    (state.editing && state.editing.created) ||
    isoNow();
  const document = {
    schema: 1,
    name,
    created,
    updated: isoNow(),
    records,
  };

  let signed;
  try {
    signed = signDomain(zoneName(), document, state.identity);
  } catch (error) {
    formStatus(`Could not sign the registration: ${error.message}`, "error");
    return;
  }

  state.busy = true;
  updateNameState();
  formStatus("Opening a registration issue…");
  try {
    const response = await fetch(`https://api.github.com/repos/${zoneRepo()}/issues`, {
      method: "POST",
      headers: {
        ...apiHeaders(state.token),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        title: `[register] ${name}.${zoneName()}`,
        body: buildIssueBody(signed, records.length, existing ? "update" : "register"),
      }),
    });
    const issue = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(issue.message || `GitHub API returned ${response.status}`);
    }
    const target = existing
      ? "update"
      : name.includes(".")
        ? "subdomain"
        : "second-level domain";
    showFlash(
      `Registration issue #${issue.number} opened for ${name}.${zoneName()}. ` +
        `The bot will validate the ${target} and commit it.`,
      "ok",
    );
    formStatus(`Issue #${issue.number} opened. Track it in "Pending requests".`, "ok");
    state.editing = null;
    $("domain-name").disabled = false;
    $("cancel-edit").hidden = true;
    $("domain-name").value = "";
    populateRecords([]);
    $("form-title").textContent = "Register a domain";
    $("form-subtitle").textContent =
      "Sign a domain file and open a registration issue. A bot validates it and commits the result.";
    await loadPending();
    updateNameState();
  } catch (error) {
    formStatus(`Could not open the issue: ${error.message}`, "error");
  } finally {
    state.busy = false;
    updateNameState();
  }
}

// ---------------------------------------------------------------------------
// Key import and export

function exportIdentity() {
  if (!state.identity) {
    return;
  }
  const data = {
    version: 1,
    zone: zoneName(),
    publicKey: state.identity.publicKey,
    seed: state.identity.seed,
    createdAt: state.identity.createdAt || isoNow(),
    warning: "This file is a private key. Keep it offline and never commit it.",
  };
  const blob = new Blob([JSON.stringify(data, null, 2) + "\n"], {
    type: "application/json",
  });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `ion-identity-${login() || "owner"}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
  showFlash(
    "Identity exported. This file contains your private key: store it offline.",
    "ok",
  );
}

async function importIdentity(file) {
  if (!file || !state.user) {
    return;
  }
  try {
    const data = JSON.parse(await file.text());
    if (typeof data.seed !== "string" || typeof data.publicKey !== "string") {
      throw new ZoneError("The file has no seed or public key.");
    }
    const identity = identityFromSeed(decodeBase64Url(data.seed));
    if (identity.publicKey !== data.publicKey) {
      throw new ZoneError("The public key in the file does not match the seed.");
    }
    if (
      state.identity &&
      state.identity.publicKey !== identity.publicKey &&
      !window.confirm(
        "Replace the current identity? Domains signed with the old key cannot be updated from this browser afterwards.",
      )
    ) {
      return;
    }
    state.identity = { ...identity, createdAt: data.createdAt || isoNow() };
    saveIdentity(state.identity);
    await renderIdentity();
    renderDomains();
    showFlash("Identity imported. Future signatures use this key.", "ok");
  } catch (error) {
    showFlash(`Could not import the identity: ${error.message}`, "error");
  } finally {
    $("import-file").value = "";
  }
}

// ---------------------------------------------------------------------------
// Wiring

function wireEvents() {
  $("login-button").addEventListener("click", startLogin);
  $("login-button-2").addEventListener("click", startLogin);
  $("logout-button").addEventListener("click", signOut);
  $("refresh-button").addEventListener("click", async () => {
    await loadLedger();
    await loadPending();
  });
  $("add-record").addEventListener("click", () => {
    addRecordRow();
    const rows = document.querySelectorAll("#record-editor .record-row");
    rows[rows.length - 1].querySelector(".record-value").focus();
  });
  $("registration-form").addEventListener("submit", submitRegistration);
  $("domain-name").addEventListener("input", updateNameState);
  $("cancel-edit").addEventListener("click", resetForm);
  $("export-key").addEventListener("click", exportIdentity);
  $("import-key").addEventListener("click", () => $("import-file").click());
  $("import-file").addEventListener("change", (event) => {
    const file = event.target.files && event.target.files[0];
    if (file) {
      importIdentity(file);
    }
  });
}

async function init() {
  updateLinks();
  wireEvents();
  populateRecords([]);
  if (!isConfigured()) {
    showFlash(
      "Setup needed: edit web/config.js with the zone repository, OAuth client ID and Worker URL. See README.md.",
      "error",
    );
    showSignedOut();
    return;
  }
  await handleOAuthCallback();
  if (!state.user) {
    const token = sessionStorage.getItem(STORAGE.token);
    if (token) {
      await loadUser(token);
    } else {
      showSignedOut();
    }
  }
  await loadLedger({ quiet: false });
  if (state.user) {
    updateNameState();
  }
}

init();
