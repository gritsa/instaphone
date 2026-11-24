/* Instaphone — browser-based Twilio softphone (personal use only). */
'use strict';

/* ### section-storage */
const LS_KEYS = {
  creds: 'instaphone.credentials',
  contacts: 'instaphone.contacts',
  log: 'instaphone.calllog',
};

function lsGet(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw === null ? fallback : JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function lsSet(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function lsRemove(key) {
  localStorage.removeItem(key);
}
/* ### endsection */

/* ### section-jwt */
/**
 * Mint a Twilio Voice access token (HS256) entirely in the browser.
 * Returns a Promise<string> because Web Crypto's HMAC is async.
 *
 * Token shape (matches twilio.jwt.AccessToken exactly — verified byte-for-byte
 * against the official Node SDK via scripts/diff-official-sdk.mjs):
 *   header  : { typ: "JWT", alg: "HS256", cty: "twilio-fpa;v=1" }
 *   payload : { jti: "<apiKeySid>-<iat>", iss: API_KEY_SID (SK…),
 *               sub: AccountSID (AC…), iat, nbf, exp,
 *               grants: { identity, voice: { incoming: { allow: true },
 *                          outgoing: { application_sid: TwimlAppSid } } } }
 *   signed  : HMAC-SHA256 with the API Key secret.
 *
 * CRITICAL: `iss` MUST be the API Key SID (SK…), NOT the Account SID.
 * Twilio's token validator resolves WHICH API key (and therefore which
 * secret) to verify the signature with by looking up the `iss` claim.
 * Setting iss = Account SID makes the validator look up a nonexistent
 * API key and fail with AccessTokenInvalid (20101) — even though the
 * signature itself is perfectly valid (which is why jsonwebtoken.verify
 * passes but Twilio's servers reject the token).
 *
 * NOTE: the outgoing grant key is `application_sid` (NOT `app_sid`) — this is
 * what Twilio's official SDKs emit and what their token validator expects.
 */
// Backdate iat/nbf slightly so minor client-clock drift behind Twilio's
// servers doesn't cause an AccessTokenInvalid (20101) rejection.
const CLOCK_SKEW_TOLERANCE_SECONDS = 30;

async function mintAccessToken(creds, ttlSeconds = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const iat = now - CLOCK_SKEW_TOLERANCE_SECONDS;
  const header = { typ: 'JWT', alg: 'HS256', cty: 'twilio-fpa;v=1' };
  const payload = {
    jti: `${creds.apiKeySid}-${iat}`,
    iss: creds.apiKeySid,
    sub: creds.accountSid,
    iat,
    nbf: iat,
    exp: now + ttlSeconds,
    grants: {
      identity: creds.identity,
      voice: {
        incoming: { allow: true },
        outgoing: { application_sid: creds.twimlAppSid },
      },
    },
  };

  const enc = new TextEncoder();
  const signingInput =
    b64urlEncode(enc.encode(JSON.stringify(header))) +
    '.' +
    b64urlEncode(enc.encode(JSON.stringify(payload)));

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(creds.apiSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(signingInput));
  return `${signingInput}.${b64urlEncode(new Uint8Array(sig))}`;
}

function b64urlEncode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode a JWT payload WITHOUT verifying the signature (debug aid only).
 * Returns the parsed claims object, or null if the token is malformed.
 * Never contains the signing secret — safe to log/share.
 */
function decodeJwtPayload(token) {
  try {
    const parts = String(token).split('.');
    if (parts.length !== 3) return null;
    let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    return JSON.parse(atob(b64));
  } catch {
    return null;
  }
}

/** Log the decoded token payload (never the secret) for debugging 20101s. */
function logTokenPayloadForDebug(token, context) {
  const payload = decodeJwtPayload(token);
  if (!payload) {
    console.warn(`[${context}] Could not decode token payload for debugging.`);
    return;
  }
  console.info(
    `[${context}] Decoded access-token payload (safe to share — contains no secret). ` +
    `Check: iss = API Key SID (SK…), sub = Account SID (AC…), ` +
    `grants.voice.outgoing.application_sid = TwiML App SID (AP…), ` +
    `grants.identity = your client identity, exp/iat/nbf are numeric epoch seconds.\n` +
    `If iss below is NOT an SK… SID, you are running a stale cached app.js — hard-refresh (Cmd+Shift+R).`,
    payload,
    `\n${JSON.stringify(payload, null, 2)}`
  );
}
/* ### endsection */

/* ### section-state */
const state = {
  creds: null,          // { accountSid, apiKeySid, apiSecret, twimlAppSid, identity }
  device: null,         // Twilio Voice SDK Device instance
  activeCall: null,     // Call instance (outgoing or accepted incoming)
  pendingIncoming: null,// Call instance awaiting accept/reject
  callTimer: null,
  callStart: null,
  currentCallMeta: null,// { direction, remote, name }
  holdSupported: true,
  lastMintedToken: null,// kept for debug logging on 20101 (never displayed)
};

const $ = (id) => document.getElementById(id);

function setStatus(kind, text) {
  const pill = $('device-status');
  pill.className = `status-pill status-${kind}`;
  $('device-status-text').textContent = text;
}

function errText(err) {
  if (!err) return 'Unknown error';
  if (typeof err === 'string') return err;
  return err.message || err.explanation || (err.code != null ? `code ${err.code}` : String(err));
}
/* ### endsection */

/* ### section-onboarding */
function initOnboarding() {
  const form = $('onboarding-form');
  const checkbox = $('cred-confirm');
  const saveBtn = $('onboarding-save');
  const cancelBtn = $('onboarding-cancel');

  checkbox.addEventListener('change', () => {
    saveBtn.disabled = !checkbox.checked;
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const creds = {
      accountSid: $('cred-account-sid').value.trim(),
      apiKeySid: $('cred-api-key-sid').value.trim(),
      apiSecret: $('cred-api-secret').value.trim(),
      twimlAppSid: $('cred-twiml-app-sid').value.trim(),
      identity: $('cred-identity').value.trim() || 'browser-user',
    };
    if (!creds.accountSid || !creds.apiKeySid || !creds.apiSecret || !creds.twimlAppSid) {
      toast('Please fill in all credential fields.', 'error');
      return;
    }
    if (!/^AC[0-9a-f]{32}$/i.test(creds.accountSid) ||
        !/^SK[0-9a-f]{32}$/i.test(creds.apiKeySid) ||
        !/^AP[0-9a-f]{32}$/i.test(creds.twimlAppSid)) {
      toast('SIDs look invalid — expected AC…/SK…/AP… followed by 32 hex chars.', 'error');
      return;
    }
    lsSet(LS_KEYS.creds, creds);
    state.creds = creds;
    hideOnboarding();
    $('app').hidden = false;
    initSettingsView();
    await setupDevice();
  });

  cancelBtn.addEventListener('click', () => {
    hideOnboarding();
  });
}

function showOnboarding(forEdit = false) {
  const c = state.creds;
  if (c) {
    $('cred-account-sid').value = c.accountSid;
    $('cred-api-key-sid').value = c.apiKeySid;
    $('cred-api-secret').value = c.apiSecret;
    $('cred-twiml-app-sid').value = c.twimlAppSid;
    $('cred-identity').value = c.identity;
    $('cred-confirm').checked = true;
    $('onboarding-save').disabled = false;
  }
  $('onboarding-cancel').hidden = !forEdit;
  $('onboarding').hidden = false;
}

function hideOnboarding() {
  $('onboarding').hidden = true;
}
/* ### endsection */

/* ### section-device */
async function setupDevice() {
  if (!state.creds) return;
  setStatus('connecting', 'Connecting…');
  let token = null;
  try {
    token = await mintAccessToken(state.creds);
    state.lastMintedToken = token;

    if (state.device) {
      try { state.device.destroy(); } catch { /* ignore */ }
      state.device = null;
    }

    const device = new Twilio.Device(token, {
      codecPreferences: ['opus', 'pcmu'],
      allowIncomingWhileBusy: false,
    });
    state.device = device;
    wireDeviceEvents(device);
    await device.register();
  } catch (err) {
    console.error('Device setup failed:', errText(err));
    if (token) logTokenPayloadForDebug(token, 'device-setup');
    setStatus('error', 'Error');
    toast(`Failed to set up device: ${errText(err)}`, 'error');
  }
}

function wireDeviceEvents(device) {
  device.on('registered', () => {
    setStatus('online', `Registered · ${state.creds.identity}`);
    toast('Device registered — ready for calls.', 'success');
  });

  device.on('unregistered', () => setStatus('offline', 'Offline'));

  device.on('error', (err) => {
    console.error('Device error:', err);
    // AccessTokenInvalid (20101): dump the decoded payload (never the secret)
    // so the user can inspect/share exactly what Twilio rejected.
    if (err && err.code === 20101) {
      logTokenPayloadForDebug(state.lastMintedToken, 'twilio-20101');
    }
    setStatus('error', 'Error');
    toast(`Twilio error: ${errText(err)}`, 'error');
  });

  device.on('incoming', (call) => {
    state.pendingIncoming = call;
    showIncoming(call);
  });

  device.on('tokenWillExpire', async () => {
    try {
      const token = await mintAccessToken(state.creds);
      state.lastMintedToken = token;
      device.updateToken(token);
    } catch (err) {
      console.error('Token refresh failed:', err);
    }
  });
}
/* ### endsection */

/* ### section-call */
function lookupName(number) {
  const contacts = lsGet(LS_KEYS.contacts, []);
  const hit = contacts.find(
    (c) => c.phone.replace(/[^\d+]/g, '') === String(number).replace(/[^\d+]/g, '')
  );
  return hit ? hit.name : null;
}

function remoteLabel(call) {
  const from = call.parameters && (call.parameters.From || call.parameters.from);
  const to = call.parameters && (call.parameters.To || call.parameters.to);
  const raw = from || to || 'Unknown';
  const stripped = String(raw).replace(/^client:/, '').replace(/^sip:/, '');
  const name = lookupName(stripped);
  return { raw: stripped, name };
}

function startCallTimer() {
  state.callStart = Date.now();
  state.callTimer = setInterval(() => {
    const s = Math.floor((Date.now() - state.callStart) / 1000);
    $('call-timer').textContent =
      `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
  }, 1000);
}

function stopCallTimer() {
  if (state.callTimer) clearInterval(state.callTimer);
  state.callTimer = null;
  return state.callStart ? Math.round((Date.now() - state.callStart) / 1000) : 0;
}

async function startOutgoingCall() {
  const target = $('dial-display').value.trim();
  if (!target) { toast('Enter a number first.', 'error'); return; }
  if (!state.device) { toast('Device not ready.', 'error'); return; }
  if (state.activeCall || state.pendingIncoming) return;

  const params = { To: target };
  try {
    const call = await state.device.connect({ params });
    state.activeCall = call;
    state.currentCallMeta = {
      direction: 'outgoing',
      remote: target,
      name: lookupName(target),
    };
    showCallOverlay('Calling…', target);
    wireCallEvents(call);
  } catch (err) {
    console.error('Call failed:', err);
    toast(`Call failed: ${errText(err)}`, 'error');
    addLogEntry('outgoing', target, lookupName(target), 'failed', 0);
  }
}

function wireCallEvents(call) {
  call.on('ringing', () => {
    if (state.activeCall === call) setCallState('Ringing…');
  });

  call.on('accept', () => {
    if (state.activeCall !== call) return;
    setCallState('Connected');
    startCallTimer();
  });

  call.on('disconnect', () => {
    const wasActive = state.activeCall === call;
    const wasIncoming = state.pendingIncoming === call;
    if (wasActive) {
      const duration = stopCallTimer();
      const meta = state.currentCallMeta || { direction: 'outgoing', remote: 'Unknown' };
      const outcome = duration > 0 ? 'answered' : 'no-answer';
      addLogEntry(meta.direction, meta.remote, meta.name, outcome, duration);
      hideCallOverlay();
      state.activeCall = null;
      state.currentCallMeta = null;
    }
    if (wasIncoming) {
      addLogEntry('incoming', remoteLabel(call).raw, remoteLabel(call).name, 'missed', 0);
      hideIncoming();
      state.pendingIncoming = null;
    }
  });

  call.on('cancel', () => {
    if (state.pendingIncoming === call) {
      addLogEntry('incoming', remoteLabel(call).raw, remoteLabel(call).name, 'missed', 0);
      hideIncoming();
      state.pendingIncoming = null;
    }
  });

  call.on('reject', () => {
    if (state.pendingIncoming === call) {
      addLogEntry('incoming', remoteLabel(call).raw, remoteLabel(call).name, 'rejected', 0);
      hideIncoming();
      state.pendingIncoming = null;
    }
  });

  call.on('error', (err) => {
    console.error('Call error:', err);
    toast(`Call error: ${errText(err)}`, 'error');
    if (state.activeCall === call) {
      stopCallTimer();
      addLogEntry(
        (state.currentCallMeta && state.currentCallMeta.direction) || 'outgoing',
        (state.currentCallMeta && state.currentCallMeta.remote) || 'Unknown',
        state.currentCallMeta && state.currentCallMeta.name,
        'failed',
        0
      );
      hideCallOverlay();
      state.activeCall = null;
    }
    if (state.pendingIncoming === call) {
      hideIncoming();
      state.pendingIncoming = null;
    }
  });
}

/* ----- Call overlay UI ----- */
function setCallState(text) {
  $('call-state-label').textContent = text;
}

function showCallOverlay(stateText, remote) {
  setCallState(stateText);
  $('call-remote').textContent = remote;
  $('call-avatar').textContent = (remote[0] || '?').toUpperCase();
  $('call-timer').textContent = '00:00';
  $('call-mute').classList.remove('active');
  $('call-hold').classList.remove('active');
  $('call-overlay').hidden = false;
}

function hideCallOverlay() {
  $('call-overlay').hidden = true;
}

function toggleMute() {
  if (!state.activeCall) return;
  const muted = state.activeCall.isMuted();
  if (muted) state.activeCall.mute(false);
  else state.activeCall.mute(true);
  $('call-mute').classList.toggle('active', !muted);
}

async function toggleHold() {
  if (!state.activeCall) return;
  if (typeof state.activeCall.sendDigits !== 'function') return;
  // Voice SDK v2 has no direct hold API; hold is typically triggered via
  // DTMF to the far end's PBX/TwiML. We send the standard hold digit pair.
  try {
    state.activeCall.sendDigits('*2');
    const btn = $('call-hold');
    const nowOn = !btn.classList.contains('active');
    btn.classList.toggle('active', nowOn);
    setCallState(nowOn ? 'On hold' : 'Connected');
  } catch (err) {
    toast(`Hold failed: ${errText(err)}`, 'error');
  }
}

function hangUp() {
  if (state.activeCall) {
    try { state.activeCall.disconnect(); } catch { /* ignore */ }
  }
  if (state.pendingIncoming) {
    try { state.pendingIncoming.reject(); } catch { /* ignore */ }
  }
}

/* ----- Incoming call UI ----- */
function showIncoming(call) {
  const { raw, name } = remoteLabel(call);
  const label = name || raw;
  $('incoming-remote').textContent = label;
  $('incoming-avatar').textContent = (label[0] || '?').toUpperCase();
  $('incoming-modal').hidden = false;
}

function hideIncoming() {
  $('incoming-modal').hidden = true;
}

function acceptIncoming() {
  if (!state.pendingIncoming) return;
  const call = state.pendingIncoming;
  state.pendingIncoming = null;
  hideIncoming();
  state.activeCall = call;
  state.currentCallMeta = {
    direction: 'incoming',
    remote: remoteLabel(call).raw,
    name: remoteLabel(call).name,
  };
  showCallOverlay('Connecting…', state.currentCallMeta.name || state.currentCallMeta.remote);
  wireCallEvents(call);
  call.accept();
}

function rejectIncoming() {
  if (!state.pendingIncoming) return;
  const call = state.pendingIncoming;
  state.pendingIncoming = null;
  hideIncoming();
  try { call.reject(); } catch { /* ignore */ }
}
/* ### endsection */

/* ### section-contacts */
let editingContactId = null;

function renderContacts() {
  const contacts = lsGet(LS_KEYS.contacts, []);
  const list = $('contact-list');
  list.innerHTML = '';
  $('contacts-empty').hidden = contacts.length > 0;

  contacts
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name))
    .forEach((c) => {
      const li = document.createElement('li');
      li.innerHTML = `
        <div class="item-main">
          <div class="item-title"></div>
          <div class="item-sub"></div>
        </div>
        <div class="item-actions">
          <button class="mini-btn dial" title="Call" aria-label="Call ${''}"><svg class="icon"><use href="#i-phone"/></svg></button>
          <button class="mini-btn edit" title="Edit" aria-label="Edit"><svg class="icon"><use href="#i-edit"/></svg></button>
          <button class="mini-btn delete" title="Delete" aria-label="Delete"><svg class="icon"><use href="#i-trash"/></svg></button>
        </div>`;
      li.querySelector('.item-title').textContent = c.name;
      li.querySelector('.item-sub').textContent = c.phone;
      li.querySelector('.dial').addEventListener('click', () => {
        switchTab('dialer');
        $('dial-display').value = c.phone;
        startOutgoingCall();
      });
      li.querySelector('.edit').addEventListener('click', () => openContactModal(c.id));
      li.querySelector('.delete').addEventListener('click', () => {
        confirmDialog('Delete contact', `Delete "${c.name}"?`, () => {
          lsSet(LS_KEYS.contacts, lsGet(LS_KEYS.contacts, []).filter((x) => x.id !== c.id));
          renderContacts();
          toast('Contact deleted.', 'success');
        });
      });
      list.appendChild(li);
    });
}

function openContactModal(contactId = null) {
  editingContactId = contactId;
  const contact = contactId
    ? lsGet(LS_KEYS.contacts, []).find((c) => c.id === contactId)
    : null;
  $('contact-modal-title').textContent = contact ? 'Edit contact' : 'Add contact';
  $('contact-name').value = contact ? contact.name : '';
  $('contact-phone').value = contact ? contact.phone : '';
  $('contact-modal').hidden = false;
  $('contact-name').focus();
}

function closeContactModal() {
  $('contact-modal').hidden = true;
  editingContactId = null;
}

function initContacts() {
  $('btn-add-contact').addEventListener('click', () => openContactModal());
  $('contact-cancel').addEventListener('click', closeContactModal);

  $('contact-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const name = $('contact-name').value.trim();
    const phone = $('contact-phone').value.trim();
    if (!name || !phone) { toast('Name and number are required.', 'error'); return; }

    const contacts = lsGet(LS_KEYS.contacts, []);
    const wasEdit = !!editingContactId;
    if (editingContactId) {
      const idx = contacts.findIndex((c) => c.id === editingContactId);
      if (idx !== -1) contacts[idx] = { ...contacts[idx], name, phone };
    } else {
      contacts.push({ id: crypto.randomUUID(), name, phone });
    }
    lsSet(LS_KEYS.contacts, contacts);
    closeContactModal();
    renderContacts();
    toast(wasEdit ? 'Contact updated.' : 'Contact added.', 'success');
  });
}
/* ### endsection */

/* ### section-log */
function renderLog() {
  const log = lsGet(LS_KEYS.log, []);
  const list = $('log-list');
  list.innerHTML = '';
  $('log-empty').hidden = log.length > 0;

  log.forEach((entry) => {
    const li = document.createElement('li');
    const when = new Date(entry.timestamp).toLocaleString();
    const outcomeText =
      entry.outcome === 'answered'
        ? `${formatDuration(entry.duration)}`
        : entry.outcome;
    const dirIcon = entry.direction === 'outgoing' ? 'i-arrow-up-right' : 'i-arrow-down-left';
    li.innerHTML = `
      <div class="item-main">
        <div class="item-title"></div>
        <div class="item-sub"></div>
      </div>
      <div class="item-actions">
        <button class="mini-btn dial" title="Call back"><svg class="icon"><use href="#i-phone"/></svg></button>
      </div>`;
    const dirBadge = document.createElement('span');
    dirBadge.className = `dir-badge dir-${entry.direction}`;
    dirBadge.title = entry.direction;
    dirBadge.innerHTML = `<svg class="icon"><use href="#${dirIcon}"/></svg>`;
    li.insertBefore(dirBadge, li.firstChild);
    li.querySelector('.item-title').textContent = entry.name || entry.remote;
    li.querySelector('.item-sub').textContent = `${entry.remote} · ${when} · ${outcomeText}`;
    li.querySelector('.dial').addEventListener('click', () => {
      switchTab('dialer');
      $('dial-display').value = entry.remote;
      startOutgoingCall();
    });
    list.appendChild(li);
  });
}

function formatDuration(s) {
  if (!s || s <= 0) return '—';
  const m = Math.floor(s / 60);
  const r = s % 60;
  return m > 0 ? `${m}m ${r}s` : `${r}s`;
}

function addLogEntry(direction, remote, name, outcome, duration) {
  const log = lsGet(LS_KEYS.log, []);
  log.unshift({
    id: crypto.randomUUID(),
    direction,
    remote,
    name: name || null,
    timestamp: Date.now(),
    outcome,
    duration,
  });
  lsSet(LS_KEYS.log, log.slice(0, 200));
  renderLog();
}

function initLog() {
  $('btn-clear-log').addEventListener('click', () => {
    confirmDialog('Clear call log', 'Delete all call log entries?', () => {
      lsSet(LS_KEYS.log, []);
      renderLog();
      toast('Call log cleared.', 'success');
    });
  });
}
/* ### endsection */

/* ### section-tabs */
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t) => {
    t.classList.toggle('active', t.dataset.tab === name);
  });
  document.querySelectorAll('.tab-panel').forEach((p) => {
    p.classList.toggle('active', p.id === `tab-${name}`);
  });
}

function initTabs() {
  document.querySelectorAll('.tab').forEach((t) => {
    t.addEventListener('click', () => switchTab(t.dataset.tab));
  });
}
/* ### endsection */

/* ### section-modals */
let confirmAction = null;

function confirmDialog(title, message, onOk) {
  $('confirm-title').textContent = title;
  $('confirm-message').textContent = message;
  confirmAction = onOk;
  $('confirm-modal').hidden = false;
}

function initModals() {
  $('confirm-cancel').addEventListener('click', () => {
    $('confirm-modal').hidden = true;
    confirmAction = null;
  });
  $('confirm-ok').addEventListener('click', () => {
    $('confirm-modal').hidden = true;
    if (confirmAction) confirmAction();
    confirmAction = null;
  });
}

function toast(message, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`.trim();
  el.textContent = message;
  $('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}
/* ### endsection */

/* ### section-settings */
const SECRET_PLACEHOLDER = '••••••••••••••••••••';

function isSecretPlaceholder(value) {
  return /^•+$/.test(value.trim());
}

/** Populate the settings form from persisted credentials. */
function initSettingsView() {
  const creds = lsGet(LS_KEYS.creds, null);
  if (!creds) return;
  $('settings-account-sid').value = creds.accountSid || '';
  $('settings-api-key-sid').value = creds.apiKeySid || '';
  $('settings-api-secret').value = SECRET_PLACEHOLDER;
  $('settings-twiml-app-sid').value = creds.twimlAppSid || '';
  $('settings-identity').value = creds.identity || '';
}

function initSettings() {
  $('settings-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const stored = lsGet(LS_KEYS.creds, null);
    if (!stored) return;

    const accountSid = $('settings-account-sid').value.trim();
    const apiKeySid = $('settings-api-key-sid').value.trim();
    const twimlAppSid = $('settings-twiml-app-sid').value.trim();
    const identity = $('settings-identity').value.trim() || 'browser-user';
    const secretField = $('settings-api-secret').value.trim();

    if (!accountSid || !apiKeySid || !twimlAppSid) {
      toast('Account SID, API Key SID, and TwiML App SID are required.', 'error');
      return;
    }
    if (!/^AC[0-9a-f]{32}$/i.test(accountSid) ||
        !/^SK[0-9a-f]{32}$/i.test(apiKeySid) ||
        !/^AP[0-9a-f]{32}$/i.test(twimlAppSid)) {
      toast('SIDs look invalid — expected AC…/SK…/AP… followed by 32 hex chars.', 'error');
      return;
    }

    // Preserve the stored secret when the field still holds the mask.
    const apiSecret = isSecretPlaceholder(secretField) || !secretField
      ? stored.apiSecret
      : secretField;

    const creds = { accountSid, apiKeySid, apiSecret, twimlAppSid, identity };
    lsSet(LS_KEYS.creds, creds);
    state.creds = creds;
    initSettingsView(); // re-mask the secret field after save
    toast('Settings saved. Reconnecting…', 'success');
    setupDevice();
  });

  $('btn-reconnect').addEventListener('click', () => {
    if (!state.creds) { toast('No credentials saved.', 'error'); return; }
    setupDevice();
  });
}
/* ### endsection */

/* ### section-theme */
const THEME_KEY = 'instaphone.theme';

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = $('theme-toggle');
  if (btn) btn.title = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
}

function initTheme() {
  const btn = $('theme-toggle');
  if (!btn) return;
  btn.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    try { localStorage.setItem(THEME_KEY, next); } catch { /* ignore */ }
  });
  // Reflect the OS preference live if the user hasn't chosen explicitly.
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
      let saved = null;
      try { saved = localStorage.getItem(THEME_KEY); } catch { /* ignore */ }
      if (saved !== 'light' && saved !== 'dark') applyTheme(e.matches ? 'light' : 'dark');
    });
  }
}
/* ### endsection */

/* ### section-init */
function initDialer() {
  document.querySelectorAll('#keypad .key').forEach((btn) => {
    btn.addEventListener('click', () => {
      $('dial-display').value += btn.dataset.key;
    });
  });
  $('dial-backspace').addEventListener('click', () => {
    const v = $('dial-display').value;
    $('dial-display').value = v.slice(0, -1);
  });
  $('btn-call').addEventListener('click', startOutgoingCall);
  $('dial-display').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') startOutgoingCall();
  });
}

function initCallControls() {
  $('call-mute').addEventListener('click', toggleMute);
  $('call-hold').addEventListener('click', toggleHold);
  $('call-hangup').addEventListener('click', hangUp);
  $('incoming-accept').addEventListener('click', acceptIncoming);
  $('incoming-reject').addEventListener('click', rejectIncoming);
}

function initDangerZone() {
  $('btn-clear-all').addEventListener('click', () => {
    confirmDialog(
      'Clear all data',
      'This permanently deletes your stored Twilio credentials, contacts, and call log from this browser. Continue?',
      () => {
        Object.values(LS_KEYS).forEach(lsRemove);
        state.creds = null;
        if (state.device) {
          try { state.device.destroy(); } catch { /* ignore */ }
          state.device = null;
        }
        setStatus('offline', 'Offline');
        renderContacts();
        renderLog();
        $('app').hidden = true;
        showOnboarding(false);
        toast('All data cleared.', 'success');
      }
    );
  });

  $('btn-edit-creds').addEventListener('click', () => switchTab('settings'));
}

function boot() {
  initOnboarding();
  initTabs();
  initDialer();
  initCallControls();
  initContacts();
  initLog();
  initModals();
  initSettings();
  initTheme();
  initDangerZone();

  renderContacts();
  renderLog();

  const creds = lsGet(LS_KEYS.creds, null);
  if (creds) {
    state.creds = creds;
    hideOnboarding(); // onboarding overlay is visible by default in the HTML
    $('app').hidden = false;
    initSettingsView(); // populate settings from persisted credentials
    setupDevice();
  } else {
    showOnboarding(false);
  }
}

document.addEventListener('DOMContentLoaded', boot);
/* ### endsection */
