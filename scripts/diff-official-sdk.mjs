#!/usr/bin/env node
/**
 * diff-official-sdk.mjs — byte-for-byte structural diff between:
 *   (A) the token app.js mints in the browser (Web Crypto HS256), and
 *   (B) the token Twilio's OFFICIAL Node SDK mints (twilio.jwt.AccessToken).
 *
 * Any structural difference (header fields, claim names, claim values,
 * encoding) is a candidate root cause for AccessTokenInvalid (20101).
 *
 * Usage: node scripts/diff-official-sdk.mjs
 */

import { webcrypto as crypto } from 'node:crypto';
import twilio from 'twilio';

/* ---------- placeholder credentials (same for both minters) ---------- */
const creds = {
  accountSid: 'ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  apiKeySid: 'SKbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  apiSecret: 'Cccccccccccccccccccccccccccccccccccccccc',
  twimlAppSid: 'APaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  identity: 'browser-user',
};

const CLOCK_SKEW_TOLERANCE_SECONDS = 30;

/* ================= (A) app.js's exact minting path ================= */

function b64urlEncode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return Buffer.from(bin, 'binary').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomHex(numBytes) {
  const bytes = new Uint8Array(numBytes);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function mintAccessTokenBrowser(creds, ttlSeconds = 3600) {
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
    'raw', enc.encode(creds.apiSecret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(signingInput));
  return `${signingInput}.${b64urlEncode(new Uint8Array(sig))}`;
}

/* ================= (B) official twilio npm SDK ================= */

function mintAccessTokenOfficial(creds, ttlSeconds = 3600) {
  const AccessToken = twilio.jwt.AccessToken;
  const token = new AccessToken(
    creds.accountSid, creds.apiKeySid, creds.apiSecret,
    { identity: creds.identity, ttl: ttlSeconds }
  );
  const VoiceGrant = twilio.jwt.AccessToken.VoiceGrant;
  const grant = new VoiceGrant({
    outgoingApplicationSid: creds.twimlAppSid,
    incomingAllow: true,
  });
  token.addGrant(grant);
  return token.toJwt();
}

/* ================= compare ================= */

function decode(token) {
  const [h, p, s] = token.split('.');
  return {
    header: JSON.parse(Buffer.from(h, 'base64url').toString('utf8')),
    payload: JSON.parse(Buffer.from(p, 'base64url').toString('utf8')),
    sigBytes: Buffer.from(s, 'base64url').length,
  };
}

function sortKeys(obj) {
  return Object.keys(obj).sort().reduce((acc, k) => { acc[k] = obj[k]; return acc; }, {});
}

const browserToken = await mintAccessTokenBrowser(creds);
const officialToken = mintAccessTokenOfficial(creds);

const a = decode(browserToken);
const b = decode(officialToken);

console.log('=== (A) app.js / browser-minted token ===');
console.log(browserToken);
console.log(JSON.stringify(a.header), JSON.stringify(a.payload));
console.log();
console.log('=== (B) official twilio SDK token ===');
console.log(officialToken);
console.log(JSON.stringify(b.header), JSON.stringify(b.payload));
console.log();

let diffs = 0;
function diff(name, aVal, bVal) {
  const same = JSON.stringify(aVal) === JSON.stringify(bVal);
  console.log(`${same ? 'SAME' : 'DIFF'}  ${name}`);
  if (!same) {
    diffs += 1;
    console.log(`      app.js : ${JSON.stringify(aVal)}`);
    console.log(`      SDK    : ${JSON.stringify(bVal)}`);
  }
}

diff('header (order-insensitive)', sortKeys(a.header), sortKeys(b.header));
diff('iss', a.payload.iss, b.payload.iss);
diff('sub', a.payload.sub, b.payload.sub);
diff('jti (prefix check)', a.payload.jti.split('-').slice(0, -1).join('-'), b.payload.jti.split('-').slice(0, -1).join('-'));
diff('grants', a.payload.grants, b.payload.grants);
diff('grants.voice (key names)', Object.keys(a.payload.grants.voice).sort(), Object.keys(b.payload.grants.voice).sort());
diff('grants.voice.outgoing (key names)', Object.keys(a.payload.grants.voice.outgoing || {}).sort(), Object.keys(b.payload.grants.voice.outgoing || {}).sort());
diff('iat/exp are numeric', [a.payload.iat, a.payload.exp].every(Number.isInteger), [b.payload.iat, b.payload.exp].every(Number.isInteger));
diff('nbf (optional — SDK omits it)', typeof a.payload.nbf === 'number' || a.payload.nbf === undefined, typeof b.payload.nbf === 'number' || b.payload.nbf === undefined);
diff('signature length (bytes)', a.sigBytes, b.sigBytes);

// Cross-verify: can jsonwebtoken verify the OFFICIAL token with the same secret?
const { default: jwt } = await import('jsonwebtoken');
try {
  jwt.verify(officialToken, creds.apiSecret, { algorithms: ['HS256'] });
  console.log('SAME  official SDK token verifies with API Secret as HMAC key');
} catch (e) {
  diffs += 1;
  console.log(`DIFF  official SDK token FAILED jsonwebtoken.verify: ${e.message}`);
}

console.log();
console.log(diffs === 0
  ? 'RESULT: app.js token is structurally IDENTICAL to the official SDK token.'
  : `RESULT: ${diffs} structural difference(s) found — see DIFF lines above.`);
process.exit(diffs === 0 ? 0 : 1);
