#!/usr/bin/env node
/**
 * verify-token.mjs — reproduces EXACTLY the token app.js mints in the browser
 * (same header, same payload shape, same base64url encoding, same HMAC-SHA256
 * via Web Crypto) and then validates it with the `jsonwebtoken` library, which
 * is what Twilio's server-side validator is modelled on.
 *
 * Usage:
 *   node scripts/verify-token.mjs [accountSid apiKeySid apiSecret twimlAppSid identity]
 *
 * With no args it uses placeholder credentials (ACxx…/SKxx…/APxx…), which is
 * enough to prove the token is structurally valid and correctly signed.
 */

import { webcrypto as crypto } from 'node:crypto';

/* ---------- placeholder credentials (edit or pass as argv) ---------- */
const args = process.argv.slice(2);
const creds = {
  accountSid:  args[0] || 'ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  apiKeySid:   args[1] || 'SKbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  apiSecret:   args[2] || 'Cccccccccccccccccccccccccccccccccccccccc', // 40 chars
  twimlAppSid: args[3] || 'APdddddddddddddddddddddddddddddddd',
  identity:    args[4] || 'browser-user',
};

/* ---------- mirror of app.js ---------- */
const CLOCK_SKEW_TOLERANCE_SECONDS = 30;

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

/* ---------- validate with jsonwebtoken ---------- */
const { default: jwt } = await import('jsonwebtoken');

const token = await mintAccessToken(creds);

console.log('=== Minted token (browser-equivalent, Web Crypto HS256) ===');
console.log(token);
console.log();

const parts = token.split('.');
const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

console.log('=== Decoded header ===');
console.log(JSON.stringify(header, null, 2));
console.log('=== Decoded payload ===');
console.log(JSON.stringify(payload, null, 2));
console.log();

let failures = 0;
function check(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures += 1;
}

check('header.alg === "HS256"', header.alg === 'HS256');
check('header.typ === "JWT"', header.typ === 'JWT');
check('header.cty === "twilio-fpa;v=1"', header.cty === 'twilio-fpa;v=1', JSON.stringify(header.cty));
check('iss is API Key SID (SK…) — Twilio resolves the signing key from iss', /^SK[0-9a-f]{32}$/.test(payload.iss), payload.iss);
check('sub is Account SID (AC…)', /^AC[0-9a-f]{32}$/.test(payload.sub), payload.sub);
check('jti is "<apiKeySid>-<iat>" (official SDK format)', payload.jti === `${payload.iss}-${payload.iat}`, payload.jti);
check('exp is numeric epoch seconds', Number.isInteger(payload.exp), String(payload.exp));
check('iat is numeric epoch seconds', Number.isInteger(payload.iat), String(payload.iat));
check('nbf is numeric epoch seconds', Number.isInteger(payload.nbf), String(payload.nbf));
check('exp > iat', payload.exp > payload.iat);
check('grants.identity present', typeof payload.grants?.identity === 'string' && payload.grants.identity.length > 0, payload.grants?.identity);
check('grants.voice.incoming.allow === true', payload.grants?.voice?.incoming?.allow === true);
check('grants.voice.outgoing.application_sid is TwiML App SID (AP…)',
  /^AP[0-9a-f]{32}$/.test(payload.grants?.voice?.outgoing?.application_sid || ''),
  payload.grants?.voice?.outgoing?.application_sid);
check('no stray "app_sid" key (common bug)', !('app_sid' in (payload.grants?.voice?.outgoing || {})));

console.log();
console.log('=== jsonwebtoken.verify (HS256, API Secret as key) ===');
try {
  const verified = jwt.verify(token, creds.apiSecret, { algorithms: ['HS256'] });
  console.log('PASS  signature valid & claims accepted by jsonwebtoken');
  check('verified iss matches API Key SID', verified.iss === creds.apiKeySid);
  check('verified sub matches Account SID', verified.sub === creds.accountSid);
  check('verified grants intact', JSON.stringify(verified.grants) === JSON.stringify(payload.grants));
} catch (err) {
  check('jsonwebtoken.verify', false, err.message);
  failures += 1;
}

// Negative control: a token signed with the WRONG key must fail — proves the
// validator is actually checking the signature, not rubber-stamping it.
console.log();
console.log('=== Negative control (tampered signature must be rejected) ===');
const tampered = token.slice(0, -4) + (token.endsWith('AAAA') ? 'BBBB' : 'AAAA');
try {
  jwt.verify(tampered, creds.apiSecret, { algorithms: ['HS256'] });
  check('tampered token rejected', false, 'jsonwebtoken ACCEPTED a tampered token!');
  failures += 1;
} catch {
  check('tampered token rejected', true);
}

console.log();
if (failures === 0) {
  console.log('RESULT: token minting is structurally valid and correctly signed.');
} else {
  console.log(`RESULT: ${failures} check(s) FAILED — see above.`);
  process.exit(1);
}
