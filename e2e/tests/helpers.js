import { test as base, expect } from '@playwright/test';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Secrets come from the environment set by run-lab.sh (read on server-home
// from the lab's 0600 files); they are never printed.
export const env = {
  userPassword: required('E2E_USER_PASSWORD'),
  adminPassword: required('E2E_ADMIN_PASSWORD'),
  adminEnrollURL: required('E2E_ADMIN_ENROLL_URL'),
};

function required(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set (run through e2e/run-lab.sh)`);
  return v;
}

export const RP = 'http://localhost:5556';
export const SP = 'http://localhost:8000';
export const GRAFANA = 'http://localhost:3300';

// ---- state shared between spec files of one project run ----

function stateFile(info) {
  return path.join(path.dirname(new URL(import.meta.url).pathname), '..', '.auth', `state-${info.project.name}.json`);
}

export function loadState(info) {
  try {
    return JSON.parse(fs.readFileSync(stateFile(info), 'utf8'));
  } catch {
    return {};
  }
}

export function saveState(info, s) {
  fs.mkdirSync(path.dirname(stateFile(info)), { recursive: true, mode: 0o700 });
  fs.writeFileSync(stateFile(info), JSON.stringify(s), { mode: 0o600 });
}

// ---- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ----

function base32Decode(s) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out = [];
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    value = (value << 5) | alphabet.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function totpAt(secret, step) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const sum = crypto.createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const off = sum[sum.length - 1] & 0x0f;
  const v = sum.readUInt32BE(off) & 0x7fffffff;
  return String(v % 1_000_000).padStart(6, '0');
}

// freshCode returns a code for a step newer than the last one used (the
// idp refuses replays), waiting for the next step when needed.
export async function freshCode(info, secret) {
  const st = loadState(info);
  let step = Math.floor(Date.now() / 30_000);
  if (st.lastStep && step <= st.lastStep) {
    await new Promise((r) => setTimeout(r, (st.lastStep + 1) * 30_000 - Date.now() + 500));
    step = Math.floor(Date.now() / 30_000);
  }
  st.lastStep = step;
  saveState(info, st);
  return totpAt(secret, step);
}

// ---- screenshots and CSP ----

export async function shot(page, info, name) {
  const dir = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'screenshots', info.project.name);
  fs.mkdirSync(dir, { recursive: true });
  await page.screenshot({ path: path.join(dir, `${name}.png`), fullPage: true });
}

// test fails on any CSP violation reported by the browser.
export const test = base.extend({
  page: async ({ page }, use) => {
    const violations = [];
    page.on('console', (m) => {
      if (/Content Security Policy|Refused to/i.test(m.text())) violations.push(m.text());
    });
    await use(page);
    expect(violations, 'CSP violations').toEqual([]);
  },
});

export { expect };

export async function signIn(page, username, password) {
  await page.getByTestId('signin-input-username').fill(username);
  await page.getByTestId('signin-input-password').fill(password);
  await page.getByTestId('signin-btn-submit').click();
}
