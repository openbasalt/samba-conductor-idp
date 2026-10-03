import { test, expect, env, shot, signIn, freshCode, loadState, saveState } from './helpers.js';

test.describe.configure({ mode: 'serial' });

test('an administrator without 2FA needs the one-time link', async ({ page }) => {
  await page.goto('/login');
  await signIn(page, 'lab.admin', env.adminPassword);
  await expect(page.getByTestId('form-text-error')).toContainText('one-time link');
});

test('the administrator enrolls TOTP with the link and reaches the admin pages', async ({ page }, info) => {
  await page.goto(env.adminEnrollURL);
  await expect(page.getByTestId('signin-text-enroll')).toBeVisible();
  await signIn(page, 'lab.admin', env.adminPassword);
  await expect(page.getByTestId('enroll-img-qr')).toBeVisible();
  await shot(page, info, '07-enroll');
  const secret = (await page.getByTestId('enroll-text-secret').innerText()).trim();
  const st = loadState(info);
  st.adminSecret = secret;
  saveState(info, st);
  await page.getByTestId('enroll-input-code').fill(await freshCode(info, secret));
  await page.getByTestId('enroll-btn-submit').click();
  await expect(page.getByTestId('recovery-list-codes')).toBeVisible();
  await expect(page.getByTestId('recovery-text-code')).toHaveCount(10);
  await shot(page, info, '08-recovery-codes');
  await page.getByTestId('recovery-btn-continue').click();
  await page.getByTestId('home-link-admin').click();
  await expect(page.getByTestId('clients-table')).toContainText('Example RP');
  await shot(page, info, '09-admin-clients');
  await page.getByTestId('clients-link-example-rp').click();
  await expect(page.getByTestId('client-input-redirects')).toHaveValue('http://localhost:5556/callback');
  await shot(page, info, '10-admin-client');
  await page.getByTestId('admin-tab-saml').click();
  await expect(page.getByTestId('sps-text-metadata')).toContainText('/saml/metadata');
  await shot(page, info, '11-admin-saml');
  await page.getByTestId('admin-tab-keys').click();
  await expect(page.getByTestId('keys-row-oidc')).toBeVisible();
  await expect(page.getByTestId('keys-row-saml')).toBeVisible();
  await shot(page, info, '12-admin-keys');
  await page.getByTestId('admin-tab-audit').click();
  await expect(page.getByTestId('audit-text-chain-ok')).toBeVisible();
  await shot(page, info, '13-admin-audit');
});

test('a second sign-in asks for the code; an admin page creates a client', async ({ page }, info) => {
  const st = loadState(info);
  await page.goto('/login');
  await signIn(page, 'lab.admin', env.adminPassword);
  await expect(page.getByTestId('mfa-input-code')).toBeVisible();
  await shot(page, info, '14-2fa');
  await page.getByTestId('mfa-input-code').fill(await freshCode(info, st.adminSecret));
  await page.getByTestId('mfa-btn-submit').click();
  await page.goto('/admin/clients/new');
  await page.getByTestId('client-input-name').fill('E2E Temp');
  await page.getByTestId('client-input-redirects').fill('https://temp.example.test/cb');
  await page.getByTestId('client-input-groups').fill('Engineering');
  await page.getByTestId('client-btn-create').click();
  await expect(page.getByTestId('secret-text-secret')).toContainText('cidp_cs_');
  await shot(page, info, '15-client-secret');
  const id = (await page.getByTestId('secret-text-client-id').innerText()).trim();
  await page.getByTestId('secret-link-client').click();
  await page.getByTestId('client-input-confirm').fill(id);
  await page.getByTestId('client-btn-delete').click();
  await expect(page.getByTestId('flash-ok')).toBeVisible();
  await expect(page.getByTestId('clients-table')).not.toContainText('E2E Temp');
});
