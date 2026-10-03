import { test, expect, env, RP, shot, signIn } from './helpers.js';

test.describe.configure({ mode: 'serial' });

test('sign-in page in English and Portuguese, no scripts', async ({ page }, info) => {
  const res = await page.goto('/login');
  await expect(page.getByTestId('signin-input-username')).toBeVisible();
  expect(await page.locator('script').count()).toBe(0);
  const csp = res.headers()['content-security-policy'];
  expect(csp).toContain("script-src 'none'");
  expect(csp).toContain("frame-ancestors 'none'");
  await shot(page, info, '01-login');
  await page.getByTestId('footer-link-lang-pt-br').click();
  await expect(page.getByRole('heading', { name: 'Entrar' })).toBeVisible();
  await page.getByTestId('footer-link-theme-dark').click();
  await shot(page, info, '02-login-pt-br-dark');
  await page.getByTestId('footer-link-lang-en').click();
  await page.getByTestId('footer-link-theme-system').click();
});

test('example RP: consent, claims with nested groups, refresh rotation, logout', async ({ page }, info) => {
  await page.goto(RP + '/');
  await page.getByTestId('rp-link-login').click();
  await expect(page.getByTestId('flow-text-app')).toContainText('Example RP');
  await signIn(page, 'user0001', env.userPassword);
  await expect(page.getByTestId('consent-text-title')).toContainText('Example RP');
  await expect(page.getByTestId('consent-item-groups')).toBeVisible();
  await shot(page, info, '03-consent');
  await page.getByTestId('consent-btn-allow').click();
  await expect(page.getByTestId('rp-text-title')).toBeVisible();
  const claims = await page.getByTestId('rp-text-claims').innerText();
  expect(claims).toContain('"preferred_username": "user0001"');
  expect(claims).toContain('user0001@lab.conductor.test');
  // user0001 is a direct member of Engineering and Platform-Team; nesting
  // (Platform-Team -> Engineering-Leads -> Engineering -> All-Staff) adds
  // the rest, resolved by the DC (tokenGroups) and named by SID lookup.
  for (const g of ['Engineering', 'Platform-Team', 'Engineering-Leads', 'All-Staff', 'Domain Users']) expect(claims).toContain(`"${g}"`);
  expect(claims).toMatch(/"sub": "[0-9a-f-]{36}"/);
  await expect(page.getByTestId('rp-text-userinfo')).toContainText('user0001@lab.conductor.test');
  await expect(page.getByTestId('rp-text-refresh')).toHaveText('refresh ok, token rotated; reuse refused');
  await shot(page, info, '04-rp-claims');
  // RP-initiated logout with id_token_hint ends the idp session.
  await page.getByTestId('rp-link-logout').click();
  await expect(page.getByTestId('rp-text-bye')).toBeVisible();
  await page.goto(RP + '/login');
  await expect(page.getByTestId('signin-input-username')).toBeVisible();
});

test('single sign-on: a second sign-in needs no password, consent is remembered', async ({ page }) => {
  await page.goto(RP + '/login');
  await signIn(page, 'user0001', env.userPassword);
  await expect(page.getByTestId('rp-text-title')).toBeVisible();
  await page.goto(RP + '/login');
  await expect(page.getByTestId('rp-text-title')).toBeVisible();
});

test('a user outside the allowed groups is refused', async ({ page }, info) => {
  await page.goto(RP + '/login');
  await signIn(page, 'normal.user', env.userPassword);
  await expect(page.getByTestId('denied-card')).toBeVisible();
  await shot(page, info, '05-denied');
});

test('refusals: wrong password, locked, disabled, expired account', async ({ page }) => {
  await page.goto('/login');
  await signIn(page, 'user0004', 'wrong-password');
  await expect(page.getByTestId('form-text-error')).toContainText('Wrong username or password');
  await signIn(page, 'locked.user', env.userPassword);
  await expect(page.getByTestId('form-text-error')).toContainText('locked');
  await signIn(page, 'disabled.user', env.userPassword);
  await expect(page.getByTestId('form-text-error')).toContainText('disabled');
  await signIn(page, 'expired.account', env.userPassword);
  await expect(page.getByTestId('form-text-error')).toContainText('expired');
});

test('expired and must-change passwords go to a change page that needs the old password', async ({ page }, info) => {
  await page.goto('/login');
  await signIn(page, 'expired.password', env.userPassword);
  await expect(page.getByTestId('password-input-current')).toBeVisible();
  await page.getByTestId('password-btn-cancel').click();
  await page.goto('/login');
  await signIn(page, 'must.change', env.userPassword);
  await expect(page.getByTestId('password-input-current')).toBeVisible();
  await shot(page, info, '06-password-change');
  const next = 'Chg-' + Math.random().toString(36).slice(2, 10) + '-7Q';
  await page.getByTestId('password-input-current').fill('not-the-password');
  await page.getByTestId('password-input-new').fill(next);
  await page.getByTestId('password-input-confirm').fill(next);
  await page.getByTestId('password-btn-submit').click();
  await expect(page.getByTestId('form-text-error')).toContainText('current password is wrong');
  await page.getByTestId('password-input-current').fill(env.userPassword);
  await page.getByTestId('password-input-new').fill(next);
  await page.getByTestId('password-input-confirm').fill(next);
  await page.getByTestId('password-btn-submit').click();
  await expect(page.getByTestId('signin-text-notice')).toContainText('Password changed');
  await signIn(page, 'must.change', next);
  await expect(page.getByTestId('home-text-username')).toHaveText('must.change');
});
