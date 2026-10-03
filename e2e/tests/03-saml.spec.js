import { test, expect, env, SP, shot, signIn } from './helpers.js';

test.describe.configure({ mode: 'serial' });

test('SP-initiated SAML with an encrypted, signed assertion', async ({ page }, info) => {
  await page.goto(SP + '/');
  await expect(page.getByTestId('flow-text-app')).toContainText('Example SP');
  await signIn(page, 'user0006', env.userPassword);
  await expect(page.getByTestId('saml-btn-continue')).toBeVisible();
  await shot(page, info, '16-saml-continue');
  await page.getByTestId('saml-btn-continue').click();
  await expect(page.getByTestId('sp-text-title')).toBeVisible();
  await expect(page.getByTestId('sp-text-nameid')).toHaveText('user0006@lab.conductor.test');
  await expect(page.getByTestId('sp-attr-uid')).toContainText('user0006');
  await expect(page.getByTestId('sp-attr-memberOf')).toContainText('Engineering');
  await shot(page, info, '17-saml-sp');
});

test('IdP-initiated SAML from the start page', async ({ page }) => {
  await page.goto('/login');
  await signIn(page, 'user0006', env.userPassword);
  await page.getByTestId('home-btn-app-example-sp').click();
  await page.getByTestId('saml-btn-continue').click();
  await expect(page.getByTestId('sp-text-nameid')).toHaveText('user0006@lab.conductor.test');
});

test('SAML refuses a user outside the allowed groups', async ({ page }) => {
  await page.goto(SP + '/');
  await signIn(page, 'normal.user', env.userPassword);
  await expect(page.getByTestId('denied-card')).toBeVisible();
});
