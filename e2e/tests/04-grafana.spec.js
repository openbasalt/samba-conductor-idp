import { test, expect, env, GRAFANA, shot, signIn } from './helpers.js';

// Grafana's generic OAuth (with PKCE) as an unmodified third-party RP.
test('Grafana signs in through conductor-idp', async ({ page }, info) => {
  await page.goto(GRAFANA + '/login');
  await page.getByText('Sign in with Samba Conductor').click();
  await signIn(page, 'user0011', env.userPassword);
  await page.waitForURL(GRAFANA + '/**');
  const me = await page.request.get(GRAFANA + '/api/user');
  expect(me.ok()).toBeTruthy();
  const u = await me.json();
  expect(u.login).toBe('user0011');
  expect(u.email).toBe('user0011@lab.conductor.test');
  await shot(page, info, '18-grafana');
});
