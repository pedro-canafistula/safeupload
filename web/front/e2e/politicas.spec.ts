import { expect, test } from '@playwright/test';

test('falha ao publicar não apresenta sucesso nem permite baixar JSON', async ({ page }) => {
  await page.route('**/api/auth/me', r => r.fulfill({ json: { idUsuario: 1, nomeCompleto: 'Teste Admin', role: 'admin' } }));
  await page.route('**/api/endpoints*', r => r.fulfill({ json: { resumo: { total: 1, online: 1, offline: 0 }, itens: [
    { endpointId: 'PC-A', hostname: 'PC-A', policyVersion: 1, status: 'online' }
  ] } }));
  await page.route('**/api/politicas', r => r.fulfill(r.request().method() === 'GET'
    ? { json: [] } : { status: 503, json: { message: 'Servidor indisponível' } }));
  await page.goto('/politicas');
  await page.getByLabel('Nome da política').fill('Minha política');
  await page.getByLabel('Computador que receberá a política').selectOption('PC-A');
  await page.locator('.rule').filter({ has: page.getByText('CPF', { exact: true }) }).click();
  await page.getByRole('button', { name: 'Publicar política' }).click();
  await expect(page.getByRole('alert')).toHaveText('Servidor indisponível');
  await expect(page.getByRole('button', { name: 'Baixar JSON' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Publicar política' })).toBeEnabled();
});
