import { expect, test } from '@playwright/test';

test('gera e baixa JSON com IP, ação e regras selecionadas', async ({ page }) => {
  await page.route('**/api/auth/me', r => r.fulfill({ json: { idUsuario: 1, nomeCompleto: 'Teste Admin', role: 'admin' } }));
  await page.goto('/politicas');
  await page.getByLabel('Nome da política').fill('Minha política');
  await page.getByLabel('IP da máquina').fill('192.168.1.20');
  await page.locator('input[name="acao"][value="alertar"]').check();
  await page.locator('.rule').filter({ has: page.getByText('RG', { exact: true }) }).click();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Gerar JSON da política' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('politica-safeupload.json');
  await expect(page.getByRole('heading', { name: 'JSON gerado e baixado' })).toBeVisible();
  await expect(page.locator('.json-result pre')).toContainText('"ip": "192.168.1.20"');
  await expect(page.locator('.json-result pre')).toContainText('"acao": "alertar"');
  await expect(page.locator('.json-result pre')).toContainText('"tipo": "rg"');
});
