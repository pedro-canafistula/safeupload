import { expect, test } from '@playwright/test';

test('envia a política ao backend e permite baixar uma cópia do JSON', async ({ page }) => {
  await page.route('**/api/auth/me', r => r.fulfill({ json: { idUsuario: 1, nomeCompleto: 'Teste Admin', role: 'admin' } }));
  let payload: Record<string, unknown> | undefined;
  await page.route('**/api/politicas', async r => {
    payload = r.request().postDataJSON();
    await r.fulfill({ status: 201, json: { status: 'CREATED', mensagem: 'Política salva com sucesso.' } });
  });
  await page.goto('/politicas');
  await page.getByLabel('Nome da política').fill('Minha política');
  await page.getByLabel('IP da máquina').fill('192.168.1.20');
  await page.locator('input[name="acao"][value="alertar"]').check();
  await page.locator('.rule').filter({ has: page.getByText('RG', { exact: true }) }).click();
  await page.getByRole('button', { name: 'Enviar política' }).click();
  await expect(page.getByRole('heading', { name: 'Política enviada' })).toBeVisible();
  expect(payload).toMatchObject({
    destino: { ip: '192.168.1.20' },
    acao: 'alertar',
    regras: [{ tipo: 'rg', nome: 'RG' }]
  });
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Baixar cópia JSON' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('politica-safeupload.json');
  await expect(page.locator('.json-result pre')).toContainText('"ip": "192.168.1.20"');
  await expect(page.locator('.json-result pre')).toContainText('"acao": "alertar"');
  await expect(page.locator('.json-result pre')).toContainText('"tipo": "rg"');
});
