import { expect, test } from '@playwright/test';
import { preencherPolitica } from './support/politica';

test('envia a política ao backend e permite baixar uma cópia do JSON', async ({ page }) => {
  await page.route('**/api/auth/me', r => r.fulfill({ json: { idUsuario: 1, nomeCompleto: 'Teste Admin', role: 'admin' } }));
  let payload: Record<string, unknown> | undefined;
  await page.route('**/api/politicas', async r => {
    payload = r.request().postDataJSON();
    await r.fulfill({ status: 201, json: { status: 'CREATED', mensagem: 'Política salva com sucesso.' } });
  });
  await preencherPolitica(page, 'Minha política', '192.168.1.20', 'RG', 'Alertar');
  await page.getByRole('button', { name: 'Publicar (demonstração)' }).click();
  await expect(page.getByRole('heading', { name: 'Política encaminhada ao servidor' })).toBeVisible();
  expect(payload).toMatchObject({
    destino: { ip: '192.168.1.20' },
    acao: 'alertar',
    regras: [{ tipo: 'rg', nome: 'RG' }]
  });
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Baixar cópia JSON' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('politica-safeupload.json');
  await expect(page.locator('.published-card pre')).toContainText('"ip": "192.168.1.20"');
  await expect(page.locator('.published-card pre')).toContainText('"acao": "alertar"');
  await expect(page.locator('.published-card pre')).toContainText('"tipo": "rg"');
});

test('combinação E indisponível não promete uma condição que a publicação ignora', async ({ page }) => {
  await page.route('**/api/auth/me', r => r.fulfill({ json: { idUsuario: 1, nomeCompleto: 'Teste Admin', role: 'admin' } }));
  await page.goto('/politicas');
  await page.getByLabel('Nome da política').fill('Condições suportadas');
  await page.getByRole('button', { name: 'Continuar' }).click();
  await page.getByLabel('Endpoint no escopo').fill('192.168.1.20');
  await page.getByRole('button', { name: 'Continuar' }).click();
  for (const categoria of ['CPF', 'CNPJ']) {
    await page.locator('.rule-card').filter({ has: page.getByText(categoria, { exact: true }) }).click();
  }
  await expect(page.getByRole('button', { name: 'Todos juntos (E)' })).toBeDisabled();
  await expect(page.locator('#condition-support')).toBeVisible();
  await expect(page.locator('.condition-readout')).toContainText('CPF ou CNPJ');
});
