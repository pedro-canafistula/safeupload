import { expect, test } from '@playwright/test';

test.describe.configure({ mode: 'serial' });
const email = 'migration-e2e@example.com';
const password = 'migration-e2e-123';
const endpointId = 'E2E-FINANCEIRO';

test('cadastro, login e estado vazio sem indicadores fictícios', async ({ page }) => {
  await page.goto('/cadastro');
  await page.getByLabel('Nome completo').fill('Teste Migração');
  await page.getByLabel('Nome de usuário').fill('migration-e2e');
  await page.getByLabel('E-mail').fill(email);
  await page.getByLabel('CPF').fill('52998224725');
  await page.getByLabel('Senha', { exact: true }).fill(password);
  await page.getByLabel('Confirmar senha').fill(password);
  await page.getByRole('button', { name: /cadastrar|criar conta/i }).click();
  await expect(page).toHaveURL(/login/);
  await page.getByLabel('E-mail').fill(email);
  await page.getByLabel('Senha', { exact: true }).fill(password);
  await page.getByRole('button', { name: /entrar/i }).click();
  await expect(page.getByRole('heading', { name: 'Visão geral' })).toBeVisible();
  await expect(page.getByText('Nenhuma inspeção recebida para esta consulta.')).toBeVisible();
  await expect(page.getByText('1.247', { exact: true })).toHaveCount(0);
  await page.reload();
  await expect(page.getByText('Teste Migração')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Visão geral' })).toBeVisible();
});

test('heartbeat e três eventos reais aparecem no painel, endpoints e auditoria', async ({ page, request }) => {
  const api = 'http://127.0.0.1:8080';
  expect((await request.post(api + '/agent/heartbeat', { data: {
    endpointId, hostname: endpointId, os: 'Windows 11 Pro', agentVersion: '1.0.0', policyVersion: 1
  } })).ok()).toBeTruthy();
  const events = ['Blocked', 'Approved', 'AllowedWithoutInspection'].map((verdict, index) => ({
    eventId: crypto.randomUUID(), occurredAtUtc: new Date(Date.now() - index * 1000).toISOString(),
    endpointId, userName: 'teste', fileName: index === 0 ? '<script>alert(1)</script>.txt' : 'arquivo-' + index + '.txt',
    extension: '.txt', sizeBytes: 128, verdict, categories: index === 0 ? ['Cpf', 'Secret'] : [],
    maskedSnippets: [], processName: 'editor.exe', processId: 42, destinationPath: 'C:\\SafeUpload',
    notInspectedReason: index === 2 ? 'inspection_timeout' : null, policyVersion: 1, elapsedMs: 5, dispatched: false
  }));
  expect((await request.post(api + '/agent/events', { data: { events } })).ok()).toBeTruthy();
  expect((await request.post(api + '/agent/events', { data: { events } })).ok()).toBeTruthy();
  await page.goto('/login');
  await page.getByLabel('E-mail').fill(email);
  await page.getByLabel('Senha', { exact: true }).fill(password);
  await page.getByRole('button', { name: /entrar/i }).click();
  const inspections = page.locator('.metrics section').filter({ has: page.getByRole('heading', { name: 'Inspeções', exact: true }) });
  await expect(inspections.locator('strong')).toHaveText('3');
  await page.getByRole('link', { name: 'Endpoints', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'Online', exact: true })).toBeVisible();
  await page.getByLabel('Buscar máquina').fill('INEXISTENTE');
  await page.getByRole('button', { name: 'Aplicar', exact: true }).click();
  await expect(page.getByText('Nenhum endpoint corresponde aos filtros.')).toBeVisible();
  await page.getByRole('link', { name: 'Limpar', exact: true }).click();
  await page.getByRole('link', { name: 'Ver auditoria' }).click();
  await expect(page).toHaveURL(/endpoint=E2E-FINANCEIRO/);
  await expect(page.getByText('Total 3', { exact: true })).toBeVisible();
  await expect(page.getByText('inspection_timeout')).toBeVisible();
  await expect(page.getByRole('cell', { name: '<script>alert(1)</script>.txt', exact: true })).toBeVisible();
  await expect(page.locator('app-event-table script')).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
});

test('erros de API não são confundidos com estado vazio; atualização recupera a tela', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('E-mail').fill(email);
  await page.getByLabel('Senha', { exact: true }).fill(password);
  await page.route('**/api/painel', route => route.fulfill({ status: 503, body: '{}' }));
  await page.getByRole('button', { name: /entrar/i }).click();
  await expect(page.getByRole('alert')).toContainText('Não foi possível consultar');
  await expect(page.getByText('Nenhuma inspeção recebida para esta consulta.')).toHaveCount(0);
  await page.unroute('**/api/painel');
  await page.getByRole('button', { name: 'Atualizar' }).click();
  await expect(page.locator('.metrics')).toBeVisible();
  await page.getByRole('button', { name: 'Sair' }).click();
  await expect(page).toHaveURL(/login/);
  await page.goto('/auditoria');
  await expect(page).toHaveURL(/login/);
});
