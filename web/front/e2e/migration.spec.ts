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
  await page.getByRole('link', { name: 'Endpoints e agentes', exact: true }).click();
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
  await page.getByRole('button', { name: 'Detalhes de <script>alert(1)</script>.txt', exact: true }).click();
  const detalhes = page.getByRole('region', { name: 'Detalhes de <script>alert(1)</script>.txt', exact: true });
  await expect(detalhes).toContainText('editor.exe');
  await expect(detalhes).toContainText('C:\\SafeUpload');
  await expect(detalhes).toContainText('42');
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

test('justificativa recebida pelo Java aparece nos detalhes e não duplica no reenvio', async ({ page, request }) => {
  const event = {
    eventId: crypto.randomUUID(), occurredAtUtc: new Date().toISOString(), endpointId: 'E2E-JUSTIFICATIVA',
    userName: 'teste', fileName: 'justificado.txt', extension: '.txt', sizeBytes: 12, verdict: 'Blocked',
    categories: ['Cpf'], maskedSnippets: [], processName: 'editor.exe', processId: 42,
    destinationPath: 'C:\\SafeUpload', policyVersion: 1, elapsedMs: 5, dispatched: false
  };
  const override = { eventId: event.eventId, justification: 'Solicitação autorizada <b>texto literal</b>',
    occurredAtUtc: new Date().toISOString(), userName: 'S-1-5-21-1001', endpointId: event.endpointId };
  for (const attempt of [1, 2]) {
    const response = await request.post('http://127.0.0.1:8080/agent/events', {
      data: { events: [event], overrides: [override] }
    });
    expect(response.ok(), `Envio ${attempt}`).toBeTruthy();
    expect((await response.json()).acceptedOverrides).toBe(1);
  }
  await page.goto('/login');
  await page.getByLabel('E-mail').fill(email);
  await page.getByLabel('Senha', { exact: true }).fill(password);
  await page.getByRole('button', { name: /entrar/i }).click();
  await expect(page).toHaveURL(/\/painel$/);
  await page.goto('/auditoria?endpoint=' + event.endpointId);
  await expect(page.getByText('Total 1', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Detalhes de justificado.txt', exact: true }).click();
  const details = page.getByRole('region', { name: 'Justificativas do evento', exact: true });
  await expect(details.getByText(override.justification, { exact: true })).toHaveCount(1);
  await expect(details).toContainText(override.userName);
  await expect(details.locator('b')).toHaveCount(0);
});

test('clipboard recebido pelo Java aparece no navegador sem duplicar no reenvio', async ({ page, request }) => {
  const clipboard = {
    eventId: crypto.randomUUID(), occurredAtUtc: new Date().toISOString(), endpointId,
    userName: 'teste', fileName: '', extension: '', sizeBytes: 14, verdict: 'Blocked', channel: 'Clipboard',
    categories: ['Cpf'], maskedSnippets: ['TRECHO_CLIPBOARD_NAO_EXIBIR'], processName: 'EXCEL.EXE',
    processId: 42, destinationPath: 'chrome.exe', notInspectedReason: null, policyVersion: 1,
    elapsedMs: 3, dispatched: false
  };
  for (const tentativa of [1, 2]) {
    const response = await request.post('http://127.0.0.1:8080/agent/events', { data: { events: [clipboard] } });
    expect(response.ok(), `Envio ${tentativa}`).toBeTruthy();
    expect((await response.json()).acceptedEvents).toBe(1);
  }
  await page.goto('/login');
  await page.getByLabel('E-mail').fill(email);
  await page.getByLabel('Senha', { exact: true }).fill(password);
  await page.getByRole('button', { name: /entrar/i }).click();
  await expect(page.getByRole('cell', { name: 'Área de transferência', exact: true })).toHaveCount(1);
  await page.goto('/auditoria?endpoint=' + endpointId);
  await expect(page.getByText('Total 4', { exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Área de transferência', exact: true })).toHaveCount(1);
  await page.getByRole('button', { name: 'Detalhes de Colagem', exact: true }).click();
  const detalhes = page.getByRole('region', { name: 'Detalhes de Colagem', exact: true });
  await expect(detalhes).toContainText(clipboard.eventId);
  await expect(detalhes).toContainText('EXCEL.EXE');
  await expect(detalhes).toContainText('chrome.exe');
  await expect(detalhes.getByText('Extensão', { exact: true })).toHaveCount(0);
  await expect(page.getByText('TRECHO_CLIPBOARD_NAO_EXIBIR')).toHaveCount(0);
});

test('política publicada pelo painel chega ao endpoint correto e informa recebimento pendente', async ({ page, request }, testInfo) => {
  const api = 'http://127.0.0.1:8080';
  expect((await request.post(api + '/agent/heartbeat', { data: {
    endpointId: 'E2E-POLITICA', hostname: 'Computador de política', os: 'Windows 11', agentVersion: '1.0', policyVersion: 1
  } })).ok()).toBeTruthy();
  await page.goto('/login');
  await page.getByLabel('E-mail').fill(email);
  await page.getByLabel('Senha', { exact: true }).fill(password);
  await page.getByRole('button', { name: /entrar/i }).click();
  await expect(page).toHaveURL(/painel/);
  await page.goto('/politicas');
  await page.getByLabel('Nome da política').fill('Proteção integrada');
  await page.getByLabel('Computador que receberá a política').selectOption('E2E-POLITICA');
  await expect(page.locator('.rule').filter({ hasText: 'Dados de saúde' }).locator('input')).toBeDisabled();
  await page.locator('.rule').filter({ has: page.getByText('CNPJ', { exact: true }) }).click();
  await expect(page.getByRole('radio', { name: /Alertar/ })).toBeDisabled();
  await page.getByRole('button', { name: 'Publicar política' }).click();
  await expect(page.getByRole('heading', { name: 'Política publicada — versão 2' })).toBeVisible();
  await expect(page.getByText(/O agente consultará a política na próxima atualização/)).toBeVisible();
  const policy = await (await request.get(api + '/agent/policy?endpointId=E2E-POLITICA')).json();
  expect(policy.version).toBe(2);
  expect(policy.activeCategories).toEqual(['Cnpj']);
  expect(policy.auditOnly).toBe(false);
  const other = await (await request.get(api + '/agent/policy?endpointId=OUTRO')).json();
  expect(other.version).toBe(1);
  await page.getByRole('radio', { name: /Bloquear/ }).check();
  await page.getByRole('button', { name: 'Publicar política' }).click();
  await expect(page.getByRole('heading', { name: 'Política publicada — versão 3' })).toBeVisible();
  expect((await (await request.get(api + '/agent/policy?endpointId=E2E-POLITICA')).json()).auditOnly).toBe(false);
  await page.reload();
  const saved = page.getByRole('region', { name: 'Políticas salvas no servidor' });
  await expect(saved).toContainText('Proteção integrada');
  await expect(saved).toContainText('Publicada: v3');
  await expect(saved).toContainText('Versão informada pelo agente: 1');
  await page.screenshot({ path: testInfo.outputPath('politicas-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: testInfo.outputPath('politicas-mobile.png'), fullPage: true });
});
