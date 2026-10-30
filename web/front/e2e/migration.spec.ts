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
  await page.getByLabel('Data de nascimento').fill('1990-01-01');
  await page.getByLabel('Razão social').fill('Empresa Sintetica E2E');
  await page.getByLabel('Nome fantasia').fill('Teste E2E');
  await page.getByLabel('CNPJ (14 dígitos)').fill('11222333000181');
  await page.getByLabel('E-mail de contato').fill('empresa-e2e@example.com');
  await page.getByLabel('Telefone de contato').fill('61999999999');
  for (const suffix of ['Empresa', 'Usuario']) {
    await page.locator('#cep' + suffix).fill('70000-000');
    await page.locator('#logradouro' + suffix).fill('Rua Sintetica');
    await page.locator('#numero' + suffix).fill('1');
    await page.locator('#bairro' + suffix).fill('Teste');
    await page.locator('#cidade' + suffix).fill('Brasilia');
    await page.locator('#estado' + suffix).fill('DF');
  }
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
  const registration = await request.post(api + '/agent/synchronize', { data: {
    host: { ip: '10.90.0.31', mascara: 24, hostname: endpointId, sistema_operacional: 'Windows', versao_so: '11 Pro' },
    usuarioSo: { sid: 'S-E2E-FINANCEIRO', usuario_so: 'teste', dominio: 'SYNTHETIC', admin: 0 }
  } });
  expect(registration.status()).toBe(201);
  const { id_host } = await registration.json();
  expect((await request.post(api + '/agent/heartbeat', { data: {
    id_host
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

test('política da console é persistida pelo IP correto; nova publicação não altera o controle', async ({ page, request }, testInfo) => {
  const api = 'http://127.0.0.1:8080';
  const hosts: Record<string, number> = {};
  for (const [name, ip] of [['E2E-POLITICA', '10.90.0.41'], ['E2E-CONTROLE', '10.90.0.42']]) {
    const registered = await request.post(api + '/agent/synchronize', { data: {
      host: { ip, mascara: 24, hostname: name, sistema_operacional: 'Windows', versao_so: '11' },
      usuarioSo: { sid: 'S-TEST-' + name, usuario_so: 'teste', dominio: 'SYNTHETIC', admin: 0 }
    } });
    expect(registered.status()).toBe(201);
    hosts[ip] = (await registered.json()).id_host;
  }
  await page.goto('/login');
  await page.getByLabel('E-mail').fill(email);
  await page.getByLabel('Senha', { exact: true }).fill(password);
  await page.getByRole('button', { name: /entrar/i }).click();
  await expect(page).toHaveURL(/painel/);
  await page.goto('/politicas');
  await page.getByLabel('Nome da política').fill('Proteção integrada');
  await page.getByLabel('IP da máquina').fill('10.90.0.41');
  await page.locator('.rule').filter({ has: page.getByText('CNPJ', { exact: true }) }).click();
  await page.getByRole('radio', { name: /Alertar/ }).check();
  const firstPublication = page.waitForResponse(r => r.url().endsWith('/api/politicas') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Enviar política' }).click();
  expect((await firstPublication).status()).toBe(201);
  await expect(page.locator('.json-result')).toBeVisible();
  const policy = await (await request.get(api + '/agent/api/policy?ip=10.90.0.41')).json();
  expect(policy.idPolitica).toBeGreaterThan(0);
  expect(policy.destino).toEqual({ idHost: hosts['10.90.0.41'], ip: '10.90.0.41' });
  expect(policy.regras).toEqual([{ tipo: 'cnpj', nome: 'CNPJ' }]);
  expect(policy.acao).toBe('alertar');
  expect((await request.get(api + '/agent/api/policy?ip=10.90.0.42')).status()).toBe(404);
  await page.getByRole('radio', { name: /Bloquear/ }).check();
  const secondPublication = page.waitForResponse(r => r.url().endsWith('/api/politicas') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Enviar política' }).click();
  expect((await secondPublication).status()).toBe(201);
  await expect(page.locator('.json-result')).toBeVisible();
  const second = await (await request.get(api + '/agent/api/policy?ip=10.90.0.41')).json();
  expect(second.idPolitica).toBeGreaterThan(policy.idPolitica);
  expect(second.acao).toBe('bloquear');
  expect(second.destino.idHost).toBe(hosts['10.90.0.41']);
  await page.reload();
  const persisted = await (await request.get(api + '/agent/api/policy?ip=10.90.0.41')).json();
  expect(persisted).toEqual(second);
  expect((await request.get(api + '/agent/api/policy?ip=10.90.0.42')).status()).toBe(404);
  await page.screenshot({ path: testInfo.outputPath('politicas-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: testInfo.outputPath('politicas-mobile.png'), fullPage: true });
});
