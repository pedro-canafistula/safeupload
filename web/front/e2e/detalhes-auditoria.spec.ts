import { expect, test } from '@playwright/test';

const resumo = { total: 3, bloqueados: 1, aprovados: 1, liberadosSemInspecao: 1 };
const eventos = ['Blocked', 'Approved', 'AllowedWithoutInspection'].map((verdict, index) => ({
  eventId: `evento-${index}`, occurredAtUtc: '2026-10-04T12:00:00Z', endpointId: 'ESTACAO-TESTE',
  userName: 'usuario-teste', fileName: `arquivo-${index}.txt`, extension: '.txt', sizeBytes: 128,
  verdict, categories: index === 0 ? ['Cpf', 'Secret'] : [], processName: '<script>origem</script>',
  processId: 0, destinationPath: 'C:\\destino\\' + 'pasta-longa-'.repeat(40), policyVersion: 2,
  elapsedMs: 0, notInspectedReason: null, maskedSnippets: ['TRECHO_QUE_NAO_DEVE_APARECER']
}));

test('auditoria filtra eventos reais e exporta CSV sem fórmulas ou trechos sensíveis', async ({ page }) => {
  const clipboard = { ...eventos[0], eventId: 'clipboard-export', channel: 'Clipboard',
    userName: '=1+1', fileName: '', extension: '', verdict: 'AllowedWithoutInspection',
    notInspectedReason: 'clipboard_focus_observed' };
  await page.route('**/api/auditoria**', route => route.fulfill({ json: {
    resumo, eventos: [...eventos, clipboard], endpoint: 'ESTACAO-TESTE'
  } }));
  await page.goto('/auditoria?endpoint=ESTACAO-TESTE');
  await page.getByLabel('Canal', { exact: true }).selectOption('Clipboard');
  await page.getByLabel('Resultado', { exact: true }).selectOption('AllowedWithoutInspection');
  await page.getByLabel('Buscar evento, usuário ou arquivo').fill('clipboard-export');
  await expect(page.getByRole('cell', { name: 'Área de transferência', exact: true })).toHaveCount(1);
  await expect(page.getByRole('cell', { name: 'Arquivo', exact: true })).toHaveCount(0);
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Exportar CSV' }).click();
  const download = await downloadPromise;
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  const csv = Buffer.concat(chunks).toString('utf8');
  expect(csv).toContain('clipboard-export');
  expect(csv).toContain('"\'=1+1"');
  expect(csv).not.toContain('evento-1');
  expect(csv).not.toContain('TRECHO_QUE_NAO_DEVE_APARECER');
  await page.getByLabel('Canal', { exact: true }).selectOption('File');
  await expect(page.getByText('Nenhuma inspeção recebida para esta consulta.')).toBeVisible();
});

for (const tela of ['/auditoria?endpoint=ESTACAO-TESTE', '/painel']) {
  test(`clipboard e arquivos antigos são distinguidos em ${tela}`, async ({ page }) => {
    const clipboard = { ...eventos[0], eventId: 'clipboard-1', channel: 'Clipboard',
      fileName: '', extension: '', processName: 'EXCEL.EXE', destinationPath: '<script>chrome.exe</script>' };
    const mistos = [eventos[1], { ...eventos[2], channel: 'File' }, clipboard];
    await page.route('**/api/auditoria**', route => route.fulfill({ json: { resumo, eventos: mistos, endpoint: 'ESTACAO-TESTE' } }));
    await page.route('**/api/painel', route => route.fulfill({ json: {
      resumo, recentes: mistos, periodo: 'Últimos 7 dias', tendencia: [], categoriasBloqueadas: [], categoriasAtivas: []
    } }));
    await page.goto(tela);
    await expect(page.getByRole('cell', { name: 'Arquivo', exact: true })).toHaveCount(2);
    await expect(page.getByRole('cell', { name: 'Área de transferência', exact: true })).toHaveCount(1);
    const abrir = page.getByRole('button', { name: 'Detalhes de Colagem', exact: true });
    await abrir.focus();
    await page.keyboard.press('Enter');
    await expect(abrir).toHaveAttribute('aria-expanded', 'true');
    const detalhes = page.getByRole('region', { name: 'Detalhes de Colagem', exact: true });
    await expect(detalhes).toContainText('EXCEL.EXE');
    await expect(detalhes).toContainText('Revise o conteúdo copiado');
    await expect(detalhes.locator('div').filter({ has: page.getByText('Processo de destino', { exact: true }) }).locator('dd'))
      .toHaveText('<script>chrome.exe</script>');
    await expect(detalhes.getByText('Extensão', { exact: true })).toHaveCount(0);
    await expect(detalhes.getByText('Caminho de destino', { exact: true })).toHaveCount(0);
    await expect(page.locator('app-event-table script')).toHaveCount(0);
    await expect(page.getByText('TRECHO_QUE_NAO_DEVE_APARECER')).toHaveCount(0);
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    await page.getByRole('button', { name: 'Detalhes de arquivo-1.txt', exact: true }).click();
    await expect(detalhes).toHaveCount(0);
    await expect(page.getByRole('region', { name: 'Detalhes de arquivo-1.txt', exact: true }).getByText('Caminho de destino', { exact: true })).toBeVisible();
  });
}

test.beforeEach(async ({ page }) => {
  await page.route('**/api/auth/me', route => route.fulfill({ json: {
    idUsuario: 1, nomeCompleto: 'Administrador de teste', username: 'admin', email: 'admin@example.com', role: 'admin'
  } }));
  await page.route('**/api/auditoria**', route => route.fulfill({ json: { resumo, eventos, endpoint: 'ESTACAO-TESTE' } }));
  await page.route('**/api/painel', route => route.fulfill({ json: {
    resumo, recentes: eventos, periodo: 'Últimos 7 dias', tendencia: [], categoriasBloqueadas: [], categoriasAtivas: []
  } }));
});

test('detalhes preservam filtro, exibem metadados e não renderizam conteúdo sensível ou HTML', async ({ page }, testInfo) => {
  await page.goto('/auditoria?endpoint=ESTACAO-TESTE');
  const abrir = page.getByRole('button', { name: 'Detalhes de arquivo-0.txt' });
  await abrir.focus();
  await page.keyboard.press('Enter');
  await expect(abrir).toHaveAttribute('aria-expanded', 'true');
  const detalhes = page.getByRole('region', { name: 'Detalhes de arquivo-0.txt' });
  await expect(detalhes).toContainText('usuario-teste');
  await expect(detalhes).toContainText('<script>origem</script>');
  await expect(detalhes.locator('div').filter({ has: page.getByText('PID do processo', { exact: true }) }).locator('dd')).toHaveText('0');
  await expect(detalhes).toContainText('0 ms');
  await expect(detalhes).toContainText('A operação foi bloqueada');
  await expect(page.locator('app-event-table script')).toHaveCount(0);
  await expect(page.getByText('TRECHO_QUE_NAO_DEVE_APARECER')).toHaveCount(0);
  await expect(page).toHaveURL(/endpoint=ESTACAO-TESTE/);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await detalhes.screenshot({ path: testInfo.outputPath('detalhes-mobile.png') });
  await abrir.focus();
  await page.keyboard.press('Space');
  await expect(abrir).toHaveAttribute('aria-expanded', 'false');
  await expect(detalhes).toHaveCount(0);
});

test('painel distingue aprovação e liberação sem inspeção e abre um evento por vez', async ({ page }) => {
  await page.goto('/painel');
  await page.getByRole('button', { name: 'Detalhes de arquivo-1.txt' }).click();
  await expect(page.getByText(/Isso não garante ausência de risco/)).toBeVisible();
  await page.getByRole('button', { name: 'Detalhes de arquivo-2.txt' }).click();
  await expect(page.getByText(/Este resultado não equivale a uma aprovação/)).toBeVisible();
  await expect(page.getByText('Não informado pelo agente')).toBeVisible();
  await expect(page.getByRole('region', { name: 'Detalhes de arquivo-1.txt' })).toHaveCount(0);
});

test('metadados ausentes não viram valores inventados', async ({ page }) => {
  await page.route('**/api/auditoria**', route => route.fulfill({ json: {
    resumo, endpoint: '', eventos: [{ ...eventos[0], processName: '', processId: null,
      extension: null, destinationPath: '', policyVersion: null, elapsedMs: null }]
  } }));
  await page.goto('/auditoria');
  await page.getByRole('button', { name: 'Detalhes de arquivo-0.txt' }).click();
  const detalhes = page.getByRole('region', { name: 'Detalhes de arquivo-0.txt' });
  await expect(detalhes.locator('div').filter({ has: page.getByText('PID do processo', { exact: true }) }).locator('dd')).toHaveText('Não informado');
  await expect(detalhes.locator('div').filter({ has: page.getByText('Duração da inspeção', { exact: true }) }).locator('dd')).toHaveText('Não informada');
});

test('justificativa aparece somente no evento correspondente e é texto, sem executar HTML', async ({ page }) => {
  const justification = '<script>window.justificationExecuted=true</script> Transferência autorizada';
  await page.route('**/api/auditoria**', route => route.fulfill({ json: {
    resumo, eventos, endpoint: '', justificativas: [{ eventId: eventos[0].eventId, justification,
      occurredAtUtc: '2026-10-04T12:01:00Z', userName: 'S-1-5-21-1001', endpointId: 'ESTACAO-TESTE' }]
  } }));
  await page.goto('/auditoria');
  await page.getByRole('button', { name: 'Detalhes de arquivo-0.txt', exact: true }).click();
  const region = page.getByRole('region', { name: 'Justificativas do evento', exact: true });
  await expect(region).toContainText(justification);
  await expect(region).toContainText('S-1-5-21-1001');
  await expect(region).toContainText('não confirma que a transferência foi concluída');
  await expect(region.locator('script')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).justificationExecuted)).toBeUndefined();
  await page.getByRole('button', { name: 'Detalhes de arquivo-1.txt', exact: true }).click();
  await expect(region).toHaveCount(0);
});

test('observação de foco não é apresentada como colagem ou bloqueio confirmado', async ({ page }) => {
  await page.route('**/api/auditoria**', route => route.fulfill({ json: {
    resumo: { total: 1, bloqueados: 0, aprovados: 0, liberadosSemInspecao: 1 }, endpoint: '',
    eventos: [{ ...eventos[0], channel: 'Clipboard', fileName: '', extension: '',
      verdict: 'AllowedWithoutInspection', notInspectedReason: 'clipboard_focus_observed' }]
  } }));
  await page.goto('/auditoria');
  await expect(page.getByRole('cell', { name: 'Observação de clipboard', exact: true })).toBeVisible();
  await expect(page.getByText('Monitoramento', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Detalhes de Observação de clipboard', exact: true }).click();
  const detalhes = page.getByRole('region', { name: 'Detalhes de Observação de clipboard', exact: true });
  await expect(detalhes).toContainText('não confirma colagem nem bloqueio');
  await expect(detalhes).not.toContainText('A operação foi bloqueada');
  await expect(detalhes.locator('div').filter({ has: page.getByText('PID do processo', { exact: true }) }).locator('dd')).toHaveText('Não informado');
});

test('contrato atual distingue Web e retenção e preserva o hash publicado', async ({ page }) => {
  await page.route('**/api/auditoria**', route => route.fulfill({ json: {
    resumo: { total: 2, bloqueados: 1, aprovados: 0, liberadosSemInspecao: 0, retidos: 1 }, endpoint: '',
    eventos: [
      { ...eventos[0], channel: 'Web', fileName: '', extension: '', destinationPath: 'https://example.test/upload' },
      { ...eventos[1], channel: 'File', verdict: 'Retained', notInspectedReason: 'publication_failed', publishedSha256Hex: 'a'.repeat(64) }
    ]
  } }));
  await page.goto('/auditoria');
  await expect(page.getByText('Retidos 1', { exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Web', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Detalhes de Envio web', exact: true }).click();
  const web = page.getByRole('region', { name: 'Detalhes de Envio web', exact: true });
  await expect(web).toContainText('Endereço de destino');
  await expect(web).toContainText('https://example.test/upload');
  await expect(web.getByText('Extensão', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Detalhes de arquivo-1.txt', exact: true }).click();
  const retained = page.getByRole('region', { name: 'Detalhes de arquivo-1.txt', exact: true });
  await expect(retained).toContainText('Nenhum conteúdo foi liberado');
  await expect(retained).toContainText('publication_failed');
  await expect(retained).toContainText('a'.repeat(64));
  await expect(retained).not.toContainText('A operação foi liberada');
});
