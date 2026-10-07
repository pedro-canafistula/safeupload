import { expect, test } from '@playwright/test';

const resumo = { total: 3, bloqueados: 1, aprovados: 1, liberadosSemInspecao: 1 };
const eventos = ['Blocked', 'Approved', 'AllowedWithoutInspection'].map((verdict, index) => ({
  eventId: `evento-${index}`, occurredAtUtc: '2026-10-04T12:00:00Z', endpointId: 'ESTACAO-TESTE',
  userName: 'usuario-teste', fileName: `arquivo-${index}.txt`, extension: '.txt', sizeBytes: 128,
  verdict, categories: index === 0 ? ['Cpf', 'Secret'] : [], processName: '<script>origem</script>',
  processId: 0, destinationPath: 'C:\\destino\\' + 'pasta-longa-'.repeat(40), policyVersion: 2,
  elapsedMs: 0, notInspectedReason: null, maskedSnippets: ['TRECHO_QUE_NAO_DEVE_APARECER']
}));

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
