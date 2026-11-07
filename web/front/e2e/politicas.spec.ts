import { expect, test } from '@playwright/test';
import { administradorSimulado } from './support/sessao';

const configuracao = {
  categorias: { cpf: 'bloquear', cnpj: 'bloquear', rg: 'bloquear', cartao_credito: 'bloquear', dados_bancarios: 'bloquear',
    credenciais: 'bloquear', dados_saude: 'bloquear', dados_pessoais: 'bloquear', documentos_confidenciais: 'bloquear' },
  pastas: [], pendrives: true, rede: false, extensoes: ['.txt', '.csv', '.docx', '.xlsx', '.pdf', '.pptx', '.zip'],
  tamanhoMaximoMb: 100, tempoLimiteSegundos: 900, permitirJustificativa: false, clipboard: 'desligado'
};

test.beforeEach(async ({ page }) => {
  await page.route('**/api/auth/me', route => route.fulfill({ json: administradorSimulado }));
});

test('editor envia todos os campos da configuração no formato do backend', async ({ page }) => {
  let enviado: unknown;
  await page.route('**/api/politicas', route => {
    enviado = route.request().postDataJSON();
    return route.fulfill({ status: 201, json: { id: 7, versao: 12 } });
  });
  await page.route('**/api/politicas/7', route => route.fulfill({ json: {
    id: 7, nome: 'Financeiro', padrao: true, versao: 12, configuracao: (enviado as { configuracao: object }).configuracao,
    historico: [{ versao: 12, criadaEm: '2026-11-07T12:00:00Z', criadaPor: 'admin-teste' }]
  } }));
  await page.goto('/politicas/nova');
  await page.getByLabel('Nome da política').fill('  Financeiro  ');
  await page.getByLabel(/Política padrão da empresa/).check();
  await page.getByRole('group', { name: 'CPF', exact: true }).getByLabel('Alertar').check();
  await page.getByRole('group', { name: 'Credenciais e segredos', exact: true }).getByLabel('Ignorar').check();
  await page.getByLabel(/Pastas protegidas/).fill('C:\\Dados\\Financeiro\n\n  \\\\servidor\\publico  ');
  await page.getByLabel(/Proteger pendrives/).uncheck();
  await page.getByLabel(/Proteger compartilhamentos de rede/).check();
  await page.getByLabel(/Extensões inspecionadas/).fill('.txt, .pdf\n.xlsx;.zip');
  await page.getByLabel('Tamanho máximo (MB)').fill('250');
  await page.getByLabel('Tempo limite da inspeção (s)').fill('60');
  await page.getByLabel(/Permitir justificativa/).check();
  await page.getByLabel('Área de transferência (clipboard)').selectOption('alertar');
  await page.getByRole('button', { name: 'Criar política' }).click();
  await expect(page).toHaveURL(/\/politicas\/7$/);
  await expect(page.getByText('Política criada (versão 12).')).toBeVisible();
  expect(enviado).toEqual({
    nome: 'Financeiro', padrao: true,
    configuracao: { ...configuracao, categorias: { ...configuracao.categorias, cpf: 'alertar', credenciais: 'ignorar' },
      pastas: ['C:\\Dados\\Financeiro', '\\\\servidor\\publico'], pendrives: false, rede: true,
      extensoes: ['.txt', '.pdf', '.xlsx', '.zip'], tamanhoMaximoMb: 250, tempoLimiteSegundos: 60,
      permitirJustificativa: true, clipboard: 'alertar' }
  });
  await expect(page.getByRole('table', { name: 'Versões da política' })).toContainText('admin-teste');
  await expect(page.getByLabel('Nome da política')).toHaveValue('Financeiro');
});

test('editor não envia política em que todas as categorias são ignoradas', async ({ page }) => {
  let enviou = false;
  await page.route('**/api/politicas', route => { enviou = true; return route.fulfill({ status: 201, json: { id: 1, versao: 1 } }); });
  await page.goto('/politicas/nova');
  await page.getByLabel('Nome da política').fill('Nada');
  for (const grupo of await page.locator('.category-row').all()) await grupo.getByLabel('Ignorar').check();
  await page.getByRole('button', { name: 'Criar política' }).click();
  await expect(page.getByRole('alert')).toHaveText('Pelo menos uma categoria precisa bloquear ou alertar.');
  expect(enviou).toBe(false);
});

test('lista mostra a padrão, os grupos e a recusa do servidor ao excluir', async ({ page }, testInfo) => {
  await page.route('**/api/politicas', route => route.fulfill({ json: [
    { id: 1, nome: 'Padrão', padrao: true, versao: 3, atualizadaEm: '2026-11-07T12:00:00Z', atualizadaPor: 'admin-teste', grupos: [], hosts: 4 },
    { id: 2, nome: 'Financeiro', padrao: false, versao: 5, atualizadaEm: '2026-11-07T13:00:00Z', atualizadaPor: 'admin-teste', grupos: ['Contas'], hosts: 2 }
  ] }));
  await page.route('**/api/grupos', route => route.fulfill({ json: [
    { id: 9, nome: 'Contas', politicaId: 2, politica: 'Financeiro', hosts: 2 },
    { id: 10, nome: 'Recepção', politicaId: null, politica: null, hosts: 0 }
  ] }));
  await page.route('**/api/politicas/2', route => route.fulfill({ status: 409,
    json: { status: 409, erro: 'ERRO_REQUISICAO', mensagem: 'Há grupos usando esta política.' } }));
  await page.goto('/politicas');
  const politicas = page.getByRole('table', { name: 'Políticas da empresa' });
  await expect(politicas.getByRole('row').filter({ hasText: 'Padrão' }).first()).toContainText('v3');
  await expect(politicas.locator('.badge')).toHaveCount(1);
  await expect(politicas.getByRole('row').filter({ hasText: 'Financeiro' })).toContainText('Contas');
  await expect(page.getByRole('table', { name: 'Grupos de máquinas' }).getByRole('row').filter({ hasText: 'Recepção' }))
    .toContainText('Sem política (usa a padrão)');
  await page.getByRole('button', { name: 'Excluir Financeiro' }).click();
  await page.getByRole('button', { name: 'Confirmar exclusão' }).click();
  await expect(page.getByRole('alert')).toHaveText('Há grupos usando esta política.');
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: testInfo.outputPath('politicas-mobile.png'), fullPage: true });
});
