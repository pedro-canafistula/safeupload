import { expect, test } from '@playwright/test';
import { administradorSimulado } from './support/sessao';

const configuracao = {
  categorias: { cpf: 'bloquear', cnpj: 'bloquear', rg: 'bloquear', cartao_credito: 'bloquear', dados_bancarios: 'bloquear',
    credenciais: 'bloquear', dados_saude: 'bloquear', dados_pessoais: 'bloquear', documentos_confidenciais: 'bloquear' },
  pastas: [], pendrives: true, rede: false, extensoes: ['.txt', '.csv', '.docx', '.xlsx', '.pdf', '.pptx', '.zip'],
  tamanhoMaximoMb: 100, tempoLimiteSegundos: 900, permitirJustificativa: false, clipboard: 'desligado', regrasPersonalizadas: {}
};

test.beforeEach(async ({ page }) => {
  await page.route('**/api/auth/me', route => route.fulfill({ json: administradorSimulado }));
  await page.route('**/api/regras', route => route.fulfill({ json: [] }));
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
  await expect(page.getByText(/A empresa ainda não tem regras personalizadas/)).toBeVisible();
  await expect(page.getByRole('form').getByRole('link', { name: 'Regras', exact: true })).toHaveAttribute('href', '/regras');
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

test('editor não envia política em que todas as categorias e regras são ignoradas', async ({ page }) => {
  let enviou = false;
  await page.route('**/api/politicas', route => { enviou = true; return route.fulfill({ status: 201, json: { id: 1, versao: 1 } }); });
  await page.goto('/politicas/nova');
  await page.getByLabel('Nome da política').fill('Nada');
  for (const grupo of await page.locator('.category-row').all()) await grupo.getByLabel('Ignorar').check();
  await page.getByRole('button', { name: 'Criar política' }).click();
  await expect(page.getByRole('alert')).toHaveText('Pelo menos uma categoria ou regra precisa bloquear ou alertar.');
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

const regras = [
  { id: 3, nome: 'Atlas', descricao: null, revisao: 1, atualizadaEm: '2026-11-07T12:00:00Z', atualizadaPor: 'admin-teste',
    politicas: ['Financeiro'], quando: { contem: ['projeto atlas'] } },
  { id: 4, nome: 'Matrícula', descricao: null, revisao: 2, atualizadaEm: '2026-11-07T12:00:00Z', atualizadaPor: 'admin-teste',
    politicas: [], quando: { mascara: 'MAT-########', validador: 'mod11' } }
];
const financeiro = { id: 7, nome: 'Financeiro', padrao: false, versao: 2,
  configuracao: { ...configuracao, regrasPersonalizadas: { '3': 'bloquear' } },
  historico: [{ versao: 2, criadaEm: '2026-11-07T12:00:00Z', criadaPor: 'admin-teste' }] };

test('editor liga regras em Bloquear/Alertar/Ignorar e mostra a recusa do servidor para agentes sem suporte', async ({ page }) => {
  await page.route('**/api/regras', route => route.fulfill({ json: regras }));
  const enviados: { configuracao: { categorias: object; regrasPersonalizadas: object } }[] = [];
  await page.route('**/api/politicas/7', route => {
    if (route.request().method() !== 'PUT') return route.fulfill({ json: financeiro });
    enviados.push(route.request().postDataJSON());
    return enviados.length === 1
      ? route.fulfill({ status: 409, json: { status: 409, erro: 'CONFLITO', mensagem: 'Estas máquinas não entendem regras personalizadas e ' +
        'receberiam uma política com regras: PC-01 (agente 0.2.0). Atualize o agente delas antes de publicar.' } })
      : route.fulfill({ json: { id: 7, versao: 3 } });
  });
  await page.goto('/politicas/7');
  const atlas = page.getByRole('group', { name: 'Regra Atlas', exact: true });
  const matricula = page.getByRole('group', { name: 'Regra Matrícula', exact: true });
  await expect(atlas.getByLabel('Bloquear')).toBeChecked();
  await expect(matricula.getByLabel('Ignorar')).toBeChecked();
  await expect(matricula).toContainText('MAT-######## (Módulo 11 válido)');
  await matricula.getByLabel('Alertar').check();
  await page.getByRole('button', { name: 'Salvar nova versão' }).click();
  await expect(page.getByRole('alert')).toHaveText(/^Estas máquinas não entendem regras personalizadas .*PC-01/);
  expect(enviados[0].configuracao.regrasPersonalizadas).toEqual({ '3': 'bloquear', '4': 'alertar' });

  // Só regras ligadas, todas as categorias em Ignorar: vale, o servidor decide.
  for (const grupo of await page.locator('.category-row:not([aria-label^="Regra "])').all()) await grupo.getByLabel('Ignorar').check();
  await atlas.getByLabel('Ignorar').check();
  await page.getByRole('button', { name: 'Salvar nova versão' }).click();
  await expect(page.getByText('Versão 3 salva', { exact: false })).toBeVisible();
  expect(enviados[1].configuracao.regrasPersonalizadas).toEqual({ '4': 'alertar' });
  expect(Object.values(enviados[1].configuracao.categorias).every(acao => acao === 'ignorar')).toBe(true);
});

test('se a lista de regras falha, salvar mantém as regras que a política já usa', async ({ page }) => {
  await page.route('**/api/regras', route => route.fulfill({ status: 500, json: {} }));
  let enviado: { configuracao: { regrasPersonalizadas: object } } | undefined;
  await page.route('**/api/politicas/7', route => {
    if (route.request().method() !== 'PUT') return route.fulfill({ json: financeiro });
    enviado = route.request().postDataJSON();
    return route.fulfill({ json: { id: 7, versao: 3 } });
  });
  await page.goto('/politicas/7');
  await expect(page.getByRole('alert')).toContainText('Não foi possível carregar as regras personalizadas.');
  await page.getByRole('button', { name: 'Salvar nova versão' }).click();
  await expect(page.getByText(/Versão 3 salva/)).toBeVisible();
  expect(enviado!.configuracao.regrasPersonalizadas).toEqual({ '3': 'bloquear' });
});
