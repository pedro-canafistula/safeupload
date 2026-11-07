import { expect, test } from '@playwright/test';
import { administradorSimulado, semRolagemHorizontal } from './support/sessao';

// Backend simulado: o fluxo com o backend real (exemplos conferidos, 409, documento do agente) está em console.spec.ts.

/** Como o backend devolve uma condição: todos os campos, os ausentes como null. */
function comoBackend(campos: Record<string, unknown>): Record<string, unknown> {
  return { todos: null, algum: null, nao: null, contem: null, mascara: null, regex: null, minimo: null, ignorarCaixa: null,
    validador: null, grupoValidado: null, ...campos };
}

test.beforeEach(async ({ page }) => {
  await page.route('**/api/auth/me', route => route.fulfill({ json: administradorSimulado }));
  await page.route('**/api/regras', route => route.request().method() === 'GET' ? route.fulfill({ json: [] }) : route.fallback());
});

test('editor monta a condição no formato do backend e o "Como texto" usa OU para "alguma"', async ({ page }, testInfo) => {
  const enviados: unknown[] = [];
  await page.route('**/api/regras', route => {
    if (route.request().method() !== 'POST') return route.fallback();
    enviados.push(route.request().postDataJSON());
    return enviados.length === 1
      ? route.fulfill({ status: 409, json: { status: 409, erro: 'CONFLITO', mensagem: 'Já existe uma regra com esse nome.' } })
      : route.fulfill({ status: 201, json: { id: 9, revisao: 1 } });
  });
  await page.goto('/regras/nova');
  await expect(page.getByRole('link', { name: 'Regras', exact: true })).toHaveClass(/active/);
  await page.getByLabel('Nome', { exact: true }).fill('  Matrícula  ');
  await page.getByLabel('Combinação das condições').selectOption({ label: 'alguma' });
  const condicao = (n: number) => page.getByRole('group', { name: `Condição ${n}`, exact: true });
  await expect(page.getByRole('button', { name: 'Remover condição 1' })).toBeDisabled();
  await condicao(1).getByLabel('Tipo').selectOption({ label: 'Expressão regular' });
  await condicao(1).getByLabel('Expressão regular').fill('\\bMAT-(\\d{8})\\b');
  await condicao(1).getByLabel('Ignorar maiúsculas').check();
  await expect(condicao(1).getByLabel('Grupo validado')).toHaveCount(0);
  await condicao(1).getByLabel('Validador').selectOption({ label: 'Módulo 11' });
  await condicao(1).getByLabel('Grupo validado').fill('1');
  await page.getByRole('button', { name: 'Adicionar condição' }).click();
  await condicao(2).getByLabel('Tipo').selectOption({ label: 'Padrão (máscara)' });
  await expect(condicao(2)).toContainText('# = dígito, A = letra');
  await condicao(2).getByLabel('Máscara').fill('###.###.###-##');
  await condicao(2).getByLabel('Validador').selectOption({ label: 'CPF' });
  await condicao(2).getByLabel('Pelo menos (vezes)').fill('3');
  await page.getByRole('button', { name: 'Adicionar condição' }).click();
  await condicao(3).getByLabel(/Palavras ou frases/).fill('matrícula, registro\nRA');
  await expect(page.locator('.rule-preview')).toHaveText('/\\bMAT-(\\d{8})\\b/ (ignorando maiúsculas, Módulo 11 válido no grupo 1) OU ' +
    'pelo menos 3× ###.###.###-## (CPF válido) OU contém "matrícula" ou "registro" ou "RA"');
  await page.getByRole('group', { name: 'Exemplos que DEVEM ser sinalizados' }).getByLabel('Exemplo 1', { exact: true }).fill('MAT-12345679');
  await page.getByRole('group', { name: 'Exemplos que NÃO devem ser sinalizados' }).getByLabel('Exemplo 1', { exact: true }).fill('nada aqui');
  await page.getByRole('button', { name: 'Salvar regra' }).click();
  await expect(page.getByRole('alert')).toHaveText('Já existe uma regra com esse nome.');
  expect(enviados[0]).toEqual({
    nome: 'Matrícula', descricao: '',
    quando: { algum: [
      { regex: '\\bMAT-(\\d{8})\\b', ignorarCaixa: true, validador: 'mod11', grupoValidado: 1 },
      { mascara: '###.###.###-##', minimo: 3, validador: 'cpf' },
      { contem: ['matrícula', 'registro', 'RA'] }
    ] },
    exemplos: { sinalizar: ['MAT-12345679'], naoSinalizar: ['nada aqui'] }
  });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await semRolagemHorizontal(page)).toBeTruthy();
  await page.screenshot({ path: testInfo.outputPath('regra-mobile.png'), fullPage: true });
  await page.setViewportSize({ width: 1280, height: 900 });

  for (let i = 3; i < 20; i++) await page.getByRole('button', { name: 'Adicionar condição' }).click();
  await expect(page.getByRole('group', { name: /^Condição \d+$/ })).toHaveCount(20);
  await expect(page.getByRole('button', { name: 'Adicionar condição' })).toBeDisabled();
  for (let i = 20; i > 3; i--) await page.getByRole('button', { name: `Remover condição ${i}` }).click();
  await page.getByLabel('Nome', { exact: true }).fill('Matrícula 2');
  await page.getByRole('button', { name: 'Salvar regra' }).click();
  await expect(page).toHaveURL(/\/regras$/);
  await expect(page.getByText('Regra Matrícula 2 criada.')).toBeVisible();
  expect((enviados[1] as { quando: { algum: unknown[] } }).quando.algum).toHaveLength(3);
});

test('editor carrega a regra salva, envia PUT e a lista mostra a mensagem', async ({ page }) => {
  let enviado: unknown;
  await page.route('**/api/regras/5', route => {
    if (route.request().method() === 'PUT') {
      enviado = route.request().postDataJSON();
      return route.fulfill({ json: { id: 5, revisao: 4 } });
    }
    return route.fulfill({ json: {
      id: 5, nome: 'Atlas', descricao: null, revisao: 3, politicas: ['Financeiro'],
      quando: comoBackend({ todos: [comoBackend({ contem: ['projeto atlas', 'atlas'], minimo: 2 }),
        comoBackend({ nao: comoBackend({ contem: ['divulgação autorizada'] }) })] }),
      exemplos: { sinalizar: ['projeto atlas, atlas'], naoSinalizar: ['atlas', 'projeto atlas divulgação autorizada atlas'] }
    } });
  });
  await page.goto('/regras/5');
  await expect(page.getByRole('heading', { name: 'Editar regra' })).toBeVisible();
  await expect(page.getByText(/Revisão 3\. Usada por Financeiro/)).toBeVisible();
  await expect(page.getByLabel('Nome', { exact: true })).toHaveValue('Atlas');
  const segunda = page.getByRole('group', { name: 'Condição 2', exact: true });
  await expect(segunda.getByLabel('Tipo')).toHaveValue('naoContem');
  await expect(page.locator('.rule-preview')).toHaveText('contém pelo menos 2× "projeto atlas" ou "atlas" E NÃO contém "divulgação autorizada"');
  const naoDevem = page.getByRole('group', { name: 'Exemplos que NÃO devem ser sinalizados' });
  await expect(naoDevem.getByLabel('Exemplo 2', { exact: true })).toHaveValue('projeto atlas divulgação autorizada atlas');
  await naoDevem.getByRole('button', { name: 'Remover exemplo 1 que não deve ser sinalizado' }).click();
  await expect(naoDevem.getByRole('button', { name: 'Remover exemplo 1 que não deve ser sinalizado' })).toBeDisabled();
  await page.getByRole('button', { name: 'Salvar regra' }).click();
  await expect(page).toHaveURL(/\/regras$/);
  await expect(page.getByText('Regra Atlas salva (revisão 4). As políticas que a usam ganharam uma versão nova.')).toBeVisible();
  expect(enviado).toEqual({
    nome: 'Atlas', descricao: '',
    quando: { todos: [{ contem: ['projeto atlas', 'atlas'], minimo: 2 }, { nao: { contem: ['divulgação autorizada'] } }] },
    exemplos: { sinalizar: ['projeto atlas, atlas'], naoSinalizar: ['projeto atlas divulgação autorizada atlas'] }
  });
});

test('regra com grupos aninhados (criada pela API) não abre o editor', async ({ page }) => {
  await page.route('**/api/regras/6', route => route.fulfill({ json: {
    id: 6, nome: 'Aninhada', descricao: null, revisao: 1, politicas: [],
    quando: comoBackend({ todos: [comoBackend({ algum: [comoBackend({ contem: ['a1'] }), comoBackend({ mascara: 'AA-##' })] }),
      comoBackend({ contem: ['b2'] })] }),
    exemplos: { sinalizar: ['a1 b2'], naoSinalizar: ['b2'] }
  } }));
  await page.goto('/regras/6');
  await expect(page.getByText(/Esta regra usa combinações que este editor não monta/)).toBeVisible();
  await expect(page.locator('.rule-preview')).toHaveText('(contém "a1" OU AA-##) E contém "b2"');
  await expect(page.getByRole('button', { name: 'Salvar regra' })).toHaveCount(0);
});

test('Testar mostra a mensagem do servidor para condições inválidas', async ({ page }) => {
  await page.route('**/api/regras/testar', route => route.fulfill({ status: 400,
    json: { status: 400, erro: 'ERRO_REQUISICAO', mensagem: 'Condição 1: Posição 3: "(?" só é aceito como "(?:".' } }));
  await page.goto('/regras/nova');
  await page.getByRole('group', { name: 'Condição 1', exact: true }).getByLabel('Tipo').selectOption({ label: 'Expressão regular' });
  await page.getByRole('group', { name: 'Condição 1', exact: true }).getByLabel('Expressão regular').fill('a(?=b)');
  await page.getByRole('button', { name: 'Testar' }).click();
  await expect(page.getByRole('alert')).toHaveText('Condição 1: Posição 3: "(?" só é aceito como "(?:".');
});

test('lista: exclusão recusada mostra a mensagem do servidor', async ({ page }) => {
  await page.route('**/api/regras', route => route.request().method() === 'GET' ? route.fulfill({ json: [{
    id: 2, nome: 'Atlas', descricao: 'Contratos', revisao: 2, atualizadaEm: '2026-11-07T12:00:00Z', atualizadaPor: 'admin-teste',
    politicas: ['Financeiro', 'Padrão'], quando: comoBackend({ todos: [comoBackend({ contem: ['projeto atlas'] }),
      comoBackend({ mascara: 'CT-####/##', minimo: 2 })] })
  }] }) : route.fallback());
  await page.route('**/api/regras/2', route => route.fulfill({ status: 409,
    json: { status: 409, erro: 'CONFLITO', mensagem: 'A regra é usada pelas políticas: Financeiro, Padrão.' } }));
  await page.goto('/regras');
  const linha = page.getByRole('table', { name: 'Regras personalizadas da empresa' }).getByRole('row').filter({ hasText: 'Atlas' });
  await expect(linha).toContainText('contém "projeto atlas" E pelo menos 2× CT-####/##');
  await expect(linha).toContainText('Financeiro, Padrão');
  await page.getByRole('button', { name: 'Excluir Atlas' }).click();
  await page.getByRole('button', { name: 'Confirmar exclusão' }).click();
  await expect(page.getByRole('alert')).toHaveText('A regra é usada pelas políticas: Financeiro, Padrão.');
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await semRolagemHorizontal(page)).toBeTruthy();
});

test('auditoria: categoria de regra sem o nome da regra usa o rótulo genérico', async ({ page }) => {
  const base = { occurredAtUtc: '2026-11-07T12:00:00Z', endpointId: 'PC-1', hostId: 1, hostname: 'PC-1', userName: 'u', extension: '.txt',
    sizeBytes: 1, processName: 'a.exe', processId: 1, destinationPath: 'C:\\x', policyVersion: 1, elapsedMs: 1, notInspectedReason: null, channel: 'File' };
  await page.route('**/api/auditoria**', route => route.fulfill({ json: { host: null,
    resumo: { total: 2, bloqueados: 1, aprovados: 1, liberadosSemInspecao: 0 },
    eventos: [{ ...base, eventId: 'e1', fileName: 'alerta.txt', verdict: 'Approved', categories: ['CustomRuleAlert'] },
      { ...base, eventId: 'e2', fileName: 'bloqueio.txt', verdict: 'Blocked', categories: ['CustomRule', 'CustomRule'], customRules: ['X', 'Y'] }] } }));
  await page.goto('/auditoria');
  await expect(page.getByRole('cell', { name: 'Regra personalizada (alerta)', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Regra: X, Regra: Y', exact: true })).toBeVisible();
});
