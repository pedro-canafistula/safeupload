import { expect, test, type Download, type Page } from '@playwright/test';
import { generateKeyPairSync } from 'node:crypto';
import { API, AgenteFalso, entrarApi, evento, gerarToken, type HostInfo } from './support/agente';
import { entrar, semRolagemHorizontal } from './support/sessao';

// Backend real em 127.0.0.1:8080 com o banco recém-criado (db/initdb). Os testes dependem uns dos outros.
test.describe.configure({ mode: 'serial' });

const root = { email: 'root-e2e@example.com', senha: 'root-e2e-123' };
const admin = { email: 'admin-e2e@example.com', senha: 'admin-e2e-123' };
const maquina: HostInfo = {
  hostname: 'E2E-FINANCEIRO-01', ip: '10.90.0.31', mascara: 24, sistema_operacional: 'Windows',
  versao_so: '10.0.19045', mac_address: '52:54:00:12:34:56'
};
let agente: AgenteFalso;
let versaoPadrao = 0;
let versaoGrupo = 0;
const regra = 'Contratos do Projeto Atlas';
let idRegra = 0;

test.afterAll(async () => {
  await agente?.encerrar();
});

async function conteudo(download: Download): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of await download.createReadStream()) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

function linhaDaMaquina(page: Page) {
  return page.getByRole('row').filter({ has: page.getByRole('cell', { name: new RegExp('^' + maquina.hostname) }) });
}

/** Versão no texto "Política criada (versão N)." ou "Versão N salva." */
async function versaoNaMensagem(page: Page): Promise<number> {
  const texto = await page.locator('.success-message').innerText();
  return Number(/(?:versão|Versão) (\d+)/.exec(texto)![1]);
}

test('sem sessão, rotas administrativas e chamadas sem assinatura do agente são recusadas', async ({ request }) => {
  expect((await (await request.get(API + '/auth/decision')).json()).existemUsuarios).toBe(false);
  for (const path of ['/admin/token', '/politicas', '/grupos', '/endpoints/1/revogar', '/regras', '/regras/testar',
    '/auth/normalregister/empresa/set', '/auth/normalregister/usuario/set']) {
    expect((await request.post(API + path, { data: {} })).status(), path).toBe(401);
  }
  for (const path of ['/painel', '/endpoints', '/auditoria', '/auditoria/exportar', '/admin/tokens', '/politicas', '/grupos', '/regras',
    '/auth/normalregister/empresa/list']) {
    expect((await request.get(API + path)).status(), path).toBe(401);
  }
  expect((await request.post(API + '/agent/heartbeat', { data: { host: maquina } })).status()).toBe(401);
  expect((await request.get(API + '/agent/policy')).status()).toBe(401);
  expect((await request.post(API + '/agent/events', { data: { events: [evento()] } })).status()).toBe(401);
  const chave = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  expect((await request.post(API + '/agent/enroll', { data: { token: 'ABCDEFGH', chave_publica: chave, host: maquina } })).status()).toBe(401);
});

test('primeiro cadastro cria o root; o painel começa vazio', async ({ page }) => {
  await page.goto('/cadastro');
  await page.getByLabel('Nome completo').fill('Root E2E');
  await page.getByLabel('Nome de usuário').fill('root-e2e');
  await page.getByLabel('E-mail', { exact: true }).fill(root.email);
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
  await page.getByLabel('Senha', { exact: true }).fill(root.senha);
  await page.getByLabel('Confirmar senha').fill(root.senha);
  await page.getByRole('button', { name: 'Criar conta' }).click();
  await expect(page).toHaveURL(/login/);
  await entrar(page, root.email, root.senha);
  await expect(page.getByRole('heading', { name: 'Visão geral' })).toBeVisible();
  await expect(page.getByText('Nenhuma inspeção recebida para esta consulta.')).toBeVisible();
  await expect(page.getByText(/Nenhuma política padrão/)).toBeVisible();
  const maquinas = page.getByRole('region', { name: 'Política e máquinas' });
  await expect(maquinas.locator('div').filter({ hasText: 'Total' }).locator('dd')).toHaveText('0');
  await page.reload();
  await expect(page.getByText('Root E2E')).toBeVisible();
});

test('políticas: padrão e de grupo; editar cria uma versão nova no histórico', async ({ page, request }) => {
  await entrar(page, root.email, root.senha);
  await page.getByRole('link', { name: 'Políticas', exact: true }).click();
  await expect(page.getByText(/Nenhuma política\. Crie a primeira/)).toBeVisible();

  await page.getByRole('link', { name: 'Nova política' }).click();
  await expect(page.getByRole('heading', { name: 'Nova política' })).toBeVisible();
  await expect(page.getByLabel(/Extensões inspecionadas/)).toHaveValue('.txt, .csv, .docx, .xlsx, .pdf, .pptx, .zip');
  await expect(page.getByLabel('Tamanho máximo (MB)')).toHaveValue('100');
  await expect(page.getByLabel('Tempo limite da inspeção (s)')).toHaveValue('900');
  await page.getByLabel('Nome da política').fill('Padrão E2E');
  await page.getByLabel(/Política padrão da empresa/).check();
  await page.getByRole('group', { name: 'RG', exact: true }).getByLabel('Alertar').check();
  await page.getByRole('group', { name: 'Dados pessoais', exact: true }).getByLabel('Ignorar').check();
  await page.getByRole('button', { name: 'Criar política' }).click();
  await expect(page.getByText(/Política criada \(versão \d+\)/)).toBeVisible();
  await expect(page).toHaveURL(/\/politicas\/\d+$/);
  await expect(page.getByRole('heading', { name: 'Editar política' })).toBeVisible();
  versaoPadrao = await versaoNaMensagem(page);
  await expect(page.getByRole('table', { name: 'Versões da política' }).locator('tbody tr')).toHaveCount(1);

  // A mensagem do backend aparece quando ele recusa a configuração.
  await page.getByRole('link', { name: 'Voltar para políticas' }).click();
  await page.getByRole('link', { name: 'Nova política' }).click();
  await page.getByLabel('Nome da política').fill('Financeiro E2E');
  await page.getByLabel(/Pastas protegidas/).fill('Dados\\Financeiro');
  await page.getByRole('button', { name: 'Criar política' }).click();
  await expect(page.getByRole('alert')).toContainText('Pasta inválida');
  await page.getByLabel(/Pastas protegidas/).fill('C:\\Dados\\Financeiro\n\\\\servidor\\publico');
  await page.getByLabel(/Proteger compartilhamentos de rede/).check();
  await page.getByLabel(/Permitir justificativa/).check();
  await page.getByLabel('Área de transferência (clipboard)').selectOption('bloquear');
  await page.getByRole('button', { name: 'Criar política' }).click();
  await expect(page.getByText(/Política criada \(versão \d+\)/)).toBeVisible();
  const primeira = await versaoNaMensagem(page);
  // A mensagem aparece antes de o editor trocar /politicas/nova por /politicas/<id>.
  await expect(page).toHaveURL(/\/politicas\/\d+$/);
  const id = Number(/\/politicas\/(\d+)$/.exec(page.url())![1]);

  await page.getByRole('group', { name: 'CNPJ', exact: true }).getByLabel('Alertar').check();
  await page.getByLabel(/Extensões inspecionadas/).fill('.txt; .CSV\n.docx');
  await page.getByRole('button', { name: 'Salvar nova versão' }).click();
  await expect(page.getByText(/Versão \d+ salva/)).toBeVisible();
  versaoGrupo = await versaoNaMensagem(page);
  expect(versaoGrupo).toBeGreaterThan(primeira);
  const historico = page.getByRole('table', { name: 'Versões da política' }).locator('tbody tr');
  await expect(historico).toHaveCount(2);
  await expect(historico.first()).toContainText(`v${versaoGrupo}`);
  await expect(historico.first()).toContainText('root-e2e');
  await expect(historico.last()).toContainText(`v${primeira}`);
  await expect(page.getByText(`Versão atual v${versaoGrupo}`)).toBeVisible();
  await page.reload();
  await expect(page.getByRole('group', { name: 'CNPJ', exact: true }).getByLabel('Alertar')).toBeChecked();
  await expect(page.getByLabel(/Pastas protegidas/)).toHaveValue('C:\\Dados\\Financeiro\n\\\\servidor\\publico');

  await entrarApi(request, root.email, root.senha);
  const salva = await (await request.get(`${API}/politicas/${id}`)).json();
  expect(salva.padrao).toBe(false);
  expect(salva.configuracao).toEqual({
    categorias: { cpf: 'bloquear', cnpj: 'alertar', rg: 'bloquear', cartao_credito: 'bloquear', dados_bancarios: 'bloquear',
      credenciais: 'bloquear', dados_saude: 'bloquear', dados_pessoais: 'bloquear', documentos_confidenciais: 'bloquear' },
    pastas: ['C:\\Dados\\Financeiro', '\\\\servidor\\publico'], pendrives: true, rede: true,
    extensoes: ['.txt', '.csv', '.docx'], tamanhoMaximoMb: 100, tempoLimiteSegundos: 900,
    permitirJustificativa: true, clipboard: 'bloquear', regrasPersonalizadas: {}
  });

  await page.getByRole('link', { name: 'Voltar para políticas' }).click();
  const lista = page.getByRole('table', { name: 'Políticas da empresa' });
  await expect(lista.getByRole('row').filter({ hasText: 'Padrão E2E' })).toContainText('Padrão');
  await expect(lista.getByRole('row').filter({ hasText: 'Financeiro E2E' })).toContainText(`v${versaoGrupo}`);
  await page.getByRole('button', { name: 'Excluir Padrão E2E' }).click();
  await page.getByRole('button', { name: 'Confirmar exclusão' }).click();
  await expect(page.getByRole('alert')).toHaveText('Esta é a política padrão; defina outra como padrão antes de excluir.');
  await expect(lista.getByRole('row').filter({ hasText: 'Padrão E2E' })).toBeVisible();
});

test('grupos: criar, renomear, trocar a política e excluir', async ({ page }) => {
  await entrar(page, root.email, root.senha);
  await page.goto('/politicas');
  const grupos = page.getByRole('table', { name: 'Grupos de máquinas' });
  await page.getByLabel('Nome do grupo').fill('Financeiro');
  await page.getByLabel('Política do grupo').selectOption({ label: 'Financeiro E2E' });
  await page.getByRole('button', { name: 'Criar grupo' }).click();
  await expect(page.getByText('Grupo Financeiro criado.')).toBeVisible();
  await expect(grupos.getByRole('row').filter({ hasText: 'Financeiro' })).toContainText('Financeiro E2E');

  await page.getByLabel('Nome do grupo').fill('Temporário');
  await page.getByRole('button', { name: 'Criar grupo' }).click();
  await expect(grupos.getByRole('row').filter({ hasText: 'Temporário' })).toContainText('Sem política (usa a padrão)');
  await page.getByRole('button', { name: 'Editar grupo Temporário' }).click();
  await page.getByLabel('Novo nome do grupo').fill('Temporário 2');
  await page.getByLabel('Nova política do grupo').selectOption({ label: 'Padrão E2E' });
  await page.getByRole('button', { name: 'Salvar grupo' }).click();
  await expect(grupos.getByRole('row').filter({ hasText: 'Temporário 2' })).toContainText('Padrão E2E');
  await page.getByRole('button', { name: 'Excluir grupo Temporário 2' }).click();
  await page.getByRole('button', { name: 'Confirmar exclusão' }).click();
  await expect(page.getByText('Grupo Temporário 2 excluído.')).toBeVisible();
  await expect(grupos.getByRole('row').filter({ hasText: 'Temporário' })).toHaveCount(0);

  await expect(page.getByRole('table', { name: 'Políticas da empresa' }).getByRole('row').filter({ hasText: 'Financeiro E2E' }))
    .toContainText('Financeiro');
  await page.getByRole('button', { name: 'Excluir Financeiro E2E' }).click();
  await page.getByRole('button', { name: 'Confirmar exclusão' }).click();
  await expect(page.getByRole('alert')).toHaveText('Há grupos usando esta política.');
});

test('configurações: gerar, listar e excluir tokens; o agente se cadastra com o token', async ({ page, request }) => {
  await entrar(page, root.email, root.senha);
  await page.getByRole('link', { name: 'Configurações', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Tokens de cadastro' })).toBeVisible();
  await expect(page.getByText('Nenhum token gerado.')).toBeVisible();

  await page.getByRole('button', { name: 'Gerar token' }).click();
  const gerado = page.getByRole('region', { name: 'Token gerado' });
  await expect(gerado.locator('.token-value')).toHaveText(/^[A-Za-z0-9]{8}$/);
  const token = await gerado.locator('.token-value').innerText();
  await expect(gerado.locator('.command')).toHaveText(`SafeUpload.Agent.Service.exe cadastrar https://SERVIDOR:8443/agent/ ${token}`);
  await expect(gerado).toContainText('15 minutos');
  await expect(gerado).toContainText('único cadastro');
  const tabela = page.getByRole('table', { name: 'Tokens de cadastro' });
  await expect(tabela.getByRole('row').filter({ hasText: token })).toContainText('Ativo');
  await expect(tabela.getByRole('row').filter({ hasText: token })).toContainText('root-e2e');

  await page.getByRole('button', { name: 'Gerar token' }).click();
  await expect(gerado.locator('.token-value')).not.toHaveText(token);
  const descartado = await gerado.locator('.token-value').innerText();
  await expect(tabela.locator('tbody tr')).toHaveCount(2);
  await tabela.getByRole('row').filter({ hasText: descartado }).getByRole('button', { name: /^Excluir/ }).click();
  await expect(tabela.locator('tbody tr')).toHaveCount(1);
  await expect(gerado).toHaveCount(0);

  agente = await AgenteFalso.cadastrar(token, maquina);
  const repetido = await request.post(API + '/agent/enroll', { data: { token, host: maquina,
    chave_publica: generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).toString('base64') } });
  expect(repetido.status()).toBe(401);
  await page.reload();
  const usado = tabela.locator('tbody tr').first();
  await expect(usado).toContainText('Usado');
  await expect(usado).not.toContainText(token);
  await expect(usado.getByRole('link', { name: maquina.hostname })).toBeVisible();
  await expect(usado.getByRole('button', { name: /^Excluir/ })).toHaveCount(0);
});

test('endpoints: política esperada, aviso de desatualizada, troca de grupo e heartbeat com a versão', async ({ page }) => {
  expect((await agente.heartbeat(null)).status()).toBe(200);
  const padrao = await agente.politica();
  expect(padrao.status()).toBe(200);
  const documentoPadrao = await padrao.json();
  expect(documentoPadrao.version).toBe(versaoPadrao);
  expect(documentoPadrao.activeCategories).toContain('Rg');
  expect(documentoPadrao.alertCategories).toEqual(['Rg']);
  expect(documentoPadrao.activeCategories).not.toContain('PersonalData');

  await entrar(page, root.email, root.senha);
  await page.getByRole('link', { name: 'Endpoints', exact: true }).click();
  const linha = linhaDaMaquina(page);
  await expect(linha).toContainText(maquina.ip);
  await expect(linha).toContainText('Windows 10.0.19045');
  await expect(linha).toContainText('0.2.0');
  await expect(linha).toContainText('Online');
  await expect(linha.getByRole('link', { name: `Padrão E2E v${versaoPadrao}` })).toBeVisible();
  await expect(linha.locator('.pill.warn')).toHaveText('aguardando');
  await expect(page.getByLabel('Grupo de ' + maquina.hostname).locator('option:checked')).toHaveText('Sem grupo');

  await page.getByLabel('Grupo de ' + maquina.hostname).selectOption({ label: 'Financeiro' });
  await expect(page.getByText(`Grupo de ${maquina.hostname} alterado.`)).toBeVisible();
  await expect(linha.getByRole('link', { name: `Financeiro E2E v${versaoGrupo}` })).toBeVisible();
  await expect(linha.locator('.pill.warn')).toHaveText('aguardando');

  const documento = await (await agente.politica()).json();
  expect(documento).toMatchObject({
    version: versaoGrupo, alertCategories: ['Cnpj'], overrideAllowed: true, failOpen: false, clipboard: { mode: 'Block' },
    monitoredScopes: { extensions: ['.txt', '.csv', '.docx'], destinationPaths: ['C:\\Dados\\Financeiro', '\\\\servidor\\publico'],
      removableDrives: true, networkPaths: true }
  });

  expect((await agente.heartbeat(versaoPadrao)).status()).toBe(200);
  await page.getByRole('button', { name: 'Atualizar' }).click();
  await expect(linha.locator('.pill.warn')).toHaveText(`aplicada v${versaoPadrao}`);
  expect((await agente.heartbeat(versaoGrupo)).status()).toBe(200);
  await page.getByRole('button', { name: 'Atualizar' }).click();
  await expect(linha.locator('.pill.warn')).toHaveCount(0);
  await expect(linha.getByRole('link', { name: `Financeiro E2E v${versaoGrupo}` })).toBeVisible();

  await page.getByLabel('Buscar máquina').fill('INEXISTENTE');
  await page.getByRole('button', { name: 'Aplicar', exact: true }).click();
  await expect(page.getByText('Nenhum endpoint corresponde aos filtros.')).toBeVisible();
  await page.getByRole('link', { name: 'Limpar', exact: true }).click();
  await expect(linha).toBeVisible();
  await page.goto('/politicas');
  await expect(page.getByRole('table', { name: 'Políticas da empresa' }).getByRole('row').filter({ hasText: 'Financeiro E2E' })
    .locator('td').nth(4)).toHaveText('1');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/endpoints');
  await expect(linha).toBeVisible();
  expect(await semRolagemHorizontal(page)).toBeTruthy();
});

test('eventos assinados aparecem na auditoria com o nome da máquina; CSV e relatório exportam', async ({ page }) => {
  const bloqueado = evento({ verdict: 'Blocked', categories: ['Cpf', 'Secret'], fileName: '<script>alert(1)</script>.txt',
    policyVersion: versaoGrupo, occurredAtUtc: new Date(Date.now() - 2000).toISOString() });
  const eventos = [bloqueado,
    evento({ verdict: 'Approved', fileName: 'limpo.txt', policyVersion: versaoGrupo, occurredAtUtc: new Date(Date.now() - 1000).toISOString() }),
    evento({ verdict: 'AllowedWithoutInspection', fileName: 'lento.txt', notInspectedReason: 'inspection_timeout', policyVersion: versaoGrupo })];
  const justificativa = { eventId: bloqueado.eventId, justification: 'Envio autorizado pelo gestor <b>texto literal</b>',
    occurredAtUtc: new Date().toISOString(), userName: 'S-1-5-21-1001', endpointId: 'ROTULO-DO-AGENTE' };
  for (const tentativa of [1, 2]) {
    const resposta = await agente.eventos(eventos, [justificativa]);
    expect(resposta.status(), `envio ${tentativa}`).toBe(200);
    expect(await resposta.json()).toEqual({ acceptedEvents: 3, acceptedOverrides: 1 });
  }

  await entrar(page, root.email, root.senha);
  const inspecoes = page.locator('.metrics section').filter({ has: page.getByRole('heading', { name: 'Inspeções', exact: true }) });
  await expect(inspecoes.locator('strong')).toHaveText('3');
  const resumo = page.getByRole('region', { name: 'Política e máquinas' });
  await expect(resumo.getByRole('link', { name: `Padrão E2E v${versaoPadrao}` })).toBeVisible();
  for (const [nome, valor] of [['Total', '1'], ['Online', '1'], ['Política desatualizada', '0']]) {
    await expect(resumo.locator('div').filter({ has: page.getByText(nome, { exact: true }) }).locator('dd')).toHaveText(valor);
  }

  await page.goto('/endpoints');
  await expect(linhaDaMaquina(page).locator('td').nth(7)).toHaveText('3');
  await page.getByRole('link', { name: 'Ver auditoria de ' + maquina.hostname }).click();
  await expect(page).toHaveURL(new RegExp(`/auditoria\\?host=${agente.idHost}$`));
  await expect(page.getByText(`Auditoria de ${maquina.hostname}`)).toBeVisible();
  await expect(page.getByText('Total 3', { exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: maquina.hostname, exact: true })).toHaveCount(3);
  await expect(page.getByText('inspection_timeout')).toBeVisible();
  await expect(page.getByRole('cell', { name: '<script>alert(1)</script>.txt', exact: true })).toBeVisible();
  await expect(page.locator('app-event-table script')).toHaveCount(0);
  await page.getByRole('button', { name: 'Detalhes de <script>alert(1)</script>.txt', exact: true }).click();
  const detalhes = page.getByRole('region', { name: 'Detalhes de <script>alert(1)</script>.txt', exact: true });
  await expect(detalhes.locator('div').filter({ has: page.getByText('Máquina', { exact: true }) }).locator('dd')).toHaveText(maquina.hostname);
  await expect(detalhes).toContainText('ROTULO-DO-AGENTE');
  await expect(detalhes).toContainText('editor.exe');
  const registro = page.getByRole('region', { name: 'Justificativas do evento', exact: true });
  await expect(registro.getByText(justificativa.justification, { exact: true })).toHaveCount(1);
  await expect(registro.locator('b')).toHaveCount(0);

  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Exportar CSV' }).click();
  const csv = await download;
  expect(csv.suggestedFilename()).toBe(`auditoria-7-dias-host-${agente.idHost}.csv`);
  const texto = await conteudo(csv);
  expect(texto.startsWith('\uFEFFdata_utc;maquina;usuario;canal;arquivo;')).toBeTruthy();
  expect(texto.trim().split('\r\n')).toHaveLength(4);
  expect(texto).toContain(`"${maquina.hostname}"`);
  expect(texto).toContain('"Bloqueado"');
  expect(texto).toContain('"CPF, Segredo/credencial"');

  await page.getByRole('link', { name: 'Relatórios', exact: true }).click();
  await page.getByLabel('Máquina').selectOption({ label: `${maquina.hostname} (${maquina.ip})` });
  const relatorio = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Baixar CSV' }).click();
  expect((await relatorio).suggestedFilename()).toBe(`auditoria-7-dias-host-${agente.idHost}.csv`);
  await page.getByLabel('Máquina').selectOption({ label: 'Todas as máquinas' });
  const todas = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Baixar CSV' }).click();
  const completo = await todas;
  expect(completo.suggestedFilename()).toBe('auditoria-7-dias.csv');
  expect(await conteudo(completo)).toContain('"lento.txt"');
});

test('regras: criar pela tela com exemplos; exemplo errado impede salvar; Testar mostra cada exemplo', async ({ page }) => {
  await entrar(page, root.email, root.senha);
  await page.getByRole('link', { name: 'Regras', exact: true }).click();
  await expect(page).toHaveURL(/\/regras$/);
  await expect(page.getByText(/Nenhuma regra personalizada/)).toBeVisible();
  await page.getByRole('link', { name: 'Nova regra' }).click();
  await expect(page.getByRole('heading', { name: 'Nova regra' })).toBeVisible();
  await page.getByLabel('Nome', { exact: true }).fill(regra);
  await page.getByLabel('Descrição').fill('Contratos CT do projeto');
  const condicao = (n: number) => page.getByRole('group', { name: `Condição ${n}`, exact: true });
  await condicao(1).getByLabel(/Palavras ou frases/).fill('projeto atlas');
  await page.getByRole('button', { name: 'Adicionar condição' }).click();
  await condicao(2).getByLabel('Tipo').selectOption({ label: 'Padrão (máscara)' });
  await condicao(2).getByLabel('Máscara').fill('CT-####/##');
  await condicao(2).getByLabel('Pelo menos (vezes)').fill('2');
  await page.getByRole('button', { name: 'Adicionar condição' }).click();
  await condicao(3).getByLabel('Tipo').selectOption({ label: 'Não contém palavras' });
  await condicao(3).getByLabel(/Palavras ou frases/).fill('divulgação autorizada');
  const comoTexto = 'contém "projeto atlas" E pelo menos 2× CT-####/## E NÃO contém "divulgação autorizada"';
  await expect(page.getByRole('region', { name: 'Como texto' }).locator('.rule-preview')).toHaveText(comoTexto);

  const devem = page.getByRole('group', { name: 'Exemplos que DEVEM ser sinalizados' });
  const naoDevem = page.getByRole('group', { name: 'Exemplos que NÃO devem ser sinalizados' });
  await devem.getByLabel('Exemplo 1', { exact: true }).fill('Projeto Atlas: contratos CT-2041/26 e CT-2042/26');
  await naoDevem.getByLabel('Exemplo 1', { exact: true }).fill('Projeto Atlas: CT-2041/26 e CT-2042/26, divulgação autorizada');
  await page.getByRole('button', { name: 'Adicionar exemplo que não deve ser sinalizado' }).click();
  await naoDevem.getByLabel('Exemplo 2', { exact: true }).fill('PROJETO-ATLAS, contratos ct-1111/11 e CT-2222/22');
  await page.getByRole('button', { name: 'Salvar regra' }).click();
  await expect(page.getByRole('alert')).toHaveText('O exemplo 2 que não deve ser sinalizado foi.');
  await expect(page).toHaveURL(/\/regras\/nova$/);

  await page.getByRole('button', { name: 'Testar' }).click();
  await expect(page.getByText(/^1 exemplo não se comporta como esperado/)).toBeVisible();
  const resultado = (lista: typeof devem, n: number) => lista.locator('.example').nth(n).locator('.test-result');
  await expect(resultado(devem, 0)).toContainText('✓ Sinalizado, como esperado');
  await expect(resultado(devem, 0)).toContainText('Condição 2 · pelo menos 2× máscara CT-####/##: 2 ocorrências ✓');
  await expect(resultado(naoDevem, 0)).toContainText('✓ Não sinalizado, como esperado');
  await expect(resultado(naoDevem, 0)).toContainText('Condição 3 · NÃO contém "divulgacao autorizada": 1 ocorrência ✗');
  await expect(resultado(naoDevem, 1)).toContainText('✗ Sinalizado, mas não deveria ser');
  await expect(resultado(naoDevem, 1)).toHaveClass(/fail/);

  // Condição inválida: o Testar mostra a mensagem do servidor.
  await page.getByRole('button', { name: 'Adicionar condição' }).click();
  await condicao(4).getByLabel('Tipo').selectOption({ label: 'Expressão regular' });
  await condicao(4).getByLabel('Expressão regular').fill('^CT');
  await expect(page.getByText('A regra ou os exemplos mudaram desde o último teste.')).toBeVisible();
  await page.getByRole('button', { name: 'Testar' }).click();
  await expect(page.locator('.test-bar').getByRole('alert')).toHaveText(
    'Condição 4: Posição 1: âncoras ^ e $ não são aceitas (a regra procura no texto inteiro).');
  await page.getByRole('button', { name: 'Remover condição 4' }).click();

  await naoDevem.getByLabel('Exemplo 2', { exact: true }).fill('Projeto Atlas: só o contrato CT-2041/26');
  await page.getByRole('button', { name: 'Testar' }).click();
  await expect(page.getByText('Todos os exemplos se comportam como esperado.')).toBeVisible();
  await page.getByRole('button', { name: 'Salvar regra' }).click();
  await expect(page).toHaveURL(/\/regras$/);
  await expect(page.getByText(`Regra ${regra} criada.`)).toBeVisible();
  const linha = page.getByRole('table', { name: 'Regras personalizadas da empresa' }).getByRole('row').filter({ hasText: regra });
  await expect(linha).toContainText('Contratos CT do projeto');
  await expect(linha.locator('td').nth(1)).toHaveText(comoTexto);
  await expect(linha.locator('td').nth(2)).toHaveText('1');
  await expect(linha.locator('td').nth(3)).toContainText('root-e2e');
  await expect(linha.locator('td').nth(4)).toHaveText('—');
  idRegra = Number(/\/regras\/(\d+)$/.exec((await linha.getByRole('link', { name: regra, exact: true }).getAttribute('href'))!)![1]);
  expect(idRegra).toBeGreaterThan(0);
});

test('regra numa política: 409 para agente sem formato_regras; o agente com formato 1 recebe a regra; editar a regra cria versão nova; regra em uso não é excluída', async ({ page, request }) => {
  expect((await agente.heartbeat(versaoGrupo)).status()).toBe(200);
  await entrar(page, root.email, root.senha);
  await page.goto('/politicas');
  await page.getByRole('link', { name: 'Financeiro E2E', exact: true }).first().click();
  await expect(page).toHaveURL(/\/politicas\/\d+$/);
  const idPolitica = Number(/\/politicas\/(\d+)$/.exec(page.url())![1]);
  const naPolitica = page.getByRole('group', { name: 'Regra ' + regra, exact: true });
  await expect(naPolitica.getByLabel('Ignorar')).toBeChecked();
  await expect(naPolitica).toContainText('pelo menos 2× CT-####/##');
  await naPolitica.getByLabel('Alertar').check();
  await page.getByRole('button', { name: 'Salvar nova versão' }).click();
  const recusa = page.getByRole('alert');
  await expect(recusa).toContainText('Estas máquinas não entendem regras personalizadas');
  await expect(recusa).toContainText(maquina.hostname);
  expect((await (await agente.politica()).json()).version).toBe(versaoGrupo);

  expect((await agente.heartbeat(versaoGrupo, 1)).status()).toBe(200);
  await page.getByRole('button', { name: 'Salvar nova versão' }).click();
  await expect(page.getByText(/Versão \d+ salva/)).toBeVisible();
  const versaoComRegra = await versaoNaMensagem(page);
  expect(versaoComRegra).toBeGreaterThan(versaoGrupo);
  const documento = await (await agente.politica()).json();
  expect(documento.version).toBe(versaoComRegra);
  expect(documento.customRulesFormat).toBe(1);
  expect(documento.customRules).toEqual([{ id: idRegra, revision: 1, name: regra, alert: true, when: { all: [
    { words: ['projeto atlas'] },
    { pattern: 'CT\\-[0-9][0-9][0-9][0-9]\\/[0-9][0-9]', ignoreCase: true, min: 2 },
    { not: { words: ['divulgacao autorizada'] } }
  ] } }]);
  expect(documento.activeCategories).toContain('CustomRuleAlert');
  expect(documento.alertCategories).toContain('CustomRuleAlert');
  await entrarApi(request, root.email, root.senha);
  expect((await (await request.get(`${API}/politicas/${idPolitica}`)).json()).configuracao.regrasPersonalizadas)
    .toEqual({ [String(idRegra)]: 'alertar' });
  await page.reload();
  await expect(naPolitica.getByLabel('Alertar')).toBeChecked();

  await page.getByRole('link', { name: 'Regras', exact: true }).click();
  const linha = page.getByRole('table', { name: 'Regras personalizadas da empresa' }).getByRole('row').filter({ hasText: regra });
  await expect(linha.locator('td').nth(4)).toHaveText('Financeiro E2E');
  await page.getByRole('button', { name: 'Excluir ' + regra }).click();
  await page.getByRole('button', { name: 'Confirmar exclusão' }).click();
  await expect(page.getByRole('alert')).toHaveText('A regra é usada pelas políticas: Financeiro E2E.');
  await expect(linha).toBeVisible();

  await page.getByRole('link', { name: 'Editar ' + regra }).click();
  await expect(page.getByText(/Revisão 1\. Usada por Financeiro E2E/)).toBeVisible();
  const primeira = page.getByRole('group', { name: 'Condição 1', exact: true }).getByLabel(/Palavras ou frases/);
  await expect(primeira).toHaveValue('projeto atlas');
  await primeira.fill('projeto atlas, atlas project');
  await page.getByRole('button', { name: 'Salvar regra' }).click();
  await expect(page).toHaveURL(/\/regras$/);
  await expect(page.getByText(`Regra ${regra} salva (revisão 2). As políticas que a usam ganharam uma versão nova.`)).toBeVisible();
  await expect(linha.locator('td').nth(2)).toHaveText('2');
  const editado = await (await agente.politica()).json();
  expect(editado.version).toBeGreaterThan(versaoComRegra);
  expect(editado.customRules[0].revision).toBe(2);
  expect(editado.customRules[0].when.all[0]).toEqual({ words: ['projeto atlas', 'atlas project'] });
  versaoGrupo = editado.version;

  await page.goto(`/politicas/${idPolitica}`);
  await expect(page.getByText(`Versão atual v${versaoGrupo}`)).toBeVisible();
  await expect(page.getByRole('table', { name: 'Versões da política' }).locator('tbody tr').first())
    .toContainText(`root-e2e (regra "${regra}" editada)`);
});

test('evento de regra personalizada aparece como "Regra: <nome>" no painel e na auditoria', async ({ page }) => {
  const alerta = evento({ verdict: 'Approved', categories: ['CustomRuleAlert'], customRules: [regra], fileName: 'contrato-alerta.docx',
    extension: '.docx', policyVersion: versaoGrupo });
  const bloqueio = evento({ verdict: 'Blocked', categories: ['Cpf', 'CustomRule'], customRules: [regra], fileName: 'contrato-bloqueado.docx',
    extension: '.docx', policyVersion: versaoGrupo });
  const resposta = await agente.eventos([alerta, bloqueio]);
  expect(resposta.status(), await resposta.text()).toBe(200);

  await entrar(page, root.email, root.senha);
  await expect(page.locator('.categories-card')).toContainText(`Regra: ${regra}: 1`);
  await page.goto('/auditoria');
  await expect(page.getByRole('cell', { name: `Regra: ${regra}`, exact: true })).toHaveCount(1);
  await expect(page.getByRole('cell', { name: `CPF, Regra: ${regra}`, exact: true })).toHaveCount(1);
  await page.getByRole('button', { name: 'Detalhes de contrato-alerta.docx', exact: true }).click();
  const detalhes = page.getByRole('region', { name: 'Detalhes de contrato-alerta.docx', exact: true });
  await expect(detalhes.locator('div').filter({ has: page.getByText('Categorias', { exact: true }) }).locator('dd')).toHaveText(`Regra: ${regra}`);
  await expect(detalhes).toContainText('com achados nas categorias indicadas');
  await page.getByLabel('Buscar evento, usuário ou arquivo').fill('projeto atlas');
  await expect(page.locator('app-event-table tbody tr:not(.details-row)')).toHaveCount(2);
});

test('revogar pede confirmação na tela e a máquina passa a receber 403', async ({ page }) => {
  await entrar(page, root.email, root.senha);
  await page.goto('/endpoints');
  const linha = linhaDaMaquina(page);
  await page.getByRole('button', { name: 'Revogar ' + maquina.hostname }).click();
  const confirmacao = page.getByRole('group', { name: 'Confirmar revogação de ' + maquina.hostname });
  await expect(confirmacao).toContainText('cadastrá-la de novo');
  await confirmacao.getByRole('button', { name: 'Cancelar' }).click();
  await expect(confirmacao).toHaveCount(0);
  await expect(linha).toContainText('Online');
  await page.getByRole('button', { name: 'Revogar ' + maquina.hostname }).click();
  await confirmacao.getByRole('button', { name: 'Confirmar revogação' }).click();
  await expect(page.getByText(`${maquina.hostname} foi revogada.`)).toBeVisible();
  await expect(linha.locator('.pill').last()).toHaveText('Revogado');
  await expect(page.getByText('Revogados 1', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Grupo de ' + maquina.hostname)).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Revogar ' + maquina.hostname })).toHaveCount(0);
  expect((await agente.heartbeat(versaoGrupo)).status()).toBe(403);
  await page.getByLabel('Status').selectOption('revogado');
  await page.getByRole('button', { name: 'Aplicar', exact: true }).click();
  await expect(page).toHaveURL(/status=revogado/);
  await expect(linha).toBeVisible();
});

test('root cadastra um administrador; o administrador só cadastra admin/user e não vê empresas', async ({ page }) => {
  await entrar(page, root.email, root.senha);
  await page.getByRole('link', { name: 'Novos Cadastros', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Cadastro de empresa' })).toBeVisible();
  const usuario = page.getByRole('region', { name: 'Cadastro de usuário' });
  await expect(usuario.getByLabel('Perfil de acesso').locator('option')).toHaveText(['Usuário', 'Administrador', 'Root (todas as empresas)']);
  await expect(usuario.getByRole('combobox', { name: /^Empresa/ }).locator('option:checked')).toHaveText('Empresa Sintetica E2E');
  await usuario.getByLabel('Nome completo').fill('Admin E2E');
  await usuario.getByLabel('Nome de usuário').fill('admin-e2e');
  await usuario.getByLabel('E-mail').fill(admin.email);
  await usuario.getByLabel('CPF').fill('39053344705');
  await usuario.getByLabel('Data de nascimento').fill('1991-02-03');
  await usuario.getByLabel('Senha', { exact: true }).fill(admin.senha);
  await usuario.getByLabel('Confirmar senha').fill(admin.senha);
  await usuario.getByLabel('Perfil de acesso').selectOption('admin');
  await usuario.getByLabel('CEP').fill('70000-000');
  await usuario.getByLabel('Estado (UF)').fill('DF');
  await usuario.getByLabel('Logradouro').fill('Rua Sintetica');
  await usuario.getByLabel('Número').fill('2');
  await usuario.getByLabel('Bairro').fill('Teste');
  await usuario.getByLabel('Cidade').fill('Brasilia');
  await usuario.getByRole('button', { name: 'Cadastrar usuário' }).click();
  await expect(usuario.getByRole('status')).toBeVisible();
  await expect(usuario.getByRole('alert')).toHaveCount(0);

  await page.getByRole('button', { name: 'Sair' }).click();
  await expect(page).toHaveURL(/login/);
  await entrar(page, admin.email, admin.senha);
  await page.goto('/novos-cadastros');
  await expect(page.getByRole('heading', { name: 'Cadastro de usuário' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Cadastro de empresa' })).toHaveCount(0);
  await expect(page.getByLabel('Perfil de acesso').locator('option')).toHaveText(['Usuário', 'Administrador']);
  await expect(page.getByRole('combobox', { name: /^Empresa/ }).locator('option:checked')).toHaveText('Empresa Sintetica E2E');
  await page.goto('/politicas');
  await expect(page.getByRole('table', { name: 'Políticas da empresa' })).toContainText('Padrão E2E');
});

test('erros de API não são confundidos com estado vazio; atualização recupera a tela', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('E-mail').fill(root.email);
  await page.getByLabel('Senha', { exact: true }).fill(root.senha);
  await page.route('**/api/painel', route => route.fulfill({ status: 503, body: '{}' }));
  await page.getByRole('button', { name: 'Entrar', exact: true }).click();
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
