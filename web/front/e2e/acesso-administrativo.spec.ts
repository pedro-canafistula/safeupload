import { expect, test } from '@playwright/test';
import { administradorSimulado as administrador, painelVazio as painel } from './support/sessao';

for (const perfil of ['user', 'desconhecido', '']) {
  test(`perfil '${perfil}' não acessa telas nem consulta dados administrativos`, async ({ page }) => {
    const consultas: string[] = [];
    await page.route('**/api/**', async route => {
      if (route.request().url().endsWith('/auth/me')) {
        await route.fulfill({ json: { ...administrador, role: perfil } });
      } else {
        consultas.push(route.request().url());
        await route.fulfill({ status: 403, json: {} });
      }
    });
    for (const tela of ['painel', 'auditoria', 'endpoints', 'relatorios', 'politicas', 'politicas/nova', 'novos-cadastros', 'configuracoes']) {
      await page.goto('/' + tela);
      await expect(page).toHaveURL(/acesso-negado$/);
      await expect(page.getByRole('heading', { name: 'Acesso restrito à administração' })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Políticas', exact: true })).toHaveCount(0);
    }
    expect(consultas).toEqual([]);
  });
}

test('administrador entra e a sessão é revalidada ao navegar entre telas', async ({ page }) => {
  let expirada = false;
  let consultasAuditoria = 0;
  await page.route('**/api/auth/me', route => route.fulfill(
    expirada ? { status: 401, json: {} } : { json: administrador }
  ));
  await page.route('**/api/painel', route => route.fulfill({ json: painel }));
  await page.route('**/api/auditoria**', route => {
    consultasAuditoria++;
    return route.fulfill({ status: 401, json: {} });
  });
  await page.goto('/painel');
  await expect(page.getByRole('heading', { name: 'Visão geral' })).toBeVisible();
  expirada = true;
  await page.getByRole('link', { name: 'Ver todas', exact: true }).click();
  await expect(page).toHaveURL(/login\?sessao=expirada$/);
  await expect(page.getByRole('alert')).toContainText('Sua sessão não está ativa');
  expect(consultasAuditoria).toBe(0);
});

test('mudança de perfil bloqueia navegação mesmo com usuário em memória', async ({ page }) => {
  let perfil = 'admin';
  await page.route('**/api/auth/me', route => route.fulfill({ json: { ...administrador, role: perfil } }));
  await page.route('**/api/painel', route => route.fulfill({ json: painel }));
  await page.goto('/painel');
  await expect(page.getByRole('heading', { name: 'Visão geral' })).toBeVisible();
  perfil = 'user';
  await page.getByRole('link', { name: 'Políticas', exact: true }).click();
  await expect(page).toHaveURL(/acesso-negado$/);
});

test('falha de conexão não é apresentada como sessão expirada', async ({ page }) => {
  await page.route('**/api/auth/me', route => route.fulfill({ status: 503, json: {} }));
  await page.goto('/auditoria');
  await expect(page).toHaveURL(/login\?servico=indisponivel$/);
  await expect(page.getByRole('alert')).toContainText('Não foi possível verificar sua sessão');
});

test('login comum leva ao aviso e permite encerrar a sessão', async ({ page }) => {
  await page.route('**/api/auth/login', route => route.fulfill({ json: { ...administrador, role: 'user' } }));
  await page.route('**/api/auth/me', route => route.fulfill({ json: { ...administrador, role: 'user' } }));
  await page.route('**/api/auth/logout', route => route.fulfill({ json: {} }));
  await page.goto('/login');
  await page.getByLabel('E-mail').fill('user@example.com');
  await page.getByLabel('Senha', { exact: true }).fill('senha-de-teste');
  await page.getByRole('button', { name: 'Entrar', exact: true }).click();
  await expect(page).toHaveURL(/acesso-negado$/);
  await page.getByRole('button', { name: 'Sair e usar outra conta' }).click();
  await expect(page).toHaveURL(/\/login$/);
});

test('falha ao verificar sessão após login permite tentar novamente', async ({ page }) => {
  await page.route('**/api/auth/login', route => route.fulfill({ json: administrador }));
  await page.route('**/api/auth/me', route => route.fulfill({ status: 503, json: {} }));
  await page.goto('/login');
  await page.getByLabel('E-mail').fill('admin@example.com');
  await page.getByLabel('Senha', { exact: true }).fill('senha-de-teste');
  await page.getByRole('button', { name: 'Entrar', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Não foi possível verificar sua sessão');
  await expect(page.getByRole('button', { name: 'Entrar', exact: true })).toBeEnabled();
  await page.route('**/api/auth/me', route => route.fulfill({ json: administrador }));
  await page.route('**/api/painel', route => route.fulfill({ json: painel }));
  await page.getByRole('button', { name: 'Entrar', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Visão geral' })).toBeVisible();
});

test('painel, endpoints e auditoria se atualizam a cada 30 s e param ao sair da tela', async ({ page }) => {
  await page.clock.install();
  const consultas = { painel: 0, endpoints: 0, auditoria: 0 };
  await page.route('**/api/auth/me', route => route.fulfill({ json: administrador }));
  await page.route('**/api/painel', route => { consultas.painel++; return route.fulfill({ json: painel }); });
  await page.route('**/api/endpoints**', route => { consultas.endpoints++; return route.fulfill({ json: {
    resumo: { total: 0, online: 0, offline: 0, revogados: 0 }, itens: [], onlineThresholdSeconds: 120 } }); });
  await page.route('**/api/grupos', route => route.fulfill({ json: [] }));
  await page.route('**/api/auditoria**', route => { consultas.auditoria++; return route.fulfill({ json: {
    resumo: painel.resumo, eventos: [], host: null, justificativas: [] } }); });

  await page.goto('/painel');
  await expect.poll(() => consultas.painel).toBe(1);
  await page.clock.fastForward(30_000);
  await expect.poll(() => consultas.painel).toBe(2);
  await page.getByRole('button', { name: 'Atualizar' }).click();
  await expect.poll(() => consultas.painel).toBe(3);

  await page.getByRole('link', { name: 'Endpoints', exact: true }).click();
  await expect.poll(() => consultas.endpoints).toBe(1);
  await page.clock.fastForward(30_000);
  await expect.poll(() => consultas.endpoints).toBe(2);

  await page.getByRole('link', { name: 'Auditoria', exact: true }).click();
  await expect.poll(() => consultas.auditoria).toBe(1);
  await page.clock.fastForward(30_000);
  await expect.poll(() => consultas.auditoria).toBe(2);
  // As telas fechadas não consultam mais.
  expect(consultas.painel).toBe(3);
  expect(consultas.endpoints).toBe(2);
});

test('endpoints não filtram por sistema operacional', async ({ page }) => {
  await page.route('**/api/auth/me', route => route.fulfill({ json: administrador }));
  await page.route('**/api/endpoints**', route => route.fulfill({ json: {
    resumo: { total: 1, online: 1, offline: 0, revogados: 0 }, onlineThresholdSeconds: 120, itens: [{
      hostId: 3, hostname: 'PC-01', ip: '10.0.0.3', os: 'Windows 10.0.19045', agentVersion: '0.2.0', grupo: null,
      politicaEsperada: null, politicaAplicada: null, politicaDesatualizada: false, lastSeenUtc: '2026-11-07T12:00:00Z',
      status: 'online', inspecoes7d: 0 }] } }));
  await page.route('**/api/grupos', route => route.fulfill({ json: [] }));
  await page.goto('/endpoints');
  await expect(page.getByRole('cell', { name: /^PC-01/ })).toBeVisible();
  await expect(page.getByText('Sem política')).toBeVisible();
  await expect(page.getByLabel('Sistema')).toHaveCount(0);
  expect(page.url()).not.toContain('os=');
});
