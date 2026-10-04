import { expect, test } from '@playwright/test';

const administrador = {
  idUsuario: 1, nomeCompleto: 'Administrador de teste', username: 'admin-teste',
  email: 'admin@example.com', role: 'admin'
};
const painel = {
  periodo: 'Últimos 7 dias', resumo: { total: 0, bloqueados: 0, aprovados: 0, liberadosSemInspecao: 0 },
  tendencia: [], categoriasBloqueadas: [], recentes: [], categoriasAtivas: []
};

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
    for (const tela of ['painel', 'auditoria', 'endpoints', 'relatorios']) {
      await page.goto('/' + tela);
      await expect(page).toHaveURL(/acesso-negado$/);
      await expect(page.getByRole('heading', { name: 'Acesso restrito à administração' })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Auditoria', exact: true })).toHaveCount(0);
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
  await page.getByRole('link', { name: 'Auditoria', exact: true }).click();
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
  await page.getByRole('link', { name: 'Endpoints', exact: true }).click();
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
