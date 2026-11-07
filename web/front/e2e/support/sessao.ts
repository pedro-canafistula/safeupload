import { expect, type Page } from '@playwright/test';

export async function entrar(page: Page, email: string, senha: string): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('E-mail').fill(email);
  await page.getByLabel('Senha', { exact: true }).fill(senha);
  await page.getByRole('button', { name: 'Entrar', exact: true }).click();
  await expect(page).toHaveURL(/\/painel$/);
}

/** Usuário de /auth/me para os testes que simulam o backend. */
export const administradorSimulado = {
  idUsuario: 1, nomeCompleto: 'Administrador de teste', username: 'admin-teste', email: 'admin@example.com', role: 'admin'
};

/** GET /painel vazio no formato atual. */
export const painelVazio = {
  periodo: 'Últimos 7 dias (UTC)', resumo: { total: 0, bloqueados: 0, aprovados: 0, liberadosSemInspecao: 0, retidos: 0 },
  tendencia: [], categoriasBloqueadas: [], recentes: [], politicaPadrao: null,
  maquinas: { total: 0, online: 0, politicaDesatualizada: 0 }
};

export function semRolagemHorizontal(page: Page): Promise<boolean> {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
}
