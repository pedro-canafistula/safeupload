import { type Page } from '@playwright/test';

export async function preencherPolitica(page: Page, nome: string, ip: string, categoria: string, acao: 'Alertar' | 'Bloquear'): Promise<void> {
  await page.goto('/politicas');
  await page.getByLabel('Nome da política').fill(nome);
  await page.getByRole('button', { name: 'Continuar' }).click();
  await page.getByLabel('Endpoint no escopo').fill(ip);
  await page.getByRole('button', { name: 'Continuar' }).click();
  await page.locator('.rule-card').filter({ has: page.getByText(categoria, { exact: true }) }).click();
  await page.getByRole('button', { name: 'Continuar' }).click();
  await page.getByRole('radio', { name: new RegExp(acao) }).check();
  await page.getByRole('button', { name: 'Continuar' }).click();
  await page.getByRole('button', { name: 'Continuar' }).click();
}
