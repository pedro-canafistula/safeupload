import { RegraCondicao, RegraValidador } from '../../core/models';

export const nomesValidadores: Record<RegraValidador, string> = {
  cpf: 'CPF', cnpj: 'CNPJ', luhn: 'Cartão (Luhn)', mod11: 'Módulo 11'
};

export type TipoCondicao = 'contem' | 'naoContem' | 'mascara' | 'regex';

/** Uma linha do editor: o editor monta um nível de condições (todas ou alguma), cada uma folha ou "não contém". */
export interface CondicaoEdicao {
  tipo: TipoCondicao;
  /** Palavras ou frases, uma por linha ou separadas por vírgula. */
  palavras: string;
  /** Máscara ou expressão regular. */
  padrao: string;
  minimo: number | null;
  ignorarCaixa: boolean;
  validador: RegraValidador | '';
  grupoValidado: number | null;
}

export function condicaoVazia(tipo: TipoCondicao = 'contem'): CondicaoEdicao {
  return { tipo, palavras: '', padrao: '', minimo: 1, ignorarCaixa: false, validador: '', grupoValidado: 0 };
}

export function termos(texto: string): string[] {
  return texto.split(/\r?\n|,/).map(termo => termo.trim()).filter(Boolean);
}

/** Linha do editor → condição no formato do backend (só os campos do tipo escolhido). */
export function paraCondicao(linha: CondicaoEdicao): RegraCondicao {
  const minimo = linha.minimo === null || linha.minimo === 1 ? {} : { minimo: Number(linha.minimo) };
  switch (linha.tipo) {
    case 'contem': return { contem: termos(linha.palavras), ...minimo };
    case 'naoContem': return { nao: { contem: termos(linha.palavras), ...minimo } };
    case 'mascara': return { mascara: linha.padrao, ...minimo, ...(linha.validador ? { validador: linha.validador } : {}) };
    case 'regex': return {
      regex: linha.padrao, ...minimo, ...(linha.ignorarCaixa ? { ignorarCaixa: true } : {}),
      ...(linha.validador ? { validador: linha.validador } : {}),
      ...(linha.validador && linha.grupoValidado ? { grupoValidado: Number(linha.grupoValidado) } : {})
    };
  }
}

/**
 * Condição do backend → modo e linhas do editor. Devolve null quando a regra usa o que o editor não monta
 * (grupos dentro de grupos, ou "não" sobre máscara, regex ou grupo); regras assim só são criadas pela API.
 */
export function paraEdicao(quando: RegraCondicao): { modo: 'todos' | 'algum'; linhas: CondicaoEdicao[] } | null {
  const modo = quando.algum ? 'algum' : 'todos';
  const filhas = quando.todos ?? quando.algum ?? [quando];
  const linhas: CondicaoEdicao[] = [];
  for (const filha of filhas) {
    const linha = folha(filha) ?? (filha.nao && filha.nao.contem ? { ...folha(filha.nao)!, tipo: 'naoContem' as const } : null);
    if (!linha) return null;
    linhas.push(linha);
  }
  return { modo, linhas };
}

function folha(c: RegraCondicao): CondicaoEdicao | null {
  const base = { ...condicaoVazia(), minimo: c.minimo ?? 1, validador: c.validador ?? '' as const, grupoValidado: c.grupoValidado ?? 0 };
  if (c.contem) return { ...base, tipo: 'contem', palavras: c.contem.join('\n') };
  if (c.mascara != null) return { ...base, tipo: 'mascara', padrao: c.mascara };
  if (c.regex != null) return { ...base, tipo: 'regex', padrao: c.regex, ignorarCaixa: c.ignorarCaixa === true };
  return null;
}

/** "Como texto": contém "projeto atlas" E pelo menos 2× CT-####/## E NÃO contém "divulgação autorizada". */
export function descrever(c: RegraCondicao | null | undefined, raiz = true): string {
  if (!c) return '…';
  if (c.todos || c.algum) {
    const partes = (c.todos ?? c.algum ?? []).map(filha => descrever(filha, false));
    const texto = partes.join(c.todos ? ' E ' : ' OU ') || '…';
    return raiz || partes.length < 2 ? texto : `(${texto})`;
  }
  if (c.nao) return 'NÃO ' + descrever(c.nao, false);
  const vezes = c.minimo && c.minimo > 1 ? `pelo menos ${c.minimo}× ` : '';
  if (c.contem) {
    const lista = c.contem.length ? c.contem.map(termo => `"${termo}"`).join(' ou ') : '…';
    return `contém ${vezes}${lista}`;
  }
  const validador = c.validador
    ? nomesValidadores[c.validador] + ' válido' + (c.grupoValidado ? ` no grupo ${c.grupoValidado}` : '') : '';
  if (c.mascara != null) return `${vezes}${c.mascara || '…'}${validador ? ` (${validador})` : ''}`;
  if (c.regex != null) {
    const opcoes = [c.ignorarCaixa ? 'ignorando maiúsculas' : '', validador].filter(Boolean);
    return `${vezes}/${c.regex || '…'}/${opcoes.length ? ` (${opcoes.join(', ')})` : ''}`;
  }
  return '…';
}
