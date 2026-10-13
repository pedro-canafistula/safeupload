import { Injectable } from '@angular/core';

export type Severity = 'Crítico' | 'Alto' | 'Médio' | 'Baixo';
export type IncidentStatus = 'Novo' | 'Em análise' | 'Resolvido' | 'Escalado';
export interface Incident { id: string; severity: Severity; policy: string; user: string; area: string; channel: string; action: string; status: IncidentStatus; when: string; }
export interface Policy { name: string; description: string; channels: string; action: string; occurrences: number; }

@Injectable({ providedIn: 'root' })
export class MockDataService {
  readonly incidents: Incident[] = [
    { id: 'INC-4821', severity: 'Crítico', policy: 'CPF e dados pessoais (LGPD)', user: 'marina.souza', area: 'Financeiro', channel: 'E-mail', action: 'Bloqueado', status: 'Novo', when: 'há 12 min' },
    { id: 'INC-4820', severity: 'Alto', policy: 'Cartão de crédito (PCI)', user: 'rafael.lima', area: 'Vendas', channel: 'Upload web', action: 'Bloqueado', status: 'Em análise', when: 'há 41 min' },
    { id: 'INC-4819', severity: 'Médio', policy: 'Documentos confidenciais', user: 'paulo.dias', area: 'Jurídico', channel: 'USB', action: 'Alertado', status: 'Novo', when: 'há 1 h' },
    { id: 'INC-4818', severity: 'Alto', policy: 'Código-fonte', user: 'carla.nunes', area: 'Engenharia', channel: 'Git / nuvem', action: 'Bloqueado', status: 'Em análise', when: 'há 2 h' },
    { id: 'INC-4817', severity: 'Baixo', policy: 'Dados de saúde', user: 'lucas.melo', area: 'RH', channel: 'Chat', action: 'Permitido + log', status: 'Resolvido', when: 'há 3 h' },
    { id: 'INC-4816', severity: 'Crítico', policy: 'Dados bancários', user: 'ana.prado', area: 'Financeiro', channel: 'Nuvem', action: 'Quarentena', status: 'Escalado', when: 'há 5 h' },
    { id: 'INC-4815', severity: 'Médio', policy: 'CPF e dados pessoais (LGPD)', user: 'tiago.reis', area: 'Atendimento', channel: 'Impressão', action: 'Alertado', status: 'Novo', when: 'há 6 h' },
    { id: 'INC-4814', severity: 'Baixo', policy: 'Documentos confidenciais', user: 'bia.costa', area: 'Marketing', channel: 'E-mail', action: 'Permitido + log', status: 'Resolvido', when: 'há 8 h' }
  ];
  readonly policies: Policy[] = [
    { name: 'CPF e dados pessoais (LGPD)', description: 'Identificadores, contato, nascimento', channels: 'E-mail, Web, Nuvem, USB', action: 'Bloquear', occurrences: 214 },
    { name: 'Cartão de crédito (PCI)', description: 'Números validados por Luhn', channels: 'Todos os canais', action: 'Bloquear', occurrences: 63 },
    { name: 'Código-fonte e segredos', description: 'Chaves, tokens, repositórios', channels: 'Git, Web, Nuvem', action: 'Bloquear', occurrences: 41 },
    { name: 'Documentos confidenciais', description: 'Rótulo e impressão digital', channels: 'E-mail, USB, Impressão', action: 'Alertar', occurrences: 157 },
    { name: 'Dados de saúde', description: 'CID, laudos, atestados', channels: 'E-mail, Chat', action: 'Alertar', occurrences: 18 },
    { name: 'Dados bancários', description: 'Agência, conta, PIX', channels: 'Todos os canais', action: 'Quarentena', occurrences: 29 }
  ];
}
