export interface Usuario {
  idUsuario: number;
  nomeCompleto: string;
  username: string;
  email: string;
  role: string;
}

export interface ApiErro {
  erro: string;
}

export type Verdict = 'Approved' | 'Blocked' | 'AllowedWithoutInspection';
export type Category = 'Cpf' | 'Cnpj' | 'PaymentCard' | 'Password' | 'Secret';
export interface AuditEvent {
  eventId: string;
  occurredAtUtc: string;
  endpointId: string;
  userName: string;
  fileName: string;
  sizeBytes: number;
  verdict: Verdict;
  categories: Category[];
  notInspectedReason: string | null;
}
export interface Summary { total: number; bloqueados: number; aprovados: number; liberadosSemInspecao: number; }
export interface Dashboard {
  periodo: string;
  resumo: Summary;
  tendencia: { data: string; quantidade: number }[];
  categoriasBloqueadas: { codigo: Category; nome: string; quantidade: number }[];
  recentes: AuditEvent[];
  categoriasAtivas: Category[];
}
export interface Audit { resumo: Summary; eventos: AuditEvent[]; endpoint: string; }
export interface EndpointRow {
  endpointId: string;
  hostname: string;
  os: string;
  agentVersion: string;
  policyVersion: number;
  lastSeenUtc: string;
  status: 'online' | 'offline';
  inspecoes7d: number;
}
export interface Endpoints {
  resumo: { total: number; online: number; offline: number };
  itens: EndpointRow[];
  onlineThresholdSeconds: number;
}
export const verdictLabels: Record<Verdict, string> = {
  Approved: 'Aprovado', Blocked: 'Bloqueado', AllowedWithoutInspection: 'Liberado sem inspeção'
};
export const categoryLabels: Record<Category, string> = {
  Cpf: 'CPF', Cnpj: 'CNPJ', PaymentCard: 'Cartão de pagamento',
  Password: 'Senha em texto claro', Secret: 'Segredo/credencial'
};

