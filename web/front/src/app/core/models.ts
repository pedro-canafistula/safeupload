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

export type Verdict = 'Approved' | 'Blocked' | 'AllowedWithoutInspection' | 'Retained';
export type Category = 'Cpf' | 'Cnpj' | 'PaymentCard' | 'Password' | 'Secret';
export type AuditChannel = 'File' | 'Clipboard' | 'Web';
export interface AuditEvent {
  eventId: string;
  occurredAtUtc: string;
  endpointId: string;
  userName: string;
  fileName: string;
  sizeBytes: number;
  verdict: Verdict;
  categories: Category[];
  channel: AuditChannel;
  publishedSha256Hex?: string | null;
  notInspectedReason: string | null;
  extension?: string | null;
  processName?: string | null;
  processId?: number | null;
  destinationPath?: string | null;
  policyVersion?: number | null;
  elapsedMs?: number | null;
}
export interface Summary { total: number; bloqueados: number; aprovados: number; liberadosSemInspecao: number; retidos?: number; }
export interface Dashboard {
  periodo: string;
  resumo: Summary;
  tendencia: { data: string; quantidade: number }[];
  categoriasBloqueadas: { codigo: Category; nome: string; quantidade: number }[];
  recentes: AuditEvent[];
  categoriasAtivas: Category[];
}
export interface AuditOverride {
  eventId: string;
  justification: string;
  occurredAtUtc: string;
  userName: string;
  endpointId: string;
}
export interface Audit { resumo: Summary; eventos: AuditEvent[]; endpoint: string; justificativas?: AuditOverride[]; }
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
  Approved: 'Aprovado', Blocked: 'Bloqueado', AllowedWithoutInspection: 'Liberado sem inspeção', Retained: 'Retido'
};
export const categoryLabels: Record<Category, string> = {
  Cpf: 'CPF', Cnpj: 'CNPJ', PaymentCard: 'Cartão de pagamento',
  Password: 'Senha em texto claro', Secret: 'Segredo/credencial'
};

