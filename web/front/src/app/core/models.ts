export interface Usuario {
  idUsuario: number;
  nomeCompleto: string;
  username: string;
  email: string;
  role: string;
}

export interface ApiErro {
  erro?: string;
  mensagem?: string;
}

export type Verdict = 'Approved' | 'Blocked' | 'AllowedWithoutInspection' | 'Retained';
export type Category = 'Cpf' | 'Cnpj' | 'PaymentCard' | 'Password' | 'Secret'
  | 'Rg' | 'BankData' | 'HealthData' | 'ConfidentialDocument' | 'PersonalData' | 'CustomRule' | 'CustomRuleAlert';
export type AuditChannel = 'File' | 'Clipboard' | 'Web';
export interface AuditEvent {
  eventId: string;
  occurredAtUtc: string;
  /** Rótulo enviado pelo agente; a máquina de verdade é hostId/hostname (assinatura). */
  endpointId: string;
  hostId?: number;
  hostname?: string | null;
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
  /** Nomes das regras personalizadas que acharam algo (categorias CustomRule/CustomRuleAlert). */
  customRules?: string[] | null;
}
export interface Summary { total: number; bloqueados: number; aprovados: number; liberadosSemInspecao: number; retidos?: number; }
export interface PoliticaRef { id: number; nome: string; versao: number; }
export interface Dashboard {
  periodo: string;
  resumo: Summary;
  tendencia: { data: string; quantidade: number }[];
  /** Regras personalizadas vêm como codigo "Regra:<nome>" e nome "Regra: <nome>". */
  categoriasBloqueadas: { codigo: string; nome: string; quantidade: number }[];
  recentes: AuditEvent[];
  politicaPadrao: PoliticaRef | null;
  maquinas: { total: number; online: number; politicaDesatualizada: number };
}
export interface AuditOverride {
  eventId: string;
  justification: string;
  occurredAtUtc: string;
  userName: string;
  endpointId: string;
  hostId?: number;
  hostname?: string | null;
}
export interface Audit {
  resumo: Summary;
  eventos: AuditEvent[];
  host: number | null;
  justificativas?: AuditOverride[];
  limit?: number;
  truncated?: boolean;
}
export type EndpointStatus = 'online' | 'offline' | 'revogado';
export interface EndpointRow {
  hostId: number;
  hostname: string | null;
  ip: string | null;
  os: string;
  agentVersion: string | null;
  grupo: { id: number; nome: string } | null;
  politicaEsperada: PoliticaRef | null;
  /** Versão relatada pelo agente no último heartbeat. */
  politicaAplicada: number | null;
  politicaDesatualizada: boolean;
  lastSeenUtc: string | null;
  status: EndpointStatus;
  inspecoes7d: number;
}
export interface Endpoints {
  resumo: { total: number; online: number; offline: number; revogados: number };
  itens: EndpointRow[];
  onlineThresholdSeconds: number;
  limit?: number;
  truncated?: boolean;
}

// ---- Políticas e grupos (docs/console-agente.md) ----

export type CategoriaCodigo = 'cpf' | 'cnpj' | 'rg' | 'cartao_credito' | 'dados_bancarios' | 'credenciais'
  | 'dados_saude' | 'dados_pessoais' | 'documentos_confidenciais';
export type AcaoCategoria = 'bloquear' | 'alertar' | 'ignorar';
export type ModoClipboard = 'desligado' | 'alertar' | 'bloquear';
export interface PoliticaConfiguracao {
  categorias: Record<CategoriaCodigo, AcaoCategoria>;
  pastas: string[];
  pendrives: boolean;
  rede: boolean;
  extensoes: string[];
  tamanhoMaximoMb: number;
  tempoLimiteSegundos: number;
  permitirJustificativa: boolean;
  clipboard: ModoClipboard;
  /** Id da regra personalizada → ação; regras ausentes são ignoradas. */
  regrasPersonalizadas?: Record<string, AcaoCategoria>;
}
export interface PoliticaResumo {
  id: number;
  nome: string;
  padrao: boolean;
  versao: number;
  atualizadaEm: string;
  atualizadaPor: string;
  grupos: string[];
  hosts: number;
}
export interface PoliticaDetalhe {
  id: number;
  nome: string;
  padrao: boolean;
  versao: number;
  configuracao: PoliticaConfiguracao;
  historico: { versao: number; criadaEm: string; criadaPor: string }[];
}
export interface PoliticaRequest { nome: string; padrao: boolean; configuracao: PoliticaConfiguracao; }
export interface Grupo { id: number; nome: string; politicaId: number | null; politica: string | null; hosts: number; }
export interface GrupoRequest { nome: string; politicaId: number | null; }

// ---- Regras personalizadas (docs/console-agente.md) ----

export type RegraValidador = 'cpf' | 'cnpj' | 'luhn' | 'mod11';
/** Exatamente um de todos, algum, nao, contem, mascara, regex; o backend devolve os demais como null. */
export interface RegraCondicao {
  todos?: RegraCondicao[] | null;
  algum?: RegraCondicao[] | null;
  nao?: RegraCondicao | null;
  contem?: string[] | null;
  mascara?: string | null;
  regex?: string | null;
  minimo?: number | null;
  ignorarCaixa?: boolean | null;
  validador?: RegraValidador | null;
  grupoValidado?: number | null;
}
export interface RegraExemplos { sinalizar: string[]; naoSinalizar: string[]; }
export interface RegraResumo {
  id: number;
  nome: string;
  descricao: string | null;
  revisao: number;
  quando: RegraCondicao;
  atualizadaEm: string;
  atualizadaPor: string;
  /** Políticas cuja versão atual usa a regra. */
  politicas: string[];
}
export interface RegraDetalhe {
  id: number;
  nome: string;
  descricao: string | null;
  revisao: number;
  quando: RegraCondicao;
  exemplos: RegraExemplos;
  politicas: string[];
}
export interface RegraRequest { nome: string; descricao: string; quando: RegraCondicao; exemplos: RegraExemplos; }
/** Resultado de POST /regras/testar para um texto; `condicoes` segue a ordem das condições da regra. */
export interface RegraTeste { matched: boolean; condicoes: { condicao: string; ocorrencias: number; atende: boolean }[]; }

export interface TokenCadastro {
  id: number;
  /** Só vem enquanto o token está ativo. */
  token: string | null;
  estado: 'ativo' | 'usado' | 'expirado';
  criadoEm: string;
  expiraEm: string;
  criadoPor: string;
  usadoEm: string | null;
  hostId: number | null;
}

export const categoriasPolitica: { codigo: CategoriaCodigo; nome: string }[] = [
  { codigo: 'cpf', nome: 'CPF' },
  { codigo: 'cnpj', nome: 'CNPJ' },
  { codigo: 'rg', nome: 'RG' },
  { codigo: 'cartao_credito', nome: 'Cartão de crédito' },
  { codigo: 'dados_bancarios', nome: 'Dados bancários' },
  { codigo: 'credenciais', nome: 'Credenciais e segredos' },
  { codigo: 'dados_saude', nome: 'Dados de saúde' },
  { codigo: 'dados_pessoais', nome: 'Dados pessoais' },
  { codigo: 'documentos_confidenciais', nome: 'Documentos confidenciais' }
];

export const verdictLabels: Record<Verdict, string> = {
  Approved: 'Aprovado', Blocked: 'Bloqueado', AllowedWithoutInspection: 'Liberado sem inspeção', Retained: 'Retido'
};
export const categoryLabels: Record<Category, string> = {
  Cpf: 'CPF', Cnpj: 'CNPJ', PaymentCard: 'Cartão de pagamento',
  Password: 'Senha em texto claro', Secret: 'Segredo/credencial',
  Rg: 'RG', BankData: 'Dados bancários', HealthData: 'Dados de saúde',
  ConfidentialDocument: 'Documento confidencial', PersonalData: 'Dados pessoais',
  CustomRule: 'Regra personalizada', CustomRuleAlert: 'Regra personalizada (alerta)'
};
