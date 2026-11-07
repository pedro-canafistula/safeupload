import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { AddressPayload } from './auth.service';
import {
  Audit, Dashboard, Endpoints, Grupo, GrupoRequest, PoliticaDetalhe, PoliticaRequest, PoliticaResumo, RegraCondicao,
  RegraDetalhe, RegraRequest, RegraResumo, RegraTeste, TokenCadastro
} from './models';

/** Resposta de POST /admin/token. */
export interface GerarTokenResponse {
  token: string;
  expiraEm: string;
}

/** Corpo de POST /auth/normalregister/empresa/set (EmpresaRegister no backend). */
export interface CadastroEmpresaRequest {
  razao_social: string;
  nome_fantasia: string;
  cnpj: string;
  email_contato: string;
  telefone_contato: string;
  endereco: AddressPayload;
}

/** Item de GET /auth/normalregister/empresa/list (ListEmpresaResponse no backend). */
export interface EmpresaResumo {
  id_empresa: number;
  razao_social: string;
}

/** Corpo de POST /auth/normalregister/usuario/set. O backend registra o criador pela sessão. */
export interface CadastroUsuarioRequest {
  username: string;
  email: string;
  cpf: string;
  senha: string;
  nome_completo: string;
  data_nascimento: string;
  fk_id_empresa: number;
  endereco: AddressPayload;
  role: string;
}

export interface CadastroResponse {
  status: string;
  mensagem: string;
}

const sessao = { withCredentials: true };

@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(private http: HttpClient) {}

  getPainel() {
    return this.http.get<Dashboard>('/api/painel', sessao);
  }

  getAuditoria(host: number | null = null) {
    return this.http.get<Audit>('/api/auditoria', { ...sessao, params: host === null ? {} : { host } });
  }

  /** CSV dos últimos 7 dias (todas as máquinas ou uma). */
  exportarAuditoria(host: number | null = null) {
    return this.http.get('/api/auditoria/exportar', { ...sessao, params: host === null ? {} : { host }, responseType: 'blob' });
  }

  getEndpoints(status = 'all', q = '') {
    return this.http.get<Endpoints>('/api/endpoints', { ...sessao, params: { status, q } });
  }

  atribuirGrupo(hostId: number, grupoId: number | null) {
    return this.http.put<void>(`/api/endpoints/${hostId}/grupo`, { grupoId }, sessao);
  }

  revogarEndpoint(hostId: number) {
    return this.http.post<void>(`/api/endpoints/${hostId}/revogar`, {}, sessao);
  }

  listarPoliticas() {
    return this.http.get<PoliticaResumo[]>('/api/politicas', sessao);
  }

  obterPolitica(id: number) {
    return this.http.get<PoliticaDetalhe>(`/api/politicas/${id}`, sessao);
  }

  criarPolitica(payload: PoliticaRequest) {
    return this.http.post<{ id: number; versao: number }>('/api/politicas', payload, sessao);
  }

  atualizarPolitica(id: number, payload: PoliticaRequest) {
    return this.http.put<{ id: number; versao: number }>(`/api/politicas/${id}`, payload, sessao);
  }

  excluirPolitica(id: number) {
    return this.http.delete<void>(`/api/politicas/${id}`, sessao);
  }

  listarGrupos() {
    return this.http.get<Grupo[]>('/api/grupos', sessao);
  }

  criarGrupo(payload: GrupoRequest) {
    return this.http.post<{ id: number }>('/api/grupos', payload, sessao);
  }

  atualizarGrupo(id: number, payload: GrupoRequest) {
    return this.http.put<void>(`/api/grupos/${id}`, payload, sessao);
  }

  excluirGrupo(id: number) {
    return this.http.delete<void>(`/api/grupos/${id}`, sessao);
  }

  listarRegras() {
    return this.http.get<RegraResumo[]>('/api/regras', sessao);
  }

  obterRegra(id: number) {
    return this.http.get<RegraDetalhe>(`/api/regras/${id}`, sessao);
  }

  criarRegra(payload: RegraRequest) {
    return this.http.post<{ id: number; revisao: number }>('/api/regras', payload, sessao);
  }

  atualizarRegra(id: number, payload: RegraRequest) {
    return this.http.put<{ id: number; revisao: number }>(`/api/regras/${id}`, payload, sessao);
  }

  excluirRegra(id: number) {
    return this.http.delete<void>(`/api/regras/${id}`, sessao);
  }

  /** Avalia condições ainda não salvas sobre até 10 textos. */
  testarRegra(quando: RegraCondicao, textos: string[]) {
    return this.http.post<RegraTeste[]>('/api/regras/testar', { quando, textos }, sessao);
  }

  gerarToken() {
    return this.http.post<GerarTokenResponse>('/api/admin/token', {}, sessao);
  }

  listarTokens() {
    return this.http.get<TokenCadastro[]>('/api/admin/tokens', sessao);
  }

  excluirToken(id: number) {
    return this.http.delete<void>(`/api/admin/tokens/${id}`, sessao);
  }

  listarEmpresas() {
    return this.http.get<EmpresaResumo[]>('/api/auth/normalregister/empresa/list', sessao);
  }

  cadastrarEmpresa(payload: CadastroEmpresaRequest) {
    return this.http.post<CadastroResponse>('/api/auth/normalregister/empresa/set', payload, sessao);
  }

  cadastrarUsuario(payload: CadastroUsuarioRequest) {
    return this.http.post<CadastroResponse>('/api/auth/normalregister/usuario/set', payload, sessao);
  }
}

/** Entrega um arquivo baixado pelo HttpClient ao navegador (mantém a sessão e o tratamento de erro). */
export function salvarArquivo(conteudo: Blob, nome: string): void {
  const url = URL.createObjectURL(conteudo);
  const link = document.createElement('a');
  link.href = url;
  link.download = nome;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
