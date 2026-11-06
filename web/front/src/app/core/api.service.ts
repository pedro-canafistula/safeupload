import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { AddressPayload } from './auth.service';
import { Audit, Dashboard, Endpoints } from './models';

export interface PublicarPoliticaRequest {
  versao: string;
  nome: string;
  destino: { ip: string };
  acao: string;
  regras: { tipo: string; nome: string }[];
  criadaEm: string;
  origem: string;
}

export interface PublicarPoliticaResponse {
  status: string;
  mensagem: string;
}

/** Resposta de POST /admin/token (TokenResponse no backend). */
export interface GerarTokenResponse {
  resposta: { status: string; mensagem: string };
  token: string;
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

/** Corpo de POST /auth/normalregister/usuario/set (UsuarioRegister no backend). */
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
  criado_por: string;
}

export interface CadastroResponse {
  status: string;
  mensagem: string;
}

@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(private http: HttpClient) {}

  getPainel() {
    return this.http.get<Dashboard>('/api/painel', { withCredentials: true });
  }

  getAuditoria(endpoint = '') {
    return this.http.get<Audit>('/api/auditoria', { params: { endpoint }, withCredentials: true });
  }

  getEndpoints(status = 'all', os = 'all', q = '') {
    return this.http.get<Endpoints>('/api/endpoints', { params: { status, os, q }, withCredentials: true });
  }

  publicarPolitica(payload: PublicarPoliticaRequest) {
    return this.http.post<PublicarPoliticaResponse>('/api/politicas', payload, { withCredentials: true });
  }

  gerarToken() {
    return this.http.post<GerarTokenResponse>('/api/admin/token', {}, { withCredentials: true });
  }

  listarEmpresas() {
    return this.http.get<EmpresaResumo[]>('/api/auth/normalregister/empresa/list', { withCredentials: true });
  }

  cadastrarEmpresa(payload: CadastroEmpresaRequest) {
    return this.http.post<CadastroResponse>('/api/auth/normalregister/empresa/set', payload, { withCredentials: true });
  }

  cadastrarUsuario(payload: CadastroUsuarioRequest) {
    return this.http.post<CadastroResponse>('/api/auth/normalregister/usuario/set', payload, { withCredentials: true });
  }
}
