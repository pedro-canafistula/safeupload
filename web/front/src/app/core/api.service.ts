import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
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
}
