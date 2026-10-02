import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly api = 'http://localhost:8080/api';

  constructor(private http: HttpClient) {}

  getPainel() {
    return this.http.get<any>(`${this.api}/painel`, { withCredentials: true });
  }

  getAuditoria() {
    return this.http.get<any>(`${this.api}/auditoria`, { withCredentials: true });
  }

  getEndpoints() {
    return this.http.get<any>(`${this.api}/endpoints`, { withCredentials: true });
  }

  getRelatorios() {
    return this.http.get<any>(`${this.api}/relatorios`, { withCredentials: true });
  }
}

