import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';
import { environment } from '../../../environments/environment';
import { CadastroRequest, LoginRequest, UsuarioResponse } from '../models/auth.models';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly baseUrl = `${environment.apiUrl}/auth`;

  // Guardado em memória só para a UI (ex: mostrar o nome no cabeçalho).
  // Quem decide se o usuário está autenticado de fato é sempre o backend.
  usuarioAtual: UsuarioResponse | null = null;

  constructor(private http: HttpClient) {}

  login(dados: LoginRequest): Observable<UsuarioResponse> {
    return this.http
      .post<UsuarioResponse>(`${this.baseUrl}/login`, dados, { withCredentials: true })
      .pipe(tap((usuario) => (this.usuarioAtual = usuario)));
  }

  cadastrar(dados: CadastroRequest): Observable<UsuarioResponse> {
    return this.http.post<UsuarioResponse>(`${this.baseUrl}/cadastro`, dados, {
      withCredentials: true,
    });
  }

  logout(): Observable<unknown> {
    return this.http
      .post(`${this.baseUrl}/logout`, {}, { withCredentials: true })
      .pipe(tap(() => (this.usuarioAtual = null)));
  }

  /** Chamado ao carregar o app para saber se já existe sessão ativa (ex: F5 na página). */
  verificarSessao(): Observable<{ idUsuario: number; role: string }> {
    return this.http.get<{ idUsuario: number; role: string }>(`${this.baseUrl}/me`, {
      withCredentials: true,
    });
  }
}
