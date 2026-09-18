import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { Usuario } from './models';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api = 'http://localhost:8080/api';
  private readonly usuario$ = new BehaviorSubject<Usuario | null>(null);

  constructor(private http: HttpClient) {}

  get usuarioLogado(): Usuario | null {
    return this.usuario$.value;
  }

  carregarSessao(): Observable<Usuario> {
    return this.http.get<Usuario>(`${this.api}/auth/me`, { withCredentials: true }).pipe(
      tap((u) => this.usuario$.next(u))
    );
  }

  login(payload: { email: string; senha: string }): Observable<Usuario> {
    return this.http.post<Usuario>(`${this.api}/auth/login`, payload, { withCredentials: true }).pipe(
      tap((u) => this.usuario$.next(u))
    );
  }

  cadastrar(payload: {
    nomeCompleto: string;
    username: string;
    email: string;
    cpf: string;
    dataNascimento?: string;
    senha: string;
    confirmarSenha: string;
  }): Observable<Usuario> {
    return this.http.post<Usuario>(`${this.api}/auth/cadastro`, payload, { withCredentials: true });
  }

  logout(): Observable<unknown> {
    return this.http.post(`${this.api}/auth/logout`, {}, { withCredentials: true }).pipe(
      tap(() => this.usuario$.next(null))
    );
  }
}

