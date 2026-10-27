import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, tap, catchError, throwError } from 'rxjs';
import { Usuario } from './models';

export interface AuthDecision {
  status: string;
  existemUsuarios: boolean;
}

export interface FirstRegisterPayload {
  username: string;
  email: string;
  cpf: string;
  senha: string;
  nome_completo: string;
  data_nascimento: string;
  empresa: {
    razao_social: string;
    nome_fantasia: string;
    cnpj: string;
    email_contato: string;
    telefone_contato: string;
    endereco: AddressPayload;
  };
  endereco: AddressPayload;
}

export interface AddressPayload {
  cep: string;
  logradouro: string;
  numero: number;
  complemento: string;
  bairro: string;
  cidade: string;
  estado: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api = '/api';
  private readonly usuario$ = new BehaviorSubject<Usuario | null>(null);

  constructor(private http: HttpClient) {}

  decision(): Observable<AuthDecision> {
    return this.http.get<AuthDecision>(`${this.api}/auth/decision`);
  }

  get usuarioLogado(): Usuario | null {
    return this.usuario$.value;
  }

  carregarSessao(): Observable<Usuario> {
    return this.http.get<Usuario>(`${this.api}/auth/me`, { withCredentials: true }).pipe(
      tap((u) => this.usuario$.next(u)),
      catchError((erro) => {
        this.usuario$.next(null);
        return throwError(() => erro);
      })
    );
  }

  login(payload: { email: string; senha: string }): Observable<Usuario> {
    return this.http.post<Usuario>(`${this.api}/auth/login`, payload, { withCredentials: true }).pipe(
      tap((u) => this.usuario$.next(u))
    );
  }

  cadastrar(payload: FirstRegisterPayload): Observable<{ status: string; mensagem: string }> {
    return this.http.post<{ status: string; mensagem: string }>(
      `${this.api}/auth/firstregister`,
      payload,
      { withCredentials: true }
    );
  }

  logout(): Observable<unknown> {
    return this.http.post(`${this.api}/auth/logout`, {}, { withCredentials: true }).pipe(
      tap(() => this.usuario$.next(null))
    );
  }
}
