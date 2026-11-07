import { HttpErrorResponse } from '@angular/common/http';
import { Observable, catchError, interval, map, merge, of, scan, startWith, switchMap } from 'rxjs';
import { ApiErro } from './models';

export interface LoadState<T> {
  loading: boolean;
  data?: T;
  error?: string;
}

/** Intervalo da atualização automática das telas Painel, Endpoints e Auditoria. */
export const ATUALIZACAO_AUTOMATICA_MS = 30_000;

export function loadState<T>(request: Observable<T>): Observable<LoadState<T>> {
  return request.pipe(
    map(data => ({ loading: false, data })),
    catchError((error: HttpErrorResponse) => of({ loading: false, error: error.status === 401
      ? 'Sua sessão expirou. Entre novamente.'
      : 'Não foi possível consultar o servidor. Tente novamente.' })),
    startWith({ loading: true })
  );
}

/** Consulta de novo a cada gatilho; enquanto recarrega, mantém os dados anteriores na tela. */
export function reload<T>(gatilho: Observable<unknown>, request: () => Observable<T>): Observable<LoadState<T>> {
  return gatilho.pipe(
    switchMap(() => loadState(request())),
    scan((anterior: LoadState<T>, atual: LoadState<T>) => atual.loading ? { ...anterior, loading: true } : atual,
      { loading: true })
  );
}

/**
 * Como `reload`, e também a cada 30 s. O timer para quando a tela é fechada (o pipe async cancela a inscrição).
 */
export function autoRefresh<T>(gatilho: Observable<unknown>, request: () => Observable<T>): Observable<LoadState<T>> {
  return reload(merge(gatilho, interval(ATUALIZACAO_AUTOMATICA_MS)), request);
}

/** Mensagem para o usuário: a `mensagem` do backend ({status, erro, mensagem}) ou o texto padrão. */
export function mensagemErro(erro: HttpErrorResponse, padrao: string): string {
  if (erro.status === 401) return 'Sua sessão expirou. Entre novamente.';
  return (erro.error as ApiErro | null)?.mensagem ?? padrao;
}
