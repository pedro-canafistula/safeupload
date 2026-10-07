import { HttpErrorResponse } from '@angular/common/http';
import { Observable, catchError, map, of, startWith } from 'rxjs';

export interface LoadState<T> {
  loading: boolean;
  data?: T;
  error?: string;
}

export function loadState<T>(request: Observable<T>): Observable<LoadState<T>> {
  return request.pipe(
    map(data => ({ loading: false, data })),
    catchError((error: HttpErrorResponse) => of({ loading: false, error: error.status === 401
      ? 'Sua sessão expirou. Entre novamente.'
      : 'Não foi possível consultar o servidor. Tente novamente.' })),
    startWith({ loading: true })
  );
}
