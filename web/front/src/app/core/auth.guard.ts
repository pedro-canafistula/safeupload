import { inject } from '@angular/core';
import { CanActivateChildFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';
import { AuthService } from './auth.service';

export const authGuard: CanActivateChildFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  return auth.carregarSessao().pipe(
    map((usuario) => usuario.role === 'admin' ? true : router.createUrlTree(['/acesso-negado'])),
    catchError((erro) => of(router.createUrlTree(['/login'], {
      queryParams: erro.status === 401 ? { sessao: 'expirada' } : { servico: 'indisponivel' }
    })))
  );
};

