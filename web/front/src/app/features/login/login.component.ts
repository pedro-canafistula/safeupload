import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize } from 'rxjs';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth.service';
import { ApiErro } from '../../core/models';

@Component({
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css'
})
export class LoginComponent {
  email = '';
  senha = '';
  erro = '';
  sucesso = '';
  carregando = false;

  constructor(private auth: AuthService, private router: Router, route: ActivatedRoute) {
    route.queryParamMap.pipe(takeUntilDestroyed()).subscribe((params) => {
      this.sucesso = params.get('cadastrado') === '1' ? 'Cadastro realizado. Faça login para continuar.' : '';
      this.erro = '';
      if (params.get('sessao') === 'expirada') {
        this.erro = 'Sua sessão não está ativa. Entre novamente para continuar.';
      }
      if (params.get('servico') === 'indisponivel') {
        this.erro = 'Não foi possível verificar sua sessão. Tente novamente em instantes.';
      }
    });
  }

  enviar(): void {
    this.erro = '';
    this.carregando = true;

    this.auth.login({ email: this.email, senha: this.senha }).pipe(
      finalize(() => this.carregando = false)
    ).subscribe({
      next: () => this.router.navigate(['/painel']),
      error: (e) => {
        this.erro = (e.error as ApiErro)?.erro ?? 'Não foi possível entrar.';
      }
    });
  }
}

