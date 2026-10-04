import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth.service';

@Component({
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <main class="card">
      <h1>Acesso restrito à administração</h1>
      <p>Esta conta não tem permissão para acessar o painel administrativo.</p>
      <p>O usuário final utiliza o agente instalado no computador, sem precisar acessar este painel.</p>
      <p>Se você precisa administrar o SafeUpload, entre em contato com o responsável pelo projeto.</p>
      <p role="alert" *ngIf="erro">{{ erro }}</p>
      <button *ngIf="auth.usuarioLogado; else entrar" type="button" [disabled]="saindo" (click)="sair()">
        Sair e usar outra conta
      </button>
      <ng-template #entrar><a routerLink="/login">Voltar ao login</a></ng-template>
    </main>`
})
export class AcessoNegadoComponent {
  erro = '';
  saindo = false;

  constructor(public auth: AuthService, private router: Router) {}

  sair(): void {
    this.erro = '';
    this.saindo = true;
    this.auth.logout().subscribe({
      next: () => this.router.navigate(['/login']),
      error: () => {
        this.saindo = false;
        this.erro = 'Não foi possível encerrar a sessão. Tente novamente.';
      }
    });
  }
}
