import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../core/auth.service';

@Component({
  standalone: true,
  imports: [CommonModule],
  template: '<main class="auth-page"><section class="auth-box card">{{ mensagem }}</section></main>',
  styles: [`
    .auth-page { min-height: 100vh; display: grid; place-items: center; background: linear-gradient(120deg,#0b2b54,#123d71); padding: 24px; }
    .auth-box { width: min(420px, 100%); text-align: center; }
  `]
})
export class AuthEntryComponent implements OnInit {
  mensagem = 'Verificando configuração inicial…';

  constructor(private auth: AuthService, private router: Router) {}

  ngOnInit(): void {
    this.auth.decision().subscribe({
      next: ({ existemUsuarios }) => this.router.navigate([existemUsuarios ? '/login' : '/cadastro']),
      error: () => this.mensagem = 'Não foi possível conectar ao servidor. Verifique se o backend está ativo.'
    });
  }
}
