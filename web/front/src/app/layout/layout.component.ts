import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from '../core/auth.service';

@Component({
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './layout.component.html',
  styleUrl: './layout.component.css'
})
export class LayoutComponent {
  menu = [
    { rota: '/painel', titulo: 'Visão geral', icone: '▦' },
    { rota: '/politicas', titulo: 'Políticas', icone: '◧' },
    { rota: '/endpoints', titulo: 'Endpoints', icone: '▣' },
    { rota: '/auditoria', titulo: 'Auditoria', icone: '◷' },
    { rota: '/relatorios', titulo: 'Relatórios', icone: '▤' },
    { rota: '/novos-cadastros', titulo: 'Novos Cadastros', icone: '◫' },
    { rota: '/configuracoes', titulo: 'Configurações', icone: '⚙' }
  ];

  constructor(public auth: AuthService, private router: Router) {}

  get paginaAtual(): string {
    const caminho = this.router.url.split(/[?#]/)[0];
    return this.menu.find(item => caminho === item.rota || caminho.startsWith(item.rota + '/'))?.titulo ?? '';
  }

  sair(): void {
    this.auth.logout().subscribe({ next: () => this.router.navigate(['/login']) });
  }
}
