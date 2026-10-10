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
    { rota: '/painel', titulo: 'Painel' },
    { rota: '/auditoria', titulo: 'Auditoria' },
    { rota: '/endpoints', titulo: 'Endpoints' },
    { rota: '/relatorios', titulo: 'Relatórios' }
  ];

  constructor(public auth: AuthService, private router: Router) {}

  sair(): void {
    this.auth.logout().subscribe({ next: () => this.router.navigate(['/login']) });
  }
}

