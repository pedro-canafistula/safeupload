import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div style="padding: 32px; font-family: sans-serif;">
      <h1>Painel</h1>
      <p>Login funcionando! As telas de indicadores, auditoria etc. ainda serão migradas.</p>
      <button (click)="sair()">Sair</button>
    </div>
  `,
})
export class DashboardComponent {
  constructor(private auth: AuthService, private router: Router) {}

  sair(): void {
    this.auth.logout().subscribe(() => this.router.navigate(['/login']));
  }
}
