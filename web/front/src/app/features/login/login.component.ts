import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
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
    if (route.snapshot.queryParamMap.get('cadastrado') === '1') {
      this.sucesso = 'Cadastro realizado. Faça login para continuar.';
    }
  }

  enviar(): void {
    this.erro = '';
    this.carregando = true;

    this.auth.login({ email: this.email, senha: this.senha }).subscribe({
      next: () => this.router.navigate(['/painel']),
      error: (e) => {
        this.carregando = false;
        this.erro = (e.error as ApiErro)?.erro ?? 'Não foi possível entrar.';
      }
    });
  }
}

