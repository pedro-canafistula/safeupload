import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { ErroApi } from '../../core/models/auth.models';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css',
})
export class LoginComponent {
  email = '';
  senha = '';
  erro: string | null = null;
  sucesso: string | null = null;
  carregando = false;

  constructor(private auth: AuthService, private router: Router, private route: ActivatedRoute) {
    if (this.route.snapshot.queryParamMap.get('cadastrado') === '1') {
      this.sucesso = 'Cadastro realizado. Faça login para continuar.';
    }
  }

  enviar(): void {
    this.erro = null;
    this.carregando = true;

    this.auth.login({ email: this.email, senha: this.senha }).subscribe({
      next: () => {
        this.router.navigate(['/dashboard']);
      },
      error: (resposta) => {
        this.carregando = false;
        const corpo = resposta.error as ErroApi | undefined;
        this.erro = corpo?.erro ?? 'Não foi possível fazer login. Tente novamente.';
      },
    });
  }
}
