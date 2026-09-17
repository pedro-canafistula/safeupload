import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { ErroApi } from '../../core/models/auth.models';

@Component({
  selector: 'app-cadastro',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './cadastro.component.html',
  styleUrl: './cadastro.component.css',
})
export class CadastroComponent {
  nomeCompleto = '';
  username = '';
  email = '';
  cpf = '';
  dataNascimento = '';
  senha = '';
  confirmarSenha = '';

  erro: string | null = null;
  carregando = false;

  constructor(private auth: AuthService, private router: Router) {}

  enviar(): void {
    this.erro = null;
    this.carregando = true;

    this.auth
      .cadastrar({
        nomeCompleto: this.nomeCompleto,
        username: this.username,
        email: this.email,
        cpf: this.cpf,
        senha: this.senha,
        confirmarSenha: this.confirmarSenha,
        dataNascimento: this.dataNascimento || undefined,
      })
      .subscribe({
        next: () => {
          // O login é quem mostra "cadastro realizado" (equivalente ao flash antigo).
          this.router.navigate(['/login'], { queryParams: { cadastrado: '1' } });
        },
        error: (resposta) => {
          this.carregando = false;
          const corpo = resposta.error as ErroApi | undefined;
          this.erro = corpo?.erro ?? 'Não foi possível concluir o cadastro.';
        },
      });
  }
}
