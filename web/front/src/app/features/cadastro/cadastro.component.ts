import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth.service';
import { ApiErro } from '../../core/models';

@Component({
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './cadastro.component.html',
  styleUrl: './cadastro.component.css'
})
export class CadastroComponent {
  nomeCompleto = '';
  username = '';
  email = '';
  cpf = '';
  dataNascimento = '';
  senha = '';
  confirmarSenha = '';
  erro = '';
  carregando = false;

  constructor(private auth: AuthService, private router: Router) {}

  enviar(): void {
    this.erro = '';
    this.carregando = true;

    this.auth.cadastrar({
      nomeCompleto: this.nomeCompleto,
      username: this.username,
      email: this.email,
      cpf: this.cpf,
      dataNascimento: this.dataNascimento || undefined,
      senha: this.senha,
      confirmarSenha: this.confirmarSenha
    }).subscribe({
      next: () => this.router.navigate(['/login'], { queryParams: { cadastrado: '1' } }),
      error: (e) => {
        this.carregando = false;
        this.erro = (e.error as ApiErro)?.erro ?? 'Falha ao cadastrar.';
      }
    });
  }
}

