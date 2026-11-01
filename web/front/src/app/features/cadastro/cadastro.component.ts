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
  cadastro = {
    nome_completo: '', username: '', email: '', cpf: '', data_nascimento: '', senha: '', confirmarSenha: '',
    empresa: {
      razao_social: '', nome_fantasia: '', cnpj: '', email_contato: '', telefone_contato: '',
      endereco: { cep: '', logradouro: '', numero: 0, complemento: '', bairro: '', cidade: '', estado: '' }
    },
    endereco: { cep: '', logradouro: '', numero: 0, complemento: '', bairro: '', cidade: '', estado: '' }
  };
  erro = '';
  carregando = false;

  constructor(private auth: AuthService, private router: Router) {
    this.auth.decision().subscribe({
      next: ({ existemUsuarios }) => {
        if (existemUsuarios) this.router.navigate(['/login']);
      },
      error: () => this.erro = 'Não foi possível verificar se o primeiro cadastro está disponível.'
    });
  }

  enviar(): void {
    this.erro = '';
    if (this.cadastro.senha !== this.cadastro.confirmarSenha) {
      this.erro = 'As senhas não coincidem.';
      return;
    }

    this.carregando = true;

    const { confirmarSenha: _confirmarSenha, ...payload } = this.cadastro;
    this.auth.cadastrar(payload).subscribe({
      next: () => this.router.navigate(['/login'], { queryParams: { cadastrado: '1' } }),
      error: (e) => {
        this.carregando = false;
        const apiErro = e.error as ApiErro | undefined;
        this.erro = apiErro?.mensagem ?? apiErro?.erro ?? 'Falha ao cadastrar.';
      }
    });
  }
}
