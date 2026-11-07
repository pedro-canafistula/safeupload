import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { FormsModule, NgForm } from '@angular/forms';
import { finalize } from 'rxjs';
import { ApiService, CadastroEmpresaRequest, CadastroUsuarioRequest, EmpresaResumo } from '../../core/api.service';
import { AddressPayload, AuthService } from '../../core/auth.service';
import { mensagemErro } from '../../core/load-state';

interface EnderecoForm {
  cep: string;
  logradouro: string;
  numero: number | null;
  complemento: string;
  bairro: string;
  cidade: string;
  estado: string;
}

const enderecoVazio = (): EnderecoForm => ({
  cep: '', logradouro: '', numero: null, complemento: '', bairro: '', cidade: '', estado: ''
});

const empresaVazia = () => ({
  razao_social: '', nome_fantasia: '', cnpj: '', email_contato: '', telefone_contato: '',
  endereco: enderecoVazio()
});

const usuarioVazio = () => ({
  nome_completo: '', username: '', email: '', cpf: '', data_nascimento: '',
  senha: '', confirmarSenha: '', role: 'user',
  fk_id_empresa: null as number | null,
  endereco: enderecoVazio()
});

const perfisAdmin = [{ valor: 'user', nome: 'Usuário' }, { valor: 'admin', nome: 'Administrador' }] as const;
const perfisRoot = [...perfisAdmin, { valor: 'root', nome: 'Root (todas as empresas)' }] as const;

@Component({
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './novos-cadastros.component.html',
  styleUrl: './novos-cadastros.component.css'
})
export class NovosCadastrosComponent implements OnInit {
  // Empresa (só ROOT cadastra empresas)
  empresa = empresaVazia();
  tentouEmpresa = false;
  enviandoEmpresa = false;
  erroEmpresa = '';
  mensagemEmpresa = '';

  // Usuário
  usuario = usuarioVazio();
  empresas: EmpresaResumo[] = [];
  carregandoEmpresas = false;
  erroEmpresas = '';
  tentouUsuario = false;
  enviandoUsuario = false;
  erroUsuario = '';
  mensagemUsuario = '';

  constructor(private api: ApiService, private auth: AuthService) {}

  get criadoPor(): string {
    return this.auth.usuarioLogado?.username ?? '';
  }

  /** ROOT cadastra empresas e usuários de qualquer perfil; ADMIN só admin/user na própria empresa. */
  get root(): boolean {
    return this.auth.usuarioLogado?.role?.trim().toLowerCase() === 'root';
  }

  get perfis(): readonly { valor: string; nome: string }[] {
    return this.root ? perfisRoot : perfisAdmin;
  }

  ngOnInit(): void {
    this.carregarEmpresas();
  }

  // ---------- Empresa ----------

  cadastrarEmpresa(form: NgForm): void {
    this.erroEmpresa = '';
    this.mensagemEmpresa = '';
    this.tentouEmpresa = true;
    if (form.invalid) {
      this.erroEmpresa = 'Revise os campos destacados antes de cadastrar.';
      return;
    }
    const e = this.empresa;
    const payload: CadastroEmpresaRequest = {
      razao_social: e.razao_social.trim(),
      nome_fantasia: e.nome_fantasia.trim(),
      cnpj: e.cnpj.trim(),
      email_contato: e.email_contato.trim(),
      telefone_contato: e.telefone_contato.trim(),
      endereco: this.paraEndereco(e.endereco)
    };
    this.enviandoEmpresa = true;
    this.api.cadastrarEmpresa(payload).pipe(finalize(() => this.enviandoEmpresa = false)).subscribe({
      next: resposta => {
        this.mensagemEmpresa = resposta.mensagem || 'Empresa cadastrada com sucesso.';
        this.empresa = empresaVazia();
        this.tentouEmpresa = false;
        this.carregarEmpresas();
      },
      error: (erro: HttpErrorResponse) => {
        this.erroEmpresa = mensagemErro(erro, 'Não foi possível cadastrar a empresa.');
      }
    });
  }

  // ---------- Usuário ----------

  carregarEmpresas(): void {
    this.carregandoEmpresas = true;
    this.erroEmpresas = '';
    this.api.listarEmpresas().pipe(finalize(() => this.carregandoEmpresas = false)).subscribe({
      next: lista => {
        this.empresas = [...lista].sort((a, b) => a.razao_social.localeCompare(b.razao_social, 'pt-BR'));
        // ADMIN só vê a própria empresa: já deixa selecionada.
        if (this.empresas.length === 1 && this.usuario.fk_id_empresa === null) this.usuario.fk_id_empresa = this.empresas[0].id_empresa;
      },
      error: (erro: HttpErrorResponse) => {
        this.erroEmpresas = mensagemErro(erro, 'Não foi possível carregar as empresas.');
      }
    });
  }

  cadastrarUsuario(form: NgForm): void {
    this.erroUsuario = '';
    this.mensagemUsuario = '';
    this.tentouUsuario = true;
    const u = this.usuario;
    if (form.invalid || u.fk_id_empresa === null) {
      this.erroUsuario = 'Revise os campos destacados antes de cadastrar.';
      return;
    }
    if (u.senha !== u.confirmarSenha) {
      this.erroUsuario = 'As senhas não coincidem.';
      return;
    }
    const payload: CadastroUsuarioRequest = {
      username: u.username.trim(),
      email: u.email.trim(),
      cpf: u.cpf.trim(),
      senha: u.senha,
      nome_completo: u.nome_completo.trim(),
      data_nascimento: u.data_nascimento,
      fk_id_empresa: u.fk_id_empresa,
      endereco: this.paraEndereco(u.endereco),
      role: u.role
    };
    this.enviandoUsuario = true;
    this.api.cadastrarUsuario(payload).pipe(finalize(() => this.enviandoUsuario = false)).subscribe({
      next: resposta => {
        this.mensagemUsuario = resposta.mensagem || 'Usuário cadastrado com sucesso.';
        const empresa = this.empresas.length === 1 ? this.empresas[0].id_empresa : null;
        this.usuario = { ...usuarioVazio(), fk_id_empresa: empresa };
        this.tentouUsuario = false;
      },
      error: (erro: HttpErrorResponse) => {
        this.erroUsuario = mensagemErro(erro, 'Não foi possível cadastrar o usuário.');
      }
    });
  }

  // ---------- Auxiliares ----------

  private paraEndereco(e: EnderecoForm): AddressPayload {
    return {
      cep: e.cep.trim(),
      logradouro: e.logradouro.trim(),
      numero: Number(e.numero),
      complemento: e.complemento.trim(),
      bairro: e.bairro.trim(),
      cidade: e.cidade.trim(),
      estado: e.estado.trim().toUpperCase()
    };
  }
}
