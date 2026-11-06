import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnDestroy, OnInit } from '@angular/core';
import { FormsModule, NgForm } from '@angular/forms';
import { finalize } from 'rxjs';
import { ApiService, CadastroEmpresaRequest, CadastroUsuarioRequest, EmpresaResumo } from '../../core/api.service';
import { AddressPayload, AuthService } from '../../core/auth.service';
import { ApiErro } from '../../core/models';

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

@Component({
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './novos-cadastros.component.html',
  styleUrl: './novos-cadastros.component.css'
})
export class NovosCadastrosComponent implements OnInit, OnDestroy {
  // Token — fica somente em memória: ao sair da página ou recarregar, ele some.
  token = '';
  gerandoToken = false;
  erroToken = '';
  copiado = false;
  statusCopia = '';
  private temporizadorCopia?: number;

  // Empresa
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

  ngOnInit(): void {
    this.carregarEmpresas();
  }

  ngOnDestroy(): void {
    window.clearTimeout(this.temporizadorCopia);
  }

  // ---------- Token ----------

  gerarToken(): void {
    this.erroToken = '';
    this.gerandoToken = true;
    this.api.gerarToken().pipe(finalize(() => this.gerandoToken = false)).subscribe({
      next: resposta => {
        this.token = resposta.token;
        this.copiado = false;
        this.statusCopia = '';
      },
      error: (erro: HttpErrorResponse) => {
        this.erroToken = this.mensagemDeErro(erro, 'Não foi possível gerar o token.');
      }
    });
  }

  copiarToken(): void {
    const token = this.token;
    if (!token) return;
    const concluir = (copiou: boolean): void => {
      window.clearTimeout(this.temporizadorCopia);
      this.copiado = copiou;
      this.statusCopia = copiou
        ? 'Token copiado para a área de transferência.'
        : 'Não foi possível copiar. Selecione o token e copie manualmente.';
      this.temporizadorCopia = window.setTimeout(() => {
        this.copiado = false;
        this.statusCopia = '';
      }, 2500);
    };
    const copia = navigator.clipboard?.writeText(token) ?? Promise.reject();
    copia.then(() => concluir(true), () => concluir(this.copiarComAlternativa(token)));
  }

  // Alternativa para contextos sem a Clipboard API (por exemplo, acesso por HTTP fora de localhost).
  private copiarComAlternativa(texto: string): boolean {
    const campo = document.createElement('textarea');
    campo.value = texto;
    campo.setAttribute('readonly', '');
    campo.style.position = 'fixed';
    campo.style.opacity = '0';
    document.body.appendChild(campo);
    campo.select();
    let copiou = false;
    try { copiou = document.execCommand('copy'); } catch { copiou = false; }
    document.body.removeChild(campo);
    return copiou;
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
        this.erroEmpresa = this.mensagemDeErro(erro, 'Não foi possível cadastrar a empresa.');
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
      },
      error: (erro: HttpErrorResponse) => {
        this.erroEmpresas = this.mensagemDeErro(erro, 'Não foi possível carregar as empresas.');
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
    const criadoPor = this.criadoPor;
    if (!criadoPor) {
      this.erroUsuario = 'Não foi possível identificar o administrador logado. Entre novamente.';
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
      role: u.role,
      criado_por: criadoPor
    };
    this.enviandoUsuario = true;
    this.api.cadastrarUsuario(payload).pipe(finalize(() => this.enviandoUsuario = false)).subscribe({
      next: resposta => {
        this.mensagemUsuario = resposta.mensagem || 'Usuário cadastrado com sucesso.';
        this.usuario = usuarioVazio();
        this.tentouUsuario = false;
      },
      error: (erro: HttpErrorResponse) => {
        this.erroUsuario = this.mensagemDeErro(erro, 'Não foi possível cadastrar o usuário.');
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

  private mensagemDeErro(erro: HttpErrorResponse, padrao: string): string {
    if (erro.status === 401) return 'Sua sessão expirou. Entre novamente.';
    return (erro.error as ApiErro | null)?.mensagem ?? padrao;
  }
}
