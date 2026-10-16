import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { ApiService } from '../../core/api.service';
import { EndpointRow } from '../../core/models';

interface Publicacao { endpointId: string; nome: string; version: number; publicadaEm: string; }
@Component({
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './politicas.component.html',
  styleUrl: './politicas.component.css'
})
export class PoliticasComponent {
  private readonly http = inject(HttpClient);
  private readonly api = inject(ApiService);
  readonly suportadas = new Set(['cpf', 'cnpj', 'cartao_credito', 'credenciais']);
  readonly regras = [
    { id: 'cpf', nome: 'CPF', descricao: 'Cadastro de Pessoa Física' },
    { id: 'rg', nome: 'RG', descricao: 'Registro Geral de identidade' },
    { id: 'cartao_credito', nome: 'Número de cartão', descricao: 'Cartões de crédito e débito' },
    { id: 'cnpj', nome: 'CNPJ', descricao: 'Cadastro Nacional de Pessoa Jurídica' },
    { id: 'dados_bancarios', nome: 'Dados bancários', descricao: 'Agência, conta e chave PIX' },
    { id: 'dados_saude', nome: 'Dados de saúde', descricao: 'Laudos, prontuários e diagnósticos' },
    { id: 'credenciais', nome: 'Credenciais e segredos', descricao: 'Senhas, tokens e chaves de API' },
    { id: 'documentos_confidenciais', nome: 'Documentos confidenciais', descricao: 'Arquivos classificados e internos' },
    { id: 'dados_pessoais', nome: 'Dados pessoais', descricao: 'E-mail, telefone e endereço' }
  ];
  endpoints: EndpointRow[] = [];
  publicacoes: Publicacao[] = [];
  erroConsulta = '';
  nome = '';
  endpointId = '';
  regrasSelecionadas: string[] = [];
  acao = 'bloquear';
  jsonGerado = '';
  enviado = false;
  enviando = false;
  erro = '';
  versaoPublicada: number | null = null;
  destinoPublicado = '';

  constructor() { this.atualizarComputadores(); }

  atualizarComputadores(): void {
    this.api.getEndpoints().subscribe({
      next: result => { this.endpoints = result.itens; this.erro = ''; },
      error: () => { this.erro = 'Não foi possível carregar os computadores. Confira sua sessão de administrador.'; }
    });
    this.http.get<Publicacao[]>('/api/politicas', { withCredentials: true }).subscribe({
      next: result => { this.publicacoes = result; this.erroConsulta = ''; },
      error: () => { this.erroConsulta = 'Não foi possível consultar as políticas publicadas.'; }
    });
  }

  versaoInformada(endpointId: string): number | string {
    return this.endpoints.find(e => e.endpointId === endpointId)?.policyVersion ?? 'sem registro';
  }

  alternarRegra(id: string, marcado: boolean): void {
    if (!this.suportadas.has(id) || this.enviando) return;
    this.regrasSelecionadas = marcado
      ? [...new Set([...this.regrasSelecionadas, id])]
      : this.regrasSelecionadas.filter(regraId => regraId !== id);
  }

  enviarPolitica(): void {
    if (this.enviando || !this.nome.trim() || !this.endpointId || !this.regrasSelecionadas.length) return;
    const politica = {
      versao: '1.0', nome: this.nome.trim(), destino: { endpointId: this.endpointId }, acao: this.acao,
      regras: this.regrasSelecionadas.map(id => ({ tipo: id, nome: this.regras.find(r => r.id === id)!.nome })),
      criadaEm: new Date().toISOString(), origem: 'console-administrativo'
    };
    this.enviando = true;
    this.enviado = false;
    this.erro = '';
    this.http.post<Publicacao>('/api/politicas', politica, { withCredentials: true }).subscribe({
      next: result => {
        this.jsonGerado = JSON.stringify(politica, null, 2);
        this.destinoPublicado = politica.destino.endpointId;
        this.versaoPublicada = result.version;
        this.enviado = true;
        this.enviando = false;
        this.atualizarComputadores();
      },
      error: (error: HttpErrorResponse) => {
        this.enviando = false;
        this.erro = error.status === 401 || error.status === 403
          ? 'Publicação restrita a administradores com sessão ativa.'
          : error.error?.message ?? 'Não foi possível publicar. Confira os dados e tente novamente.';
      }
    });
  }

  baixarJson(): void {
    const arquivo = new Blob([this.jsonGerado], { type: 'application/json' });
    const url = URL.createObjectURL(arquivo);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'politica-publicada.json';
    link.click();
    URL.revokeObjectURL(url);
  }
}
