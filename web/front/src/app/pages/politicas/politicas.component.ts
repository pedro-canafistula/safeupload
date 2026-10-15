import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';

interface RegraDlp {
  id: string;
  nome: string;
  descricao: string;
}

@Component({
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './politicas.component.html',
  styleUrl: './politicas.component.css'
})
export class PoliticasComponent {
  readonly regras: RegraDlp[] = [
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

  nome = '';
  ipDestino = '';
  regrasSelecionadas: string[] = [];
  acao = 'bloquear';
  jsonGerado = '';
  enviado = false;

  alternarRegra(id: string, marcado: boolean): void {
    this.regrasSelecionadas = marcado
      ? [...this.regrasSelecionadas, id]
      : this.regrasSelecionadas.filter(regraId => regraId !== id);
    this.enviado = false;
  }

  enviarPolitica(): void {
    if (!this.nome.trim() || !this.ipDestino.trim() || !this.regrasSelecionadas.length) return;

    const politica = {
      versao: '1.0',
      nome: this.nome.trim(),
      destino: { ip: this.ipDestino.trim() },
      acao: this.acao,
      regras: this.regrasSelecionadas.map(id => {
        const regra = this.regras.find(item => item.id === id)!;
        return { tipo: regra.id, nome: regra.nome };
      }),
      criadaEm: new Date().toISOString(),
      origem: 'console-administrativo'
    };

    this.jsonGerado = JSON.stringify(politica, null, 2);
    this.enviado = true;
  }

  baixarJson(): void {
    const arquivo = new Blob([this.jsonGerado], { type: 'application/json' });
    const url = URL.createObjectURL(arquivo);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${this.nome.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'politica'}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }
}
