import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';

@Component({
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './politicas.component.html',
  styleUrl: './politicas.component.css'
})
export class PoliticasComponent {
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
  nome = '';
  ip = '';
  regrasSelecionadas: string[] = [];
  acao = 'bloquear';
  jsonGerado = '';
  jsonPronto = false;

  alternarRegra(id: string, marcado: boolean): void {
    this.regrasSelecionadas = marcado
      ? [...new Set([...this.regrasSelecionadas, id])]
      : this.regrasSelecionadas.filter(regraId => regraId !== id);
  }

  enviarPolitica(): void {
    if (!this.nome.trim() || !this.ipValido(this.ip) || !this.regrasSelecionadas.length) return;
    const politica = {
      versao: '1.0', nome: this.nome.trim(), destino: { ip: this.ip.trim() }, acao: this.acao,
      regras: this.regrasSelecionadas.map(id => ({ tipo: id, nome: this.regras.find(r => r.id === id)!.nome })),
      criadaEm: new Date().toISOString(), origem: 'console-administrativo'
    };
    this.jsonGerado = JSON.stringify(politica, null, 2);
    this.jsonPronto = true;
    this.baixarJson();
  }

  private ipValido(valor: string): boolean {
    const octetos = valor.trim().split('.');
    return octetos.length === 4 && octetos.every(octeto =>
      /^\d{1,3}$/.test(octeto) && Number(octeto) >= 0 && Number(octeto) <= 255
    );
  }

  baixarJson(): void {
    const arquivo = new Blob([this.jsonGerado], { type: 'application/json' });
    const url = URL.createObjectURL(arquivo);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'politica-safeupload.json';
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
