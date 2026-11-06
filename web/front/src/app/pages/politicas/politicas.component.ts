import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { finalize } from 'rxjs';
import { ApiService } from '../../core/api.service';

@Component({
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './politicas.component.html',
  styleUrl: './politicas.component.css'
})
export class PoliticasComponent {
  constructor(private api: ApiService, private router: Router) {}

  readonly etapas = ['Identificação', 'Escopo de aplicação', 'Dados e condições', 'Operações e destinos', 'Ação e exceções', 'Revisão da política'];
  readonly titulosEtapas = ['Identificação', 'Escopo de aplicação', 'Dados e condições', 'Operações e destinos', 'Ação e exceções', 'Revisão da política'];
  readonly descricoesEtapas = [
    'Dê um nome claro para identificar esta política.',
    'Escolha o endpoint que receberá a configuração.',
    'Selecione os classificadores e como combiná-los.',
    'Defina o comportamento aplicado quando houver correspondência.',
    'Revise exceções e limitações de compatibilidade.',
    'Confira o resultado esperado, os pontos de atenção e o endpoint afetado.'
  ];
  readonly regras = [
    { id: 'cpf', nome: 'CPF', descricao: 'Documento pessoal validado' },
    { id: 'cnpj', nome: 'CNPJ', descricao: 'Registro empresarial validado' },
    { id: 'cartao_credito', nome: 'Cartão de pagamento', descricao: 'Validação do número' },
    { id: 'credenciais', nome: 'Credenciais e segredos', descricao: 'Senhas, tokens e chaves' },
    { id: 'rg', nome: 'RG', descricao: 'Registro geral de identidade' },
    { id: 'dados_bancarios', nome: 'Dados bancários', descricao: 'Agência, conta e chave PIX' },
    { id: 'dados_saude', nome: 'Dados de saúde', descricao: 'Laudos e prontuários' },
    { id: 'documentos_confidenciais', nome: 'Documentos confidenciais', descricao: 'Arquivos internos e classificados' },
    { id: 'dados_pessoais', nome: 'Dados pessoais', descricao: 'E-mail, telefone e endereço' }
  ];

  etapaAtual = 1;
  nome = '';
  ip = '';
  regrasSelecionadas: string[] = [];
  combinacao: 'any' | 'all' = 'any';
  acao: 'bloquear' | 'alertar' = 'bloquear';
  jsonGerado = '';
  jsonPronto = false;
  enviando = false;
  erro = '';
  mensagem = '';

  get resumoCondicao(): string {
    const nomes = this.regras.filter(regra => this.regrasSelecionadas.includes(regra.id)).map(regra => regra.nome);
    if (nomes.length === 0) return '';
    return nomes.length === 1 ? nomes[0] : nomes.join(this.combinacao === 'any' ? ' ou ' : ' e ');
  }

  get etapaValida(): boolean {
    switch (this.etapaAtual) {
      case 1: return Boolean(this.nome.trim());
      case 2: return this.ipValido(this.ip);
      case 3: return this.regrasSelecionadas.length > 0;
      default: return true;
    }
  }

  alternarRegra(id: string, marcado: boolean): void {
    this.regrasSelecionadas = marcado
      ? [...new Set([...this.regrasSelecionadas, id])]
      : this.regrasSelecionadas.filter(regraId => regraId !== id);
  }

  continuar(): void {
    if (!this.etapaValida || this.etapaAtual >= 6) return;
    this.erro = '';
    this.etapaAtual += 1;
  }

  voltar(): void {
    if (this.etapaAtual > 1) this.etapaAtual -= 1;
    this.erro = '';
  }

  irParaEtapa(etapa: number): void {
    if (etapa < this.etapaAtual && etapa >= 1) {
      this.etapaAtual = etapa;
      this.erro = '';
    }
  }

  enviarPolitica(): void {
    if (!this.nome.trim() || !this.ipValido(this.ip) || !this.regrasSelecionadas.length) return;
    this.erro = '';
    this.mensagem = '';
    const politica = {
      versao: '1.0', nome: this.nome.trim(), destino: { ip: this.ip.trim() }, acao: this.acao,
      regras: this.regrasSelecionadas.map(id => ({ tipo: id, nome: this.regras.find(regra => regra.id === id)!.nome })),
      criadaEm: new Date().toISOString(), origem: 'console-administrativo'
    };
    this.jsonGerado = JSON.stringify(politica, null, 2);
    this.enviando = true;
    this.api.publicarPolitica(politica).pipe(finalize(() => this.enviando = false)).subscribe({
      next: response => {
        this.mensagem = response.mensagem || 'Política enviada ao servidor.';
        this.jsonPronto = true;
      },
      error: error => {
        this.erro = error?.error?.mensagem ?? error?.error?.erro ?? 'Não foi possível enviar a política ao servidor.';
      }
    });
  }

  fechar(): void {
    this.router.navigate(['/painel']);
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
