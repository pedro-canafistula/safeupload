import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule, NgForm } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { finalize } from 'rxjs';
import { ApiService } from '../../core/api.service';
import { mensagemErro } from '../../core/load-state';
import {
  AcaoCategoria, CategoriaCodigo, ModoClipboard, PoliticaConfiguracao, PoliticaDetalhe, PoliticaRequest, categoriasPolitica
} from '../../core/models';

const EXTENSOES_PADRAO = ['.txt', '.csv', '.docx', '.xlsx', '.pdf', '.pptx', '.zip'];

function configuracaoInicial(): PoliticaConfiguracao {
  return {
    categorias: Object.fromEntries(categoriasPolitica.map(c => [c.codigo, 'bloquear'])) as Record<CategoriaCodigo, AcaoCategoria>,
    pastas: [], pendrives: true, rede: false, extensoes: EXTENSOES_PADRAO, tamanhoMaximoMb: 100,
    tempoLimiteSegundos: 900, permitirJustificativa: false, clipboard: 'desligado'
  };
}

/** Rota /politicas/nova ou /politicas/:id. Salvar uma política existente cria uma versão nova. */
@Component({
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './politica-editor.component.html',
  styleUrl: './politicas.component.css'
})
export class PoliticaEditorComponent {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  readonly categoriasLista = categoriasPolitica;
  readonly acoes: { valor: AcaoCategoria; nome: string }[] = [
    { valor: 'bloquear', nome: 'Bloquear' }, { valor: 'alertar', nome: 'Alertar' }, { valor: 'ignorar', nome: 'Ignorar' }
  ];
  readonly modosClipboard: { valor: ModoClipboard; nome: string }[] = [
    { valor: 'desligado', nome: 'Desligado' }, { valor: 'alertar', nome: 'Alertar' }, { valor: 'bloquear', nome: 'Bloquear' }
  ];

  /** null = política nova. */
  id: number | null = null;
  carregando = false;
  erroCarga = '';
  salvando = false;
  tentou = false;
  erro = '';
  mensagem = '';

  nome = '';
  padrao = false;
  config = configuracaoInicial();
  pastasTexto = '';
  extensoesTexto = EXTENSOES_PADRAO.join(', ');
  versao: number | null = null;
  historico: PoliticaDetalhe['historico'] = [];

  constructor() {
    // Depois de criar, a rota muda de /politicas/nova para /politicas/:id e este componente é reaproveitado.
    inject(ActivatedRoute).paramMap.pipe(takeUntilDestroyed()).subscribe(params => {
      const id = Number(params.get('id'));
      if (params.get('id') === 'nova' || !Number.isInteger(id) || id <= 0) {
        this.id = null;
        this.preencher('', false, configuracaoInicial());
        this.versao = null;
        this.historico = [];
        this.mensagem = '';
      } else {
        this.id = id;
        this.carregar();
      }
    });
  }

  carregar(): void {
    if (this.id === null) return;
    this.carregando = true;
    this.erroCarga = '';
    this.api.obterPolitica(this.id).pipe(finalize(() => this.carregando = false)).subscribe({
      next: politica => {
        this.preencher(politica.nome, politica.padrao, politica.configuracao);
        this.versao = politica.versao;
        this.historico = politica.historico;
      },
      error: (erro: HttpErrorResponse) => this.erroCarga = mensagemErro(erro, 'Não foi possível carregar a política.')
    });
  }

  salvar(form: NgForm): void {
    this.erro = '';
    this.mensagem = '';
    this.tentou = true;
    if (form.invalid) {
      this.erro = 'Revise os campos destacados.';
      return;
    }
    if (Object.values(this.config.categorias).every(acao => acao === 'ignorar')) {
      this.erro = 'Pelo menos uma categoria precisa bloquear ou alertar.';
      return;
    }
    const payload: PoliticaRequest = {
      nome: this.nome.trim(),
      padrao: this.padrao,
      configuracao: {
        ...this.config,
        pastas: this.pastasTexto.split(/\r?\n/).map(pasta => pasta.trim()).filter(Boolean),
        extensoes: this.extensoesTexto.split(/[\s,;]+/).map(extensao => extensao.trim()).filter(Boolean),
        tamanhoMaximoMb: Number(this.config.tamanhoMaximoMb),
        tempoLimiteSegundos: Number(this.config.tempoLimiteSegundos)
      }
    };
    this.salvando = true;
    const id = this.id;
    const pedido = id === null ? this.api.criarPolitica(payload) : this.api.atualizarPolitica(id, payload);
    pedido.pipe(finalize(() => this.salvando = false)).subscribe({
      next: resposta => {
        this.tentou = false;
        if (id === null) {
          this.mensagem = `Política criada (versão ${resposta.versao}).`;
          void this.router.navigate(['/politicas', resposta.id], { replaceUrl: true });
        } else {
          this.mensagem = `Versão ${resposta.versao} salva. As máquinas online recebem a nova versão em até 30 segundos.`;
          this.carregar();
        }
      },
      error: (erro: HttpErrorResponse) => this.erro = mensagemErro(erro, 'Não foi possível salvar a política.')
    });
  }

  private preencher(nome: string, padrao: boolean, config: PoliticaConfiguracao): void {
    this.nome = nome;
    this.padrao = padrao;
    this.config = { ...config, categorias: { ...configuracaoInicial().categorias, ...config.categorias } };
    this.pastasTexto = config.pastas.join('\n');
    this.extensoesTexto = config.extensoes.join(', ');
  }
}
