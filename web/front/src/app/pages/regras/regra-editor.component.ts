import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule, NgForm } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { finalize, forkJoin } from 'rxjs';
import { ApiService } from '../../core/api.service';
import { mensagemErro } from '../../core/load-state';
import { RegraCondicao, RegraRequest, RegraTeste, RegraValidador } from '../../core/models';
import { CondicaoEdicao, TipoCondicao, condicaoVazia, descrever, nomesValidadores, paraCondicao, paraEdicao } from './regra-texto';

const MAX_CONDICOES = 20;
const MAX_EXEMPLOS = 10;
type Lista = 'sinalizar' | 'naoSinalizar';

/** Rota /regras/nova ou /regras/:id. O servidor confere a regra e os exemplos antes de salvar. */
@Component({
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './regra-editor.component.html',
  styleUrls: ['../politicas/politicas.component.css', './regras.component.css']
})
export class RegraEditorComponent {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  readonly maxCondicoes = MAX_CONDICOES;
  readonly maxExemplos = MAX_EXEMPLOS;
  readonly tipos: { valor: TipoCondicao; nome: string }[] = [
    { valor: 'contem', nome: 'Contém palavras' }, { valor: 'naoContem', nome: 'Não contém palavras' },
    { valor: 'mascara', nome: 'Padrão (máscara)' }, { valor: 'regex', nome: 'Expressão regular' }
  ];
  readonly listas: Lista[] = ['sinalizar', 'naoSinalizar'];
  readonly exemploRegex = '\\bMAT-(\\d{8})\\b';
  readonly validadores = (Object.keys(nomesValidadores) as RegraValidador[]).map(valor => ({ valor, nome: nomesValidadores[valor] }));

  /** null = regra nova. */
  id: number | null = null;
  revisao: number | null = null;
  politicas: string[] = [];
  carregando = false;
  erroCarga = '';
  /** A regra salva usa combinações que este editor não monta; mostramos só o "Como texto" dela. */
  naoEditavel = false;
  descricaoSalva = '';
  salvando = false;
  testando = false;
  tentou = false;
  erro = '';
  erroTeste = '';

  nome = '';
  descricao = '';
  modo: 'todos' | 'algum' = 'todos';
  condicoes: CondicaoEdicao[] = [condicaoVazia()];
  exemplos: Record<Lista, string[]> = { sinalizar: [''], naoSinalizar: [''] };
  /** Resultado do último Testar e a regra/exemplos que foram testados (para avisar quando ficou velho). */
  resultados: Record<Lista, RegraTeste[]> | null = null;
  private testado = '';

  constructor() {
    inject(ActivatedRoute).paramMap.pipe(takeUntilDestroyed()).subscribe(params => {
      const id = Number(params.get('id'));
      this.id = params.get('id') === 'nova' || !Number.isInteger(id) || id <= 0 ? null : id;
      if (this.id !== null) this.carregar(this.id);
    });
  }

  private carregar(id: number): void {
    this.carregando = true;
    this.api.obterRegra(id).pipe(finalize(() => this.carregando = false)).subscribe({
      next: regra => {
        const edicao = paraEdicao(regra.quando);
        this.naoEditavel = edicao === null;
        this.nome = regra.nome;
        this.descricao = regra.descricao ?? '';
        this.revisao = regra.revisao;
        this.politicas = regra.politicas;
        this.modo = edicao?.modo ?? 'todos';
        this.condicoes = edicao?.linhas ?? [];
        this.exemplos = { sinalizar: [...regra.exemplos.sinalizar], naoSinalizar: [...regra.exemplos.naoSinalizar] };
        this.descricaoSalva = descrever(regra.quando);
      },
      error: (erro: HttpErrorResponse) => this.erroCarga = mensagemErro(erro, 'Não foi possível carregar a regra.')
    });
  }

  get quando(): RegraCondicao {
    return { [this.modo]: this.condicoes.map(paraCondicao) };
  }

  get comoTexto(): string {
    return descrever(this.quando);
  }

  adicionarCondicao(): void {
    if (this.condicoes.length < MAX_CONDICOES) this.condicoes.push(condicaoVazia());
  }

  removerCondicao(indice: number): void {
    this.condicoes.splice(indice, 1);
  }

  adicionarExemplo(lista: Lista): void {
    if (this.exemplos[lista].length < MAX_EXEMPLOS) this.exemplos[lista].push('');
  }

  removerExemplo(lista: Lista, indice: number): void {
    this.exemplos[lista].splice(indice, 1);
    this.resultados = null;
  }

  readonly trackIndice = (indice: number): number => indice;

  /** Resultado do último teste para o exemplo, enquanto a regra e os exemplos não mudaram. */
  resultado(lista: Lista, indice: number): RegraTeste | null {
    return this.resultados && !this.testeDesatualizado ? this.resultados[lista][indice] ?? null : null;
  }

  esperado(lista: Lista, resultado: RegraTeste): boolean {
    return resultado.matched === (lista === 'sinalizar');
  }

  /**
   * "Condição 2 · pelo menos 2× máscara CT-####/##: 2 ocorrências ✓". O servidor diz se cada folha achou o mínimo;
   * numa linha "Não contém", achar as palavras faz a condição falhar.
   */
  linhaResultado(indice: number, c: RegraTeste['condicoes'][number]): string {
    const negada = this.condicoes[indice]?.tipo === 'naoContem';
    const atende = negada ? !c.atende : c.atende;
    return `Condição ${indice + 1} · ${negada ? 'NÃO ' : ''}${c.condicao}: ${c.ocorrencias} ${c.ocorrencias === 1 ? 'ocorrência' : 'ocorrências'} ${atende ? '✓' : '✗'}`;
  }

  get testeDesatualizado(): boolean {
    return this.resultados !== null && this.testado !== this.chaveTeste();
  }

  get falhasTeste(): number {
    if (!this.resultados || this.testeDesatualizado) return 0;
    return this.resultados.sinalizar.filter(r => !r.matched).length + this.resultados.naoSinalizar.filter(r => r.matched).length;
  }

  testar(): void {
    this.erroTeste = '';
    const quando = this.quando;
    const chave = this.chaveTeste();
    this.testando = true;
    // O servidor avalia até 10 textos por pedido: um pedido por lista.
    forkJoin({
      sinalizar: this.api.testarRegra(quando, this.exemplos.sinalizar),
      naoSinalizar: this.api.testarRegra(quando, this.exemplos.naoSinalizar)
    }).pipe(finalize(() => this.testando = false)).subscribe({
      next: resultados => {
        this.resultados = resultados;
        this.testado = chave;
      },
      error: (erro: HttpErrorResponse) => {
        this.resultados = null;
        this.erroTeste = mensagemErro(erro, 'Não foi possível testar a regra.');
      }
    });
  }

  salvar(form: NgForm): void {
    this.erro = '';
    this.tentou = true;
    if (form.invalid) {
      this.erro = 'Revise os campos destacados.';
      return;
    }
    const payload: RegraRequest = {
      nome: this.nome.trim(), descricao: this.descricao.trim(), quando: this.quando,
      exemplos: { sinalizar: [...this.exemplos.sinalizar], naoSinalizar: [...this.exemplos.naoSinalizar] }
    };
    const id = this.id;
    this.salvando = true;
    (id === null ? this.api.criarRegra(payload) : this.api.atualizarRegra(id, payload))
      .pipe(finalize(() => this.salvando = false)).subscribe({
        next: resposta => {
          const mensagem = id === null ? `Regra ${payload.nome} criada.`
            : `Regra ${payload.nome} salva (revisão ${resposta.revisao}).` +
              (this.politicas.length ? ' As políticas que a usam ganharam uma versão nova.' : '');
          void this.router.navigate(['/regras'], { state: { mensagem } });
        },
        error: (erro: HttpErrorResponse) => this.erro = mensagemErro(erro, 'Não foi possível salvar a regra.')
      });
  }

  private chaveTeste(): string {
    return JSON.stringify([this.quando, this.exemplos]);
  }
}
