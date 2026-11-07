import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Observable, Subject, forkJoin, startWith } from 'rxjs';
import { ApiService } from '../../core/api.service';
import { mensagemErro, reload } from '../../core/load-state';
import { Grupo, GrupoRequest, PoliticaResumo } from '../../core/models';

/** Lista de políticas e grupos de máquinas. O editor de uma política fica em PoliticaEditorComponent. */
@Component({
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './politicas.component.html',
  styleUrl: './politicas.component.css'
})
export class PoliticasComponent {
  private readonly api = inject(ApiService);
  readonly refresh = new Subject<void>();
  readonly state$ = reload(this.refresh.pipe(startWith(undefined)),
    () => forkJoin({ politicas: this.api.listarPoliticas(), grupos: this.api.listarGrupos() }));

  erro = '';
  mensagem = '';
  ocupado = false;
  confirmandoPolitica: number | null = null;
  confirmandoGrupo: number | null = null;
  novoGrupo: GrupoRequest = { nome: '', politicaId: null };
  edicaoGrupo: (GrupoRequest & { id: number }) | null = null;

  temPadrao(politicas: PoliticaResumo[]): boolean {
    return politicas.some(politica => politica.padrao);
  }

  excluirPolitica(politica: PoliticaResumo): void {
    this.executar(this.api.excluirPolitica(politica.id), `Política ${politica.nome} excluída.`, 'Não foi possível excluir a política.');
  }

  criarGrupo(): void {
    const grupo = { nome: this.novoGrupo.nome.trim(), politicaId: this.novoGrupo.politicaId };
    if (!grupo.nome) {
      this.erro = 'Informe o nome do grupo.';
      return;
    }
    this.executar(this.api.criarGrupo(grupo), `Grupo ${grupo.nome} criado.`, 'Não foi possível criar o grupo.',
      () => this.novoGrupo = { nome: '', politicaId: null });
  }

  editarGrupo(grupo: Grupo): void {
    this.limparAvisos();
    this.edicaoGrupo = { id: grupo.id, nome: grupo.nome, politicaId: grupo.politicaId };
  }

  salvarGrupo(): void {
    const edicao = this.edicaoGrupo;
    if (!edicao) return;
    const grupo = { nome: edicao.nome.trim(), politicaId: edicao.politicaId };
    if (!grupo.nome) {
      this.erro = 'Informe o nome do grupo.';
      return;
    }
    this.executar(this.api.atualizarGrupo(edicao.id, grupo), `Grupo ${grupo.nome} salvo.`, 'Não foi possível salvar o grupo.',
      () => this.edicaoGrupo = null);
  }

  excluirGrupo(grupo: Grupo): void {
    this.executar(this.api.excluirGrupo(grupo.id), `Grupo ${grupo.nome} excluído.`, 'Não foi possível excluir o grupo.');
  }

  limparAvisos(): void {
    this.erro = '';
    this.mensagem = '';
  }

  private executar(acao: Observable<unknown>, sucesso: string, falha: string, depois?: () => void): void {
    this.limparAvisos();
    this.ocupado = true;
    acao.subscribe({
      next: () => {
        this.ocupado = false;
        this.confirmandoPolitica = null;
        this.confirmandoGrupo = null;
        this.mensagem = sucesso;
        depois?.();
        this.refresh.next();
      },
      error: (erro: HttpErrorResponse) => {
        this.ocupado = false;
        this.confirmandoPolitica = null;
        this.confirmandoGrupo = null;
        this.erro = mensagemErro(erro, falha);
      }
    });
  }
}
