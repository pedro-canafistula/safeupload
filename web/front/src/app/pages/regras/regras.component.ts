import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { Subject, startWith } from 'rxjs';
import { ApiService } from '../../core/api.service';
import { mensagemErro, reload } from '../../core/load-state';
import { RegraResumo } from '../../core/models';
import { descrever } from './regra-texto';

/** Lista das regras personalizadas da empresa. O editor fica em RegraEditorComponent. */
@Component({
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './regras.component.html',
  styleUrls: ['../politicas/politicas.component.css', './regras.component.css']
})
export class RegrasComponent {
  private readonly api = inject(ApiService);
  readonly refresh = new Subject<void>();
  readonly state$ = reload(this.refresh.pipe(startWith(undefined)), () => this.api.listarRegras());
  readonly descrever = descrever;

  erro = '';
  /** Mensagem deixada pelo editor ao salvar (estado da navegação). */
  mensagem: string = inject(Router).getCurrentNavigation()?.extras.state?.['mensagem'] ?? '';
  ocupado = false;
  confirmando: number | null = null;

  excluir(regra: RegraResumo): void {
    this.limparAvisos();
    this.ocupado = true;
    this.api.excluirRegra(regra.id).subscribe({
      next: () => {
        this.ocupado = false;
        this.confirmando = null;
        this.mensagem = `Regra ${regra.nome} excluída.`;
        this.refresh.next();
      },
      error: (erro: HttpErrorResponse) => {
        this.ocupado = false;
        this.confirmando = null;
        this.erro = mensagemErro(erro, 'Não foi possível excluir a regra.');
      }
    });
  }

  limparAvisos(): void {
    this.erro = '';
    this.mensagem = '';
  }
}
