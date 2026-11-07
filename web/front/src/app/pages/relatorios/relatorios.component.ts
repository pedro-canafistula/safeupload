import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { finalize } from 'rxjs';
import { ApiService, salvarArquivo } from '../../core/api.service';
import { loadState, mensagemErro } from '../../core/load-state';

@Component({
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './relatorios.component.html',
  styleUrl: './relatorios.component.css'
})
export class RelatoriosComponent {
  private readonly api = inject(ApiService);
  readonly maquinas$ = loadState(this.api.getEndpoints());
  host: number | null = null;
  exportando = false;
  erro = '';

  exportar(): void {
    this.erro = '';
    this.exportando = true;
    const host = this.host;
    this.api.exportarAuditoria(host).pipe(finalize(() => this.exportando = false)).subscribe({
      next: csv => salvarArquivo(csv, host === null ? 'auditoria-7-dias.csv' : `auditoria-7-dias-host-${host}.csv`),
      error: (erro: HttpErrorResponse) => this.erro = mensagemErro(erro, 'Não foi possível exportar a auditoria.')
    });
  }
}
