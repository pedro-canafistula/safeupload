import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Subject, combineLatest, finalize, startWith, tap } from 'rxjs';
import { ApiService, salvarArquivo } from '../../core/api.service';
import { autoRefresh, mensagemErro } from '../../core/load-state';
import { Audit, AuditChannel, AuditEvent, Verdict } from '../../core/models';
import { EventTableComponent } from '../../core/event-table.component';

@Component({ standalone: true, imports: [CommonModule, FormsModule, RouterLink, EventTableComponent], templateUrl: './auditoria.component.html', styleUrl: './auditoria.component.css' })
export class AuditoriaComponent {
  private readonly api = inject(ApiService);
  private readonly route = inject(ActivatedRoute);
  readonly refresh = new Subject<void>();
  /** Filtro por máquina (?host=ID). */
  host: number | null = null;
  readonly state$ = autoRefresh(
    combineLatest([this.route.queryParamMap, this.refresh.pipe(startWith(undefined))]).pipe(tap(([params]) => {
      const host = Number(params.get('host'));
      this.host = Number.isInteger(host) && host > 0 ? host : null;
    })),
    () => this.api.getAuditoria(this.host)
  );
  query = '';
  verdict: Verdict | '' = '';
  channel: AuditChannel | '' = '';
  exportando = false;
  erroExportacao = '';

  filtered(events: AuditEvent[]): AuditEvent[] {
    const query = this.query.trim().toLocaleLowerCase();
    return events.filter(event => (!this.verdict || event.verdict === this.verdict)
      && (!this.channel || (event.channel ?? 'File') === this.channel)
      && (!query || [event.eventId, event.hostname, event.endpointId, event.userName, event.fileName, event.processName, event.destinationPath,
        ...(event.customRules ?? [])].some(value => value?.toLocaleLowerCase().includes(query))));
  }

  hostLabel(dados: Audit): string {
    return dados.eventos.find(event => event.hostname)?.hostname ?? 'máquina ' + dados.host;
  }

  exportCsv(): void {
    this.erroExportacao = '';
    this.exportando = true;
    const host = this.host;
    this.api.exportarAuditoria(host).pipe(finalize(() => this.exportando = false)).subscribe({
      next: csv => salvarArquivo(csv, host === null ? 'auditoria-7-dias.csv' : `auditoria-7-dias-host-${host}.csv`),
      error: (erro: HttpErrorResponse) => this.erroExportacao = mensagemErro(erro, 'Não foi possível exportar a auditoria.')
    });
  }
}
