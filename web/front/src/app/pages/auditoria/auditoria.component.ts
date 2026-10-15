import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Subject, combineLatest, startWith, switchMap } from 'rxjs';
import { ApiService } from '../../core/api.service';
import { loadState } from '../../core/load-state';
import { AuditChannel, AuditEvent, Verdict, verdictLabels } from '../../core/models';
import { EventTableComponent } from '../../core/event-table.component';

@Component({ standalone: true, imports: [CommonModule, FormsModule, RouterLink, EventTableComponent], templateUrl: './auditoria.component.html', styleUrl: './auditoria.component.css' })
export class AuditoriaComponent {
  private readonly api = inject(ApiService);
  private readonly route = inject(ActivatedRoute);
  readonly refresh = new Subject<void>();
  readonly state$ = combineLatest([this.route.queryParamMap, this.refresh.pipe(startWith(undefined))]).pipe(
    switchMap(([params]) => loadState(this.api.getAuditoria(params.get('endpoint') ?? '')))
  );
  query = '';
  verdict: Verdict | '' = '';
  channel: AuditChannel | '' = '';

  filtered(events: AuditEvent[]): AuditEvent[] {
    const query = this.query.trim().toLocaleLowerCase();
    return events.filter(event => (!this.verdict || event.verdict === this.verdict)
      && (!this.channel || (event.channel ?? 'File') === this.channel)
      && (!query || [event.eventId, event.endpointId, event.userName, event.fileName, event.processName, event.destinationPath]
        .some(value => value?.toLocaleLowerCase().includes(query))));
  }

  exportCsv(events: AuditEvent[]): void {
    const cell = (value: string): string => '"' + (/^[\s]*[=+@-]/.test(value) ? "'" + value : value).replace(/"/g, '""') + '"';
    const rows = this.filtered(events).map(event => [event.eventId, event.endpointId, event.userName,
      event.channel ?? 'File', verdictLabels[event.verdict], event.occurredAtUtc].map(cell).join(';'));
    const csv = ['ID;Endpoint;Usuário;Canal;Resultado;Data UTC', ...rows].join('\r\n');
    const url = URL.createObjectURL(new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'auditoria.csv';
    anchor.click();
    URL.revokeObjectURL(url);
  }
}
