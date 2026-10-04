import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';
import { AuditEvent, categoryLabels, verdictLabels } from './models';

@Component({
  selector: 'app-event-table',
  standalone: true,
  imports: [CommonModule],
  template: `
    <p *ngIf="!events.length">Nenhuma inspeção recebida para esta consulta.</p>
    <div class="table-scroll" *ngIf="events.length">
      <table>
        <caption class="sr-only">Eventos de inspeção recebidos</caption>
        <thead><tr><th>Data/hora</th><th>Endpoint</th><th>Arquivo</th><th>Tamanho</th><th>Resultado</th><th>Categorias</th></tr></thead>
        <tbody><tr *ngFor="let event of events">
          <td>{{ event.occurredAtUtc | date:'dd/MM/yyyy HH:mm:ss' }}</td>
          <td>{{ event.endpointId }}</td><td>{{ event.fileName }}</td><td>{{ event.sizeBytes | number }} B</td>
          <td><span class="pill" [class.ok]="event.verdict === 'Approved'" [class.danger]="event.verdict === 'Blocked'"
            [class.warn]="event.verdict === 'AllowedWithoutInspection'">{{ verdicts[event.verdict] }}</span>
            <small *ngIf="event.notInspectedReason">{{ event.notInspectedReason }}</small></td>
          <td><span *ngFor="let category of event.categories; let last = last">{{ categories[category] }}{{ last ? '' : ', ' }}</span>
            <span *ngIf="!event.categories.length">—</span></td>
        </tr></tbody>
      </table>
    </div>`
})
export class EventTableComponent {
  @Input() events: AuditEvent[] = [];
  readonly verdicts = verdictLabels;
  readonly categories = categoryLabels;
}
