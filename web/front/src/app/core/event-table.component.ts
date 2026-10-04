import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';
import { AuditEvent, categoryLabels, verdictLabels } from './models';

@Component({
  selector: 'app-event-table',
  standalone: true,
  imports: [CommonModule],
  styleUrl: './event-table.component.css',
  template: `
    <p *ngIf="!events.length">Nenhuma inspeção recebida para esta consulta.</p>
    <div class="table-scroll" *ngIf="events.length">
      <table>
        <caption class="sr-only">Eventos de inspeção recebidos</caption>
        <thead><tr><th scope="col">Data/hora</th><th scope="col">Endpoint</th><th scope="col">Arquivo</th><th scope="col">Tamanho</th><th scope="col">Resultado</th><th scope="col">Categorias</th><th scope="col">Detalhes</th></tr></thead>
        <tbody><ng-container *ngFor="let event of events">
        <tr>
          <td>{{ event.occurredAtUtc | date:'dd/MM/yyyy HH:mm:ss' }}</td>
          <td>{{ event.endpointId }}</td><td>{{ event.fileName }}</td><td>{{ event.sizeBytes | number }} B</td>
          <td><span class="pill" [class.ok]="event.verdict === 'Approved'" [class.danger]="event.verdict === 'Blocked'"
            [class.warn]="event.verdict === 'AllowedWithoutInspection'">{{ verdicts[event.verdict] }}</span>
            <small *ngIf="event.notInspectedReason">{{ event.notInspectedReason }}</small></td>
          <td><span *ngFor="let category of event.categories; let last = last">{{ categories[category] }}{{ last ? '' : ', ' }}</span>
            <span *ngIf="!event.categories.length">—</span></td>
          <td><button type="button" class="btn-secondary" [attr.aria-expanded]="expandedEventId === event.eventId"
            [attr.aria-controls]="'evento-' + event.eventId" [attr.aria-label]="'Detalhes de ' + event.fileName"
            (click)="toggle(event.eventId)">{{ expandedEventId === event.eventId ? 'Ocultar' : 'Ver detalhes' }}</button></td>
        </tr>
        </ng-container></tbody>
      </table>
    </div>
            <section *ngIf="expandedEvent as event" class="event-details" [id]="'evento-' + event.eventId" [attr.aria-label]="'Detalhes de ' + event.fileName">
              <h4>Detalhes da inspeção</h4>
              <p>{{ event.fileName }}</p>
              <p *ngIf="event.verdict === 'Approved'">As regras ativas não encontraram ocorrências no conteúdo analisado. Isso não garante ausência de risco.</p>
              <p *ngIf="event.verdict === 'Blocked'">A operação foi bloqueada por ocorrências nas categorias indicadas. Revise o arquivo antes de tentar novamente.</p>
              <p *ngIf="event.verdict === 'AllowedWithoutInspection'">A operação foi liberada sem conclusão da inspeção. Este resultado não equivale a uma aprovação.</p>
              <dl>
                <div><dt>Identificador do evento</dt><dd>{{ event.eventId }}</dd></div>
                <div><dt>Data/hora local</dt><dd>{{ event.occurredAtUtc | date:'dd/MM/yyyy HH:mm:ss Z' }}</dd></div>
                <div><dt>Endpoint</dt><dd>{{ event.endpointId }}</dd></div>
                <div><dt>Usuário no endpoint</dt><dd>{{ event.userName || 'Não informado' }}</dd></div>
                <div><dt>Extensão</dt><dd>{{ event.extension || 'Não informada' }}</dd></div>
                <div><dt>Processo de origem</dt><dd>{{ event.processName || 'Não informado' }}</dd></div>
                <div><dt>PID do processo</dt><dd>{{ event.processId ?? 'Não informado' }}</dd></div>
                <div><dt>Caminho de destino</dt><dd>{{ event.destinationPath || 'Não informado' }}</dd></div>
                <div><dt>Versão da política aplicada</dt><dd>{{ event.policyVersion ?? 'Não informada' }}</dd></div>
                <div><dt>Duração da inspeção</dt><dd>{{ event.elapsedMs == null ? 'Não informada' : event.elapsedMs + ' ms' }}</dd></div>
                <div *ngIf="event.verdict === 'AllowedWithoutInspection'"><dt>Motivo da não inspeção</dt>
                  <dd>{{ event.notInspectedReason || 'Não informado pelo agente' }}</dd></div>
              </dl>
              <p class="privacy-note">Esta consulta mostra somente metadados. Conteúdo do arquivo e trechos detectados não são exibidos.</p>
            </section>`
})
export class EventTableComponent {
  @Input() events: AuditEvent[] = [];
  readonly verdicts = verdictLabels;
  readonly categories = categoryLabels;
  expandedEventId: string | null = null;

  get expandedEvent(): AuditEvent | undefined {
    return this.events.find((event) => event.eventId === this.expandedEventId);
  }

  toggle(eventId: string): void {
    this.expandedEventId = this.expandedEventId === eventId ? null : eventId;
  }
}
