import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';
import { AuditEvent, AuditOverride, categoryLabels, verdictLabels } from './models';

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
        <thead><tr><th scope="col">Data/hora</th><th scope="col">Endpoint</th><th scope="col">Canal</th><th scope="col">Arquivo / atividade</th><th scope="col">Tamanho</th><th scope="col">Resultado</th><th scope="col">Categorias</th><th scope="col">Detalhes</th></tr></thead>
        <tbody><ng-container *ngFor="let event of events">
        <tr>
          <td>{{ event.occurredAtUtc | date:'dd/MM/yyyy HH:mm:ss' }}</td>
          <td>{{ event.endpointId }}</td><td>{{ channelLabel(event) }}</td>
          <td>{{ eventLabel(event) }}</td><td>{{ event.sizeBytes | number }} B</td>
          <td><span class="pill" [class.ok]="event.verdict === 'Approved'" [class.danger]="event.verdict === 'Blocked'"
            [class.warn]="event.verdict === 'AllowedWithoutInspection' || event.verdict === 'Retained'">{{ isObservation(event) ? 'Monitoramento' : verdicts[event.verdict] }}</span>
            <small *ngIf="event.notInspectedReason">{{ event.notInspectedReason }}</small></td>
          <td><span *ngFor="let category of event.categories; let last = last">{{ categories[category] }}{{ last ? '' : ', ' }}</span>
            <span *ngIf="!event.categories.length">—</span></td>
          <td><button type="button" class="btn-secondary" [attr.aria-expanded]="expandedEventId === event.eventId"
            [attr.aria-controls]="'evento-' + event.eventId" [attr.aria-label]="'Detalhes de ' + eventLabel(event)"
            (click)="toggle(event.eventId)">{{ expandedEventId === event.eventId ? 'Ocultar' : 'Ver detalhes' }}</button></td>
        </tr>
        </ng-container></tbody>
      </table>
    </div>
            <section *ngIf="expandedEvent as event" class="event-details" [id]="'evento-' + event.eventId" [attr.aria-label]="'Detalhes de ' + eventLabel(event)">
              <h4>Detalhes da inspeção</h4>
              <p>{{ eventLabel(event) }}</p>
              <p *ngIf="event.verdict === 'Approved'">As regras ativas não encontraram ocorrências no conteúdo analisado. Isso não garante ausência de risco.</p>
              <p *ngIf="event.verdict === 'Retained'">A transferência foi retida localmente. Nenhum conteúdo foi liberado para o destino protegido.</p>
              <p *ngIf="event.verdict === 'Blocked'">A operação foi bloqueada por ocorrências nas categorias indicadas. {{ event.channel === 'Clipboard' ? 'Revise o conteúdo copiado antes de tentar novamente.' : event.channel === 'Web' ? 'Revise o conteúdo enviado antes de tentar novamente.' : 'Revise o arquivo antes de tentar novamente.' }}</p>
              <p *ngIf="isObservation(event)">Clipboard sinalizado ao mudar o foco para um aplicativo de saída. Este registro não confirma colagem nem bloqueio.</p>
              <p *ngIf="event.verdict === 'AllowedWithoutInspection' && !isObservation(event)">A operação foi liberada sem conclusão da inspeção. Este resultado não equivale a uma aprovação.</p>
              <dl>
                <div><dt>Identificador do evento</dt><dd>{{ event.eventId }}</dd></div>
                <div><dt>Data/hora local</dt><dd>{{ event.occurredAtUtc | date:'dd/MM/yyyy HH:mm:ss Z' }}</dd></div>
                <div><dt>Endpoint</dt><dd>{{ event.endpointId }}</dd></div>
                <div><dt>Usuário no endpoint</dt><dd>{{ event.userName || 'Não informado' }}</dd></div>
                <div><dt>Canal</dt><dd>{{ channelLabel(event) }}</dd></div>
                <div *ngIf="event.channel !== 'Clipboard' && (event.channel !== 'Web' || event.fileName)"><dt>Extensão</dt><dd>{{ event.extension || 'Não informada' }}</dd></div>
                <div><dt>Processo de origem</dt><dd>{{ event.processName || 'Não informado' }}</dd></div>
                <div><dt>PID do processo</dt><dd>{{ isObservation(event) ? 'Não informado' : (event.processId ?? 'Não informado') }}</dd></div>
                <div><dt>{{ event.channel === 'Clipboard' ? 'Processo de destino' : event.channel === 'Web' ? 'Endereço de destino' : 'Caminho de destino' }}</dt><dd>{{ event.destinationPath || 'Não informado' }}</dd></div>
                <div *ngIf="event.publishedSha256Hex"><dt>SHA-256 publicado</dt><dd>{{ event.publishedSha256Hex }}</dd></div>
                <div><dt>Versão da política aplicada</dt><dd>{{ event.policyVersion ?? 'Não informada' }}</dd></div>
                <div><dt>Duração da inspeção</dt><dd>{{ isObservation(event) || event.elapsedMs == null ? 'Não informada' : event.elapsedMs + ' ms' }}</dd></div>
                <div *ngIf="event.verdict === 'AllowedWithoutInspection' || event.verdict === 'Retained'"><dt>{{ event.verdict === 'Retained' ? 'Motivo da retenção' : 'Motivo da não inspeção' }}</dt>
                  <dd>{{ event.notInspectedReason || 'Não informado pelo agente' }}</dd></div>
              </dl>
              <section *ngIf="overridesFor(event.eventId).length" aria-label="Justificativas do evento">
                <h5>Justificativas registradas</h5>
                <p>A justificativa registra a solicitação de exceção; não confirma que a transferência foi concluída.</p>
                <div *ngFor="let record of overridesFor(event.eventId)">
                  <p class="override-text">{{ record.justification }}</p>
                  <p>{{ record.userName }} · {{ record.occurredAtUtc | date:'dd/MM/yyyy HH:mm:ss Z' }}</p>
                </div>
              </section>
              <p class="privacy-note">Esta consulta mostra somente metadados e justificativas registradas. {{ event.channel === 'Clipboard' ? 'Texto copiado' : 'Conteúdo do arquivo' }} e trechos detectados não são exibidos.</p>
            </section>`
})
export class EventTableComponent {
  @Input() events: AuditEvent[] = [];
  @Input() overrides: AuditOverride[] = [];
  readonly verdicts = verdictLabels;
  readonly categories = categoryLabels;
  expandedEventId: string | null = null;

  overridesFor(eventId: string): AuditOverride[] {
    return this.overrides.filter(record => record.eventId === eventId);
  }

  eventLabel(event: AuditEvent): string {
    return this.isObservation(event) ? 'Observação de clipboard' : event.channel === 'Clipboard' ? 'Colagem' : event.fileName || (event.channel === 'Web' ? 'Envio web' : '');
  }

  channelLabel(event: AuditEvent): string {
    return event.channel === 'Clipboard' ? 'Área de transferência' : event.channel === 'Web' ? 'Web' : 'Arquivo';
  }

  isObservation(event: AuditEvent): boolean {
    return event.channel === 'Clipboard' && event.notInspectedReason === 'clipboard_focus_observed';
  }

  get expandedEvent(): AuditEvent | undefined {
    return this.events.find((event) => event.eventId === this.expandedEventId);
  }

  toggle(eventId: string): void {
    this.expandedEventId = this.expandedEventId === eventId ? null : eventId;
  }
}
