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
        <thead><tr><th scope="col">Data/hora</th><th scope="col">Máquina</th><th scope="col">Canal</th><th scope="col">Arquivo / atividade</th><th scope="col">Tamanho</th><th scope="col">Resultado</th><th scope="col">Categorias</th><th scope="col">Detalhes</th></tr></thead>
        <tbody><ng-container *ngFor="let event of events; trackBy: trackEvent">
        <tr>
          <td class="nowrap">{{ event.occurredAtUtc | date:'dd/MM/yyyy HH:mm' }}</td>
          <td class="nowrap">{{ machine(event) }}</td><td>{{ channelLabel(event) }}</td>
          <td>{{ eventLabel(event) }}</td><td class="nowrap">{{ event.sizeBytes | number }} B</td>
          <td><span class="pill" [class.ok]="result(event).tone === 'ok'" [class.danger]="result(event).tone === 'danger'"
            [class.warn]="result(event).tone === 'warn'">{{ result(event).label }}</span>
            <small *ngIf="event.notInspectedReason">{{ event.notInspectedReason }}</small></td>
          <td>{{ categoryNames(event).join(', ') || '—' }}</td>
          <td><button type="button" class="btn-secondary" [attr.aria-expanded]="expandedEventId === event.eventId"
            [attr.aria-controls]="'evento-' + event.eventId" [attr.aria-label]="'Detalhes de ' + eventLabel(event)"
            (click)="toggle(event.eventId)">{{ expandedEventId === event.eventId ? 'Ocultar' : 'Ver detalhes' }}</button></td>
        </tr>
        <tr *ngIf="expandedEventId === event.eventId" class="details-row"><td colspan="8">
            <section class="event-details" [id]="'evento-' + event.eventId" [attr.aria-label]="'Detalhes de ' + eventLabel(event)">
              <h4>Detalhes da inspeção</h4>
              <p>{{ eventLabel(event) }}</p>
              <p>{{ result(event).description }}</p>
              <dl>
                <div><dt>Identificador do evento</dt><dd>{{ event.eventId }}</dd></div>
                <div><dt>Data/hora local</dt><dd>{{ event.occurredAtUtc | date:'dd/MM/yyyy HH:mm:ss Z' }}</dd></div>
                <div><dt>Máquina</dt><dd>{{ machine(event) }}</dd></div>
                <div *ngIf="event.hostname && event.endpointId && event.endpointId !== event.hostname"><dt>Identificação informada pelo agente</dt><dd>{{ event.endpointId }}</dd></div>
                <div><dt>Usuário no endpoint</dt><dd>{{ event.userName || 'Não informado' }}</dd></div>
                <div><dt>Canal</dt><dd>{{ channelLabel(event) }}</dd></div>
                <div><dt>Categorias</dt><dd>{{ categoryNames(event).join(', ') || 'Nenhuma' }}</dd></div>
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
            </section>
        </td></tr>
        </ng-container></tbody>
      </table>
    </div>`
})
export class EventTableComponent {
  @Input() events: AuditEvent[] = [];
  @Input() overrides: AuditOverride[] = [];
  readonly verdicts = verdictLabels;
  readonly categories = categoryLabels;
  expandedEventId: string | null = null;

  readonly trackEvent = (_: number, event: AuditEvent): string => event.eventId;

  /** A máquina autenticada que enviou o evento; eventos sem hostId (dados de teste) usam o rótulo do agente. */
  machine(event: AuditEvent): string {
    return event.hostname || event.endpointId || (event.hostId ? 'Máquina ' + event.hostId : 'Não informada');
  }

  /** Rótulos das categorias; as de regra personalizada mostram o nome da regra ("Regra: X"), como o painel e o CSV. */
  categoryNames(event: AuditEvent): string[] {
    const names: string[] = [];
    for (const category of event.categories) {
      const rules = category === 'CustomRule' || category === 'CustomRuleAlert' ? event.customRules ?? [] : [];
      for (const name of rules.length ? rules.map(rule => 'Regra: ' + rule) : [this.categories[category] ?? category])
        if (!names.includes(name)) names.push(name);
    }
    return names;
  }

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

  result(event: AuditEvent): { label: string; tone: 'ok' | 'warn' | 'danger'; description: string } {
    const reason = event.notInspectedReason;
    if (this.isObservation(event)) return { label: 'Monitoramento', tone: 'warn',
      description: 'Clipboard sinalizado ao mudar o foco para um aplicativo de saída. Este registro não confirma colagem nem bloqueio.' };
    if (reason === 'publication_outcome_unknown') return { label: 'Não confirmado', tone: 'warn',
      description: 'O resultado da publicação não foi confirmado. Este registro não comprova a conclusão da transferência.' };
    if (event.verdict === 'Retained') return { label: 'Retido', tone: 'warn',
      description: 'A transferência foi retida localmente. Nenhum conteúdo foi liberado para o destino protegido.' };
    if (reason === 'publication_failed') return { label: 'Pendente', tone: 'warn',
      description: 'A publicação falhou e permanece pendente. Este registro não comprova a conclusão da transferência.' };
    const inspectionFailed = reason?.startsWith('parse_error:') || [
      'file_too_large', 'unsupported_format', 'inspection_timeout', 'inspection_limit', 'not_enough_staging_space',
      'archive_encrypted', 'archive_unsupported_member', 'archive_unsupported_structure', 'archive_7z_unavailable'
    ].includes(reason ?? '');
    if (inspectionFailed && event.verdict === 'Blocked') return { label: 'Inconclusivo / bloqueado', tone: 'warn',
      description: 'A inspeção não pôde ser concluída e a operação foi bloqueada. Isso não confirma a presença nem a ausência de dados sensíveis.' };
    if (inspectionFailed && event.verdict === 'Approved') return { label: 'Inspeção inconclusiva / liberado', tone: 'warn',
      description: 'O registro indica liberação com inspeção inconclusiva. Este resultado não equivale a uma aprovação de conteúdo.' };
    if (event.verdict === 'Approved' && event.categories.length) return { label: 'Aprovado com achados', tone: 'warn',
      description: 'A inspeção permitiu a operação com achados nas categorias indicadas. Isso não significa conteúdo sem dados sensíveis nem confirma a conclusão da transferência.' };
    if (event.verdict === 'Approved') return { label: this.verdicts.Approved, tone: 'ok',
      description: 'As regras ativas não encontraram ocorrências no conteúdo analisado. Isso não garante ausência de risco.' };
    if (event.verdict === 'Blocked') return { label: this.verdicts.Blocked, tone: 'danger',
      description: 'A operação foi bloqueada por ocorrências nas categorias indicadas. ' +
        (event.channel === 'Clipboard' ? 'Revise o conteúdo copiado antes de tentar novamente.' :
          event.channel === 'Web' ? 'Revise o conteúdo enviado antes de tentar novamente.' : 'Revise o arquivo antes de tentar novamente.') };
    return { label: this.verdicts[event.verdict], tone: 'warn',
      description: 'A operação foi liberada sem conclusão da inspeção. Este resultado não equivale a uma aprovação.' };
  }

  toggle(eventId: string): void {
    this.expandedEventId = this.expandedEventId === eventId ? null : eventId;
  }
}
