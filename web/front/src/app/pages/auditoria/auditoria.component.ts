import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MockDataService, Severity, IncidentStatus } from '../../core/mock-data.service';
@Component({ standalone: true, imports: [CommonModule, FormsModule], templateUrl: './auditoria.component.html', styleUrl: './auditoria.component.css' })
export class AuditoriaComponent {
  private readonly data = inject(MockDataService); severity = ''; status = ''; query = '';
  get incidents() { return this.data.incidents.filter((i) => (!this.severity || i.severity === this.severity) && (!this.status || i.status === this.status) && (!this.query || Object.values(i).join(' ').toLowerCase().includes(this.query.toLowerCase()))); }
  exportCsv(): void { const csv = ['ID;Severidade;Política;Usuário;Canal;Ação;Status;Quando', ...this.incidents.map((i) => [i.id,i.severity,i.policy,i.user,i.channel,i.action,i.status,i.when].join(';'))].join('\n'); const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' })); const a = document.createElement('a'); a.href = url; a.download = 'incidentes.csv'; a.click(); URL.revokeObjectURL(url); }
}
