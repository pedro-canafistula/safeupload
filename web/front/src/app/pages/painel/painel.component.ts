import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Subject, startWith, switchMap } from 'rxjs';
import { ApiService } from '../../core/api.service';
import { loadState } from '../../core/load-state';
import { categoryLabels } from '../../core/models';
import { EventTableComponent } from '../../core/event-table.component';

@Component({
  standalone: true,
  imports: [CommonModule, RouterLink, EventTableComponent],
  templateUrl: './painel.component.html',
  styleUrl: './painel.component.css'
})
export class PainelComponent {
  private readonly api = inject(ApiService);
  readonly refresh = new Subject<void>();
  readonly state$ = this.refresh.pipe(startWith(undefined), switchMap(() => loadState(this.api.getPainel())));
  readonly categories = categoryLabels;

  // dados fictícios (depois troque pelos dados da API)
  resumo = {
    inspecoes: 1247,
    variacao: 12,
    bloqueados: 89,
    aprovados: 1135,
    rejeitados: 23,
  };

  constructor(private api: ApiService) {}

  pct(valor: number): string {
    const total = this.resumo.inspecoes;
    return ((valor / total) * 100).toLocaleString('pt-BR', {
      minimumFractionDigits: 1,
      maximumFractionDigits: 1,
    });
  }

  ngOnInit(): void {
    this.api.getPainel().subscribe({
      next: (d: any) => (this.dados = d),
      error: (e: any) => console.error('erro painel:', e),
    });
  }
}
