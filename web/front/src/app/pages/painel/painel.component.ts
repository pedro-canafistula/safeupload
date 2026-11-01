import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { Subject, startWith, switchMap } from 'rxjs';
import { RouterLink } from '@angular/router';
import { categoryLabels } from '../../core/models';
import { loadState } from '../../core/load-state';
import { EventTableComponent } from '../../core/event-table.component';
import { PainelDataService } from '../../core/painel-data.service';

@Component({
  standalone: true,
  imports: [CommonModule, RouterLink, EventTableComponent],
  templateUrl: './painel.component.html',
  styleUrl: './painel.component.css'
})
export class PainelComponent {
  private readonly painelData = inject(PainelDataService);
  readonly refresh = new Subject<void>();
  readonly state$ = this.refresh.pipe(startWith(undefined), switchMap(() => loadState(this.painelData.getPainel())));
  readonly categories = categoryLabels;

  percentage(count: number, total: number): number { return total ? count / total * 100 : 0; }
  barHeight(quantity: number, trend: { quantidade: number }[]): number {
    const maximum = Math.max(...trend.map((day) => day.quantidade), 1);
    return quantity / maximum * 100;
  }
}
