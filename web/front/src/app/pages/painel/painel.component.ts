import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { Subject, startWith } from 'rxjs';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { autoRefresh } from '../../core/load-state';
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
  readonly state$ = autoRefresh(this.refresh.pipe(startWith(undefined)), () => this.api.getPainel());

  percentage(count: number, total: number): number { return total ? count / total * 100 : 0; }
  barHeight(quantity: number, trend: { quantidade: number }[]): number {
    const maximum = Math.max(...trend.map((day) => day.quantidade), 1);
    return quantity / maximum * 100;
  }
}
