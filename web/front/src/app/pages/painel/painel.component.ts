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

  percentage(count: number, total: number): number { return total ? count / total * 100 : 0; }
}
