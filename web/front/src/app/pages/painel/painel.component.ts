import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { catchError, of } from 'rxjs';
import { RouterLink } from '@angular/router';
import { categoryLabels, verdictLabels } from '../../core/models';
import { PainelDataService } from '../../core/painel-data.service';

@Component({
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './painel.component.html',
  styleUrl: './painel.component.css'
})
export class PainelComponent {
  private readonly painelData = inject(PainelDataService);
  readonly painel$ = this.painelData.getPainel().pipe(catchError(() => of(null)));
  readonly categories = categoryLabels;
  readonly verdicts = verdictLabels;

  percentage(count: number, total: number): number { return total ? count / total * 100 : 0; }
  barHeight(quantity: number, trend: { quantidade: number }[]): number {
    const maximum = Math.max(...trend.map((day) => day.quantidade), 1);
    return Math.max(2, quantity / maximum * 100);
  }
}
