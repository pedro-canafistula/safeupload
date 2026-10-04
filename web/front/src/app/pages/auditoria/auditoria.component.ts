import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Subject, combineLatest, startWith, switchMap } from 'rxjs';
import { ApiService } from '../../core/api.service';
import { loadState } from '../../core/load-state';
import { EventTableComponent } from '../../core/event-table.component';

@Component({
  standalone: true,
  imports: [CommonModule, RouterLink, EventTableComponent],
  templateUrl: './auditoria.component.html',
  styleUrl: './auditoria.component.css'
})
export class AuditoriaComponent {
  private readonly api = inject(ApiService);
  private readonly route = inject(ActivatedRoute);
  readonly refresh = new Subject<void>();
  readonly state$ = combineLatest([this.route.queryParamMap, this.refresh.pipe(startWith(undefined))]).pipe(
    switchMap(([params]) => loadState(this.api.getAuditoria(params.get('endpoint') ?? '')))
  );
}

