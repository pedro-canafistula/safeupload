import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Subject, combineLatest, startWith, switchMap, tap } from 'rxjs';
import { ApiService } from '../../core/api.service';
import { loadState } from '../../core/load-state';

@Component({
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './endpoints.component.html',
  styleUrl: './endpoints.component.css'
})
export class EndpointsComponent {
  private readonly api = inject(ApiService);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  status = 'all';
  os = 'all';
  q = '';
  readonly refresh = new Subject<void>();
  readonly state$ = combineLatest([this.route.queryParamMap, this.refresh.pipe(startWith(undefined))]).pipe(
    tap(([params]) => {
      this.status = ['online', 'offline'].includes(params.get('status') ?? '') ? params.get('status')! : 'all';
      this.os = ['win11', 'win10', 'other'].includes(params.get('os') ?? '') ? params.get('os')! : 'all';
      this.q = params.get('q') ?? '';
    }),
    switchMap(() => loadState(this.api.getEndpoints(this.status, this.os, this.q)))
  );

  apply(): void {
    void this.router.navigate([], { relativeTo: this.route, queryParams: { status: this.status, os: this.os, q: this.q } });
  }
}

