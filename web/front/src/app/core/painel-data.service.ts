import { Injectable, inject } from '@angular/core';
import { ApiService } from './api.service';

@Injectable({ providedIn: 'root' })
export class PainelDataService {
  private readonly api = inject(ApiService);
  getPainel() { return this.api.getPainel(); }
}
