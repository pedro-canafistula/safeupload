import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Observable, Subject, combineLatest, forkJoin, startWith, tap } from 'rxjs';
import { ApiService } from '../../core/api.service';
import { autoRefresh, mensagemErro } from '../../core/load-state';
import { EndpointRow } from '../../core/models';

const STATUS = ['online', 'offline', 'revogado'];

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
  q = '';
  /** Máquina com a revogação aguardando confirmação. */
  confirmandoRevogacao: number | null = null;
  ocupado: number | null = null;
  erro = '';
  mensagem = '';
  readonly refresh = new Subject<void>();
  readonly statusLabels: Record<string, string> = { online: 'Online', offline: 'Offline', revogado: 'Revogado' };
  readonly state$ = autoRefresh(
    combineLatest([this.route.queryParamMap, this.refresh.pipe(startWith(undefined))]).pipe(tap(([params]) => {
      this.status = STATUS.includes(params.get('status') ?? '') ? params.get('status')! : 'all';
      this.q = params.get('q') ?? '';
    })),
    () => forkJoin({ endpoints: this.api.getEndpoints(this.status, this.q), grupos: this.api.listarGrupos() })
  );
  readonly trackHost = (_: number, endpoint: EndpointRow): number => endpoint.hostId;

  apply(): void {
    void this.router.navigate([], { relativeTo: this.route, queryParams: { status: this.status, q: this.q } });
  }

  nome(endpoint: EndpointRow): string {
    return endpoint.hostname || 'Máquina ' + endpoint.hostId;
  }

  atribuirGrupo(endpoint: EndpointRow, grupoId: number | null): void {
    this.executar(endpoint, this.api.atribuirGrupo(endpoint.hostId, grupoId),
      grupoId === null ? `${this.nome(endpoint)} ficou sem grupo.` : `Grupo de ${this.nome(endpoint)} alterado.`,
      'Não foi possível alterar o grupo.');
  }

  revogar(endpoint: EndpointRow): void {
    this.executar(endpoint, this.api.revogarEndpoint(endpoint.hostId), `${this.nome(endpoint)} foi revogada.`,
      'Não foi possível revogar a máquina.');
  }

  private executar(endpoint: EndpointRow, acao: Observable<unknown>, sucesso: string, falha: string): void {
    this.erro = '';
    this.mensagem = '';
    this.ocupado = endpoint.hostId;
    acao.subscribe({
      next: () => {
        this.ocupado = null;
        this.confirmandoRevogacao = null;
        this.mensagem = sucesso;
        this.refresh.next();
      },
      error: (erro: HttpErrorResponse) => {
        this.ocupado = null;
        this.erro = mensagemErro(erro, falha);
        this.refresh.next();
      }
    });
  }
}
