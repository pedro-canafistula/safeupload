import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnDestroy, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Subject, finalize, forkJoin, map, startWith } from 'rxjs';
import { ApiService, GerarTokenResponse } from '../../core/api.service';
import { mensagemErro, reload } from '../../core/load-state';
import { TokenCadastro } from '../../core/models';

@Component({
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './configuracoes.component.html',
  styleUrl: './configuracoes.component.css'
})
export class ConfiguracoesComponent implements OnDestroy {
  private readonly api = inject(ApiService);
  readonly refresh = new Subject<void>();
  /** Tokens e o nome da máquina que usou cada um. */
  readonly tokens$ = reload(this.refresh.pipe(startWith(undefined)), () =>
    forkJoin({ tokens: this.api.listarTokens(), endpoints: this.api.getEndpoints() }).pipe(map(({ tokens, endpoints }) => {
      const nomes = new Map(endpoints.itens.map(item => [item.hostId, item.hostname || 'Máquina ' + item.hostId]));
      return tokens.map(token => ({ ...token, maquina: token.hostId === null ? null : nomes.get(token.hostId) ?? 'Máquina ' + token.hostId }));
    })));
  readonly estados: Record<TokenCadastro['estado'], string> = { ativo: 'Ativo', usado: 'Usado', expirado: 'Expirado' };

  // Fica só em memória: ao sair da página, o token gerado deixa de ser exibido aqui (continua na tabela enquanto ativo).
  gerado: GerarTokenResponse | null = null;
  gerando = false;
  erro = '';
  statusCopia = '';
  excluindo: number | null = null;
  private temporizadorCopia?: number;

  comando(token: string): string {
    return `SafeUpload.Agent.Service.exe cadastrar https://SERVIDOR:8443/agent/ ${token}`;
  }

  gerarToken(): void {
    this.erro = '';
    this.gerando = true;
    this.api.gerarToken().pipe(finalize(() => this.gerando = false)).subscribe({
      next: resposta => {
        this.gerado = resposta;
        this.statusCopia = '';
        this.refresh.next();
      },
      error: (erro: HttpErrorResponse) => this.erro = mensagemErro(erro, 'Não foi possível gerar o token.')
    });
  }

  excluir(token: TokenCadastro): void {
    this.erro = '';
    this.excluindo = token.id;
    this.api.excluirToken(token.id).pipe(finalize(() => this.excluindo = null)).subscribe({
      next: () => {
        if (this.gerado && this.gerado.token === token.token) this.gerado = null;
        this.refresh.next();
      },
      error: (erro: HttpErrorResponse) => {
        this.erro = mensagemErro(erro, 'Não foi possível excluir o token.');
        this.refresh.next();
      }
    });
  }

  copiar(texto: string): void {
    const concluir = (copiou: boolean): void => {
      window.clearTimeout(this.temporizadorCopia);
      this.statusCopia = copiou ? 'Comando copiado para a área de transferência.'
        : 'Não foi possível copiar. Selecione o comando e copie manualmente.';
      this.temporizadorCopia = window.setTimeout(() => this.statusCopia = '', 2500);
    };
    const copia = navigator.clipboard?.writeText(texto) ?? Promise.reject();
    copia.then(() => concluir(true), () => concluir(this.copiarComAlternativa(texto)));
  }

  ngOnDestroy(): void {
    window.clearTimeout(this.temporizadorCopia);
  }

  // Alternativa para contextos sem a Clipboard API (por exemplo, acesso por HTTP fora de localhost).
  private copiarComAlternativa(texto: string): boolean {
    const campo = document.createElement('textarea');
    campo.value = texto;
    campo.setAttribute('readonly', '');
    campo.style.position = 'fixed';
    campo.style.opacity = '0';
    document.body.appendChild(campo);
    campo.select();
    let copiou = false;
    try { copiou = document.execCommand('copy'); } catch { copiou = false; }
    document.body.removeChild(campo);
    return copiou;
  }
}
