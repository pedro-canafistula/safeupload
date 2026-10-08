import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { ApiService } from '../../core/api.service';

@Component({
  standalone: true,
  imports: [CommonModule],
  templateUrl: './painel.component.html',
  styleUrl: './painel.component.css'
})
export class PainelComponent implements OnInit {
  dados: any;

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