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

  // dados fictícios do card
  resumo_inspecoes = { inspecoes: 1247, variacao: 12 };

  resumo_bloqueados = { quantidade: 89};

  resumo_aprovados = { quantidade: 1000};

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.getPainel().subscribe({
      next: (d: any) => (this.dados = d),
      error: (e) => console.error('erro painel:', e),
    });
  }
}