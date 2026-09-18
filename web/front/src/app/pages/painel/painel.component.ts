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

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.getPainel().subscribe((d) => (this.dados = d));
  }
}

