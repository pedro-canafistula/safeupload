import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { ApiService } from '../../core/api.service';

@Component({
  standalone: true,
  imports: [CommonModule],
  templateUrl: './relatorios.component.html',
  styleUrl: './relatorios.component.css'
})
export class RelatoriosComponent implements OnInit {
  dados: any;

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.getRelatorios().subscribe((d) => (this.dados = d));
  }
}

