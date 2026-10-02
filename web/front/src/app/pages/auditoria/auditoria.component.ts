import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { ApiService } from '../../core/api.service';

@Component({
  standalone: true,
  imports: [CommonModule],
  templateUrl: './auditoria.component.html',
  styleUrl: './auditoria.component.css'
})
export class AuditoriaComponent implements OnInit {
  dados: any;

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.getAuditoria().subscribe((d) => (this.dados = d));
  }
}

