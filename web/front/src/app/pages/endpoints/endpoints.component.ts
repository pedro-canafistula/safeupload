import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { ApiService } from '../../core/api.service';

@Component({
  standalone: true,
  imports: [CommonModule],
  templateUrl: './endpoints.component.html',
  styleUrl: './endpoints.component.css'
})
export class EndpointsComponent implements OnInit {
  dados: any;

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.getEndpoints().subscribe((d) => (this.dados = d));
  }
}

