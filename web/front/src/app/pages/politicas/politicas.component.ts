import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { MockDataService } from '../../core/mock-data.service';
@Component({ standalone: true, imports: [CommonModule], templateUrl: './politicas.component.html', styleUrl: './politicas.component.css' })
export class PoliticasComponent { readonly policies = inject(MockDataService).policies; }
