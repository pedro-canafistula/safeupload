import { Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
@Component({ standalone: true, template: '<section class="placeholder"><h1>{{ title }}</h1><div><h2>Em breve</h2><p>Esta área está preparada para receber os dados e operações do serviço.</p></div></section>', styles: [':host{display:block;color:#172342}.placeholder h1{margin:4px 0 20px;font-size:23px}.placeholder div{background:#fff;border:1px solid #dfe5ef;border-radius:10px;padding:28px}.placeholder h2{margin:0 0 8px;font-size:16px}.placeholder p{margin:0;color:#66738e}'] })
export class PlaceholderComponent { readonly title = inject(ActivatedRoute).snapshot.data['title'] ?? 'Em breve'; }
