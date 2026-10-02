import { Routes } from '@angular/router';
import { authGuard } from './core/auth.guard';
import { LoginComponent } from './features/login/login.component';
import { CadastroComponent } from './features/cadastro/cadastro.component';
import { LayoutComponent } from './layout/layout.component';
import { PainelComponent } from './pages/painel/painel.component';
import { AuditoriaComponent } from './pages/auditoria/auditoria.component';
import { EndpointsComponent } from './pages/endpoints/endpoints.component';
import { RelatoriosComponent } from './pages/relatorios/relatorios.component';

export const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: 'cadastro', component: CadastroComponent },
  {
    path: '',
    component: LayoutComponent,
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'painel', pathMatch: 'full' },
      { path: 'painel', component: PainelComponent },
      { path: 'auditoria', component: AuditoriaComponent },
      { path: 'endpoints', component: EndpointsComponent },
      { path: 'relatorios', component: RelatoriosComponent }
    ]
  },
  { path: '**', redirectTo: 'login' }
];

