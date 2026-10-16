import { Routes } from '@angular/router';
import { authGuard } from './core/auth.guard';
import { LoginComponent } from './features/login/login.component';
import { CadastroComponent } from './features/cadastro/cadastro.component';
import { LayoutComponent } from './layout/layout.component';
import { PainelComponent } from './pages/painel/painel.component';
import { AuditoriaComponent } from './pages/auditoria/auditoria.component';
import { EndpointsComponent } from './pages/endpoints/endpoints.component';
import { RelatoriosComponent } from './pages/relatorios/relatorios.component';
import { AcessoNegadoComponent } from './pages/acesso-negado/acesso-negado.component';
import { PoliticasComponent } from './pages/politicas/politicas.component';
import { PlaceholderComponent } from './pages/placeholder/placeholder.component';

export const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: 'cadastro', component: CadastroComponent },
  { path: 'acesso-negado', component: AcessoNegadoComponent },
  {
    path: '',
    component: LayoutComponent,
    canActivateChild: [authGuard],
    children: [
      { path: '', redirectTo: 'painel', pathMatch: 'full' },
      { path: 'painel', component: PainelComponent },
      { path: 'auditoria', component: AuditoriaComponent },
      { path: 'endpoints', component: EndpointsComponent },
      { path: 'relatorios', component: RelatoriosComponent },
      { path: 'politicas', component: PoliticasComponent },
      { path: 'configuracoes', component: PlaceholderComponent, data: { title: 'Configurações' } }
    ]
  },
  { path: '**', redirectTo: 'login' }
];
