import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';

export interface PainelData {
  periodo: { rotulo: string; inicio: string; fim: string };
  indicadores: {
    incidentesAbertos: { valor: number; variacaoPercentual: number; comparacao: string; tom: string };
    criticosSemTratamento: { valor: number; acimaDe24Horas: number; tom: string };
    dadosBloqueados: { valor: number; unidade: string; variacaoPercentual: number; comparacao: string; tom: string };
    agentesProtegidos: { percentual: number; semComunicacao: number; tom: string };
  };
  incidentesPorDia: { data: string; rotulo: string; quantidade: number }[];
  porCanal: { canal: string; percentual: number }[];
  incidentesRecentes: { id: string; severidade: string; politica: string; usuario: string; area: string; canal: string; acao: string; status: string; ocorridoHa: string }[];
  usuariosMaiorRisco: { usuario: string; area: string; pontuacao: number }[];
}

@Injectable({ providedIn: 'root' })
export class PainelDataService {
  private readonly http = inject(HttpClient);
  getPainel() { return this.http.get<PainelData>('/data/painel.json'); }
}
