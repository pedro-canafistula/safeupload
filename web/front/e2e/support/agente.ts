import { expect, request as playwrightRequest, type APIRequestContext } from '@playwright/test';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, type KeyObject } from 'node:crypto';

/** Backend real (os testes que usam este arquivo precisam dele em 127.0.0.1:8080). */
export const API = 'http://127.0.0.1:8080';

export interface HostInfo {
  hostname: string;
  ip: string;
  mascara: number;
  sistema_operacional: string;
  versao_so: string;
  mac_address: string;
}

/** Entra com a sessão de administrador no contexto `request` (cookie de sessão). */
export async function entrarApi(request: APIRequestContext, email: string, senha: string): Promise<void> {
  expect((await request.post(API + '/auth/login', { data: { email, senha } })).status()).toBe(200);
}

/** POST /admin/token com a sessão de administrador já aberta em `request`. */
export async function gerarToken(request: APIRequestContext): Promise<string> {
  const resposta = await request.post(API + '/admin/token');
  expect(resposta.status()).toBe(200);
  return (await resposta.json()).token;
}

/**
 * Agente falso que se cadastra como o de verdade (docs/console-agente.md): par Ed25519, POST /agent/enroll com o
 * token e a chave pública (SPKI DER em Base64) e, depois, requisições assinadas. Usa um contexto HTTP próprio, sem o
 * cookie de sessão do administrador, que vive entre os testes; chame `encerrar()` no fim.
 */
export class AgenteFalso {
  private constructor(private readonly request: APIRequestContext, readonly idHost: number,
                      private readonly chavePrivada: KeyObject, readonly host: HostInfo) {}

  static async cadastrar(token: string, host: HostInfo): Promise<AgenteFalso> {
    const request = await playwrightRequest.newContext();
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const resposta = await request.post(API + '/agent/enroll', { data: {
      token, chave_publica: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), host
    } });
    expect(resposta.status(), await resposta.text()).toBe(201);
    const { id_host } = await resposta.json();
    expect(Number.isInteger(id_host) && id_host > 0).toBeTruthy();
    return new AgenteFalso(request, id_host, privateKey, host);
  }

  /** Requisição assinada: X-SafeUpload-Host/Time/Nonce/Signature sobre método, rota, host, horário, nonce e corpo. */
  enviar(metodo: 'GET' | 'POST', rota: string, corpo?: unknown) {
    const body = corpo === undefined ? '' : JSON.stringify(corpo);
    const time = Math.floor(Date.now() / 1000);
    const nonce = randomBytes(18).toString('base64');
    const mensagem = ['SafeUpload-v1', metodo, rota, String(this.idHost), String(time), nonce,
      createHash('sha256').update(body, 'utf8').digest('hex')].join('\n');
    const assinatura = sign(null, Buffer.from(mensagem, 'utf8'), this.chavePrivada).toString('base64');
    return this.request.fetch(API + '/agent/' + rota, {
      method: metodo,
      headers: {
        'Content-Type': 'application/json',
        'X-SafeUpload-Host': String(this.idHost),
        'X-SafeUpload-Time': String(time),
        'X-SafeUpload-Nonce': nonce,
        'X-SafeUpload-Signature': assinatura
      },
      data: body === '' ? undefined : Buffer.from(body, 'utf8')
    });
  }

  encerrar(): Promise<void> {
    return this.request.dispose();
  }

  /** Sem `formatoRegras`, o heartbeat é o de um agente que não entende regras personalizadas (o servidor grava 0). */
  heartbeat(politicaAplicada: number | null, formatoRegras?: number) {
    return this.enviar('POST', 'heartbeat', { host: this.host, politica_aplicada: politicaAplicada, versao_agente: '0.2.0',
      ...(formatoRegras === undefined ? {} : { formato_regras: formatoRegras }) });
  }

  politica() {
    return this.enviar('GET', 'policy');
  }

  eventos(events: object[], overrides: object[] = []) {
    return this.enviar('POST', 'events', { schemaVersion: 1, hostname: this.host.hostname, agentVersion: '0.2.0', events, overrides });
  }
}

/** Evento de auditoria no formato do agente (schemaVersion 1). */
export function evento(campos: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    eventId: randomUUID(), occurredAtUtc: new Date().toISOString(), endpointId: 'ROTULO-DO-AGENTE',
    userName: 'usuario-e2e', fileName: 'arquivo.txt', extension: '.txt', sizeBytes: 128, verdict: 'Approved',
    categories: [], processName: 'editor.exe', processId: 42, destinationPath: 'C:\\Dados\\Financeiro\\arquivo.txt',
    notInspectedReason: null, policyVersion: 1, elapsedMs: 5, channel: 'File', ...campos
  };
}
