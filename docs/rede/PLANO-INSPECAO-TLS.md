# Plano: inspeção TLS no agente

Branch: `feat/inspecao-tls`. Objetivo: inspecionar o que sai da máquina para a
internet (upload de arquivo e texto enviado a sites), reaproveitando o motor de
inspeção que o agente já usa para arquivos.

A primeira versão roda **inteira no serviço**, em modo usuário. Nenhum driver
novo. O minifiltro não é alterado.

## Decisões tomadas

| Tema | Decisão |
|---|---|
| Abordagem | Inspeção TLS (proxy MITM local), não extensão de navegador. |
| Desvio do tráfego | Proxy do sistema na v1, mais filtros WFP em modo usuário. Driver WFP (callout) só depois, se necessário. |
| Proxy | Implementação própria sobre .NET (`SslStream` + parser HTTP/1.1), dentro do serviço. |
| Escopo | Descriptografa tudo, exceto exceções por **categoria** (bancos, saúde, governo…), **domínio** e **processo**. |

## Arquitetura alvo

```
Chrome/Edge/Firefox
   │  CONNECT drive.google.com:443   (proxy do sistema → 127.0.0.1:porta)
   ▼
Proxy do SafeUpload (dentro do serviço)
   │
   ├─ host em exceção (categoria, lista ou pinning detectado)? ─► túnel cego, nada é descriptografado
   │
   └─ senão: TLS com o navegador (cert da CA local, só HTTP/1.1)
             TLS com o servidor (valida o certificado real de verdade)
             │
             ├─ requisição sem corpo relevante ─► encaminha direto
             └─ upload ou POST com conteúdo ─► segura, extrai e inspeciona (InspectionService)
                      aprovado ─► encaminha    bloqueado ─► 403 + notificação no app + auditoria
```

- Código novo em `agente/SafeUpload.Agent.Network` (proxy, CA, exceções),
  hospedado por `SafeUpload.Agent.Service`.
- O motor de inspeção do `Core` é reaproveitado sem mudanças: os extratores
  (`ITextExtractor`) já recebem `Stream`, não caminho de arquivo.

### Por que a WFP em modo usuário basta na v1

A WFP tem duas partes:

| | Precisa de driver? | O que faz |
|---|---|---|
| Filtros (`FwpmFilterAdd`) | Não. O serviço cria via P/Invoke. | Permite ou bloqueia conexões por processo, porta, IP e protocolo. |
| Callouts | Sim, driver de kernel. | Redireciona ou modifica conexões. |

Com filtros, o serviço impõe "só o processo do proxy sai para 80/443" e
"UDP 443 bloqueado". Um app que ignora o proxy do sistema fica sem conexão em
vez de escapar da inspeção. O callout só seria necessário para redirecionar de
forma transparente, mantendo esses apps funcionando.

## Fases

### Fase 0 — Estudo do tráfego (antes de escrever código)

Com mitmproxy ou Fiddler numa VM, levantar como cada serviço sobe arquivos:
Google Drive, OneDrive, Dropbox, WeTransfer, anexo do Gmail e do Outlook web,
ChatGPT, WhatsApp Web.

Para cada um:
- formato (multipart, corpo bruto, JSON);
- se o upload é em pedaços;
- **qual requisição finaliza o arquivo**;
- se há criptografia no próprio navegador.

Entrega: tabela por serviço. Confirma ou derruba a hipótese de que basta barrar
o último pedaço, e já diz quais serviços não dá para inspecionar.

### Fase 1 — CA e certificados

- CA raiz gerada na instalação, **única por máquina**; chave no repositório de
  chaves da máquina, não exportável; instalada em `LocalMachine\Root`.
- Firefox: política `ImportEnterpriseRoots`, gravada no registro
  (`HKLM\SOFTWARE\Policies\Mozilla\Firefox`) em vez de `policies.json`: não
  depende da pasta de instalação nem é sobrescrita nas atualizações.
- Certificados por host gerados na hora, com cache em memória.
- A desinstalação remove a CA.

### Fase 2 — Núcleo do proxy

- Escuta em `127.0.0.1`; trata `CONNECT`; decide túnel ou interceptação pelo host.
- TLS com o navegador oferecendo só `http/1.1` (ALPN).
- TLS com o servidor **validando o certificado**. Erro de certificado nunca é mascarado.
- Parser HTTP/1.1: keep-alive, `Content-Length`, `chunked`, `100-continue`.
  WebSocket passa sem inspeção nesta versão.
- Processo de origem pela porta local (`GetExtendedTcpTable`), para a auditoria.

### Fase 3 — Desvio do tráfego

- Proxy do sistema por máquina (`ProxySettingsPerUser=0`; o serviço roda como SYSTEM).
- Filtros WFP em modo usuário: saída direta para 80/443 só para o proxy;
  UDP 443 bloqueado (força a saída do QUIC/HTTP3).
- Política `QuicAllowed=false` no Chrome e no Edge.
- O tráfego do próprio proxy sai direto.

### Fase 4 — Exceções

- Por **categoria** (bancos, saúde, governo…), por **domínio** (casamento por
  sufixo) e por **processo** (apps com pinning).
- **Detecção automática de pinning:** cliente que aborta o handshake com o
  nosso certificado manda o host para o túnel nas próximas conexões, com registro
  na auditoria.
- Listas curadas por categoria, com lista inicial (bancos brasileiros,
  operadoras de saúde, `gov.br`), editáveis no painel web e enviadas com a política.
- Depois, se necessário: base comercial de categorização (Zvelo, BrightCloud)
  ou lista aberta (UT1).

### Fase 5 — Inspeção de upload

- `multipart/form-data`: arquivos vão para o `ExtractorRegistry` pela extensão
  ou pelo tipo real do conteúdo.
- Corpos brutos (`PUT`/`POST` de arquivo) e campos de texto (prompt de IA,
  corpo de e-mail) vão para o `ContentScanner`.
- Upload em pedaços: acumular por sessão em arquivo temporário protegido e
  barrar a requisição que finaliza (conforme a Fase 0).
- Limite de tamanho do que é segurado em memória ou disco.

### Fase 6 — Decisão, aviso e auditoria

- Bloqueio: 403 ao site; o app WPF mostra o motivo pelo `NotificationPipeServer`.
- Evento de auditoria com domínio, processo, usuário e categorias encontradas.
- Justificativa: reaproveitar o fluxo atual em versão posterior.

### Fase 7 — Qualificação

Matriz de sites × navegadores, latência adicionada, apps que quebram e
comportamento com o proxy fora do ar.

### Depois

Driver WFP com callout de redirecionamento, HTTP/2, inspeção de WebSocket.

## Limitações conhecidas

- Serviços que criptografam no navegador (WhatsApp Web, Proton Drive, Mega)
  não são inspecionáveis pela rede.
- Upload em pedaços: os pedaços anteriores ao bloqueio já saíram da máquina.
- Apps com pinning só funcionam em túnel, sem inspeção.

## Decisões em aberto

1. **Inspeção falhou** (timeout, formato ilegível): libera e audita, como o
   resto do produto, ou bloqueia?
2. **Proxy fora do ar:** com proxy do sistema e filtros WFP, a máquina fica sem
   internet. Precisa de watchdog que reinicie o proxy ou desfaça o desvio.
3. **Comunicação aos funcionários:** mesmo com saúde e bancos liberados,
   descriptografar o resto pede aviso e política interna (LGPD).
