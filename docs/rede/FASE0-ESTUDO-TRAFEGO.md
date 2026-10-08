# Fase 0: estudo do tráfego de upload

Parte do [plano de inspeção TLS](PLANO-INSPECAO-TLS.md). Duas rodadas:

1. **Genérica**, sem login: valida a mecânica de cada formato de upload e as
   hipóteses do plano.
2. **Com login**, em Google Drive, Gmail e ChatGPT. OneDrive, Outlook, Dropbox
   e WeTransfer ainda precisam de captura própria.

## Como foi feito

- mitmproxy 12.2.3 com `http2=false`: o proxy oferece ao navegador só
  `http/1.1` no ALPN, como o proxy do agente vai fazer.
- Chromium 152 headless, dirigido por script, com perfil descartável.
- Um addon registra cada requisição com corpo: cabeçalhos de upload, tamanho,
  partes do multipart e se um CPF fictício (`529.982.247-25`) aparece no corpo.
- Arquivos de teste: texto pequeno com o CPF e dois binários de 12 MB, um com o
  CPF no começo e outro perto do fim.

## Resultados

| Caso | Requisição | Onde está o conteúdo | CPF visto pelo proxy |
|---|---|---|---|
| Formulário HTML com `<input type=file>` | `POST` multipart | Parte com `filename` e também campos de texto | Sim, no arquivo **e** no campo de texto |
| `fetch` + `FormData` | `POST` multipart | Parte com `filename` | Sim |
| Corpo bruto | `PUT` `application/octet-stream` | Corpo inteiro | Sim |
| Texto em JSON (formato de prompt de IA) | `POST` `application/json` | Campo dentro do JSON | Sim |
| Upload em pedaços (protocolo tus, 12 MB em pedaços de 5 MB) | `POST` de criação com `Upload-Length`, depois `PATCH` com `Upload-Offset` | Cada pedaço num `PATCH` | Só no pedaço que contém o trecho |

Detalhe do upload em pedaços:

| Arquivo | Pedaço 1 (offset 0) | Pedaço 2 (5 MB) | Pedaço 3, final (10 MB) |
|---|---|---|---|
| CPF no começo | **CPF** | - | - |
| CPF no fim | - | - | **CPF** |

Um caso extra (formulário do tmpfiles.org) não gerou upload: o script não
acionou o envio da página. Não é falha do proxy e o caso é coberto pelo teste
de formulário acima.

## O que isso confirma ou derruba no plano

1. **Oferecer só HTTP/1.1 funciona.** Todos os sites testados (httpbin,
   tusdemo, jsDelivr, tmpfiles) aceitaram a conexão sem HTTP/2. Hipótese da
   Fase 2 mantida, ainda a confirmar nos serviços grandes.
2. **Multipart: inspecionar todas as partes, não só os arquivos.** O CPF do
   campo de texto do formulário saiu numa parte sem `filename`. A Fase 5 deve
   mandar campos de texto ao `ContentScanner`, não só arquivos ao
   `ExtractorRegistry`.
3. **"Basta barrar o último pedaço" é falso.** Com o CPF no começo, ele saiu no
   primeiro `PATCH`; segurar só o pedaço final deixaria o dado vazar. Para
   texto e formatos sem compressão, o proxy precisa inspecionar **cada pedaço**
   ao chegar e barrar o pedaço onde o achado aparece. Formatos compactados
   (docx, xlsx, pdf com fluxos comprimidos) só são legíveis com o arquivo
   inteiro: neles, a inspeção só acontece no pedaço final e os anteriores já
   saíram. A Fase 5 precisa das duas estratégias.
4. **O pedaço final é identificável.** No tus, é o `PATCH` em que
   `Upload-Offset + tamanho do corpo == Upload-Length` (valor anunciado na
   criação). Cada protocolo tem o seu sinal; ver a tabela de pendências.
5. **O navegador não usou `Transfer-Encoding: chunked`** em nenhum caso: todo
   corpo veio com `Content-Length`. O parser ainda precisa suportar `chunked`,
   mas ele não é o caso comum.
6. **Há ruído do próprio navegador.** O Chromium faz `POST` em segundo plano
   para serviços do Google (`accounts.google.com`, `android.clients.google.com`).
   O proxy vai ver esse tráfego e não deve gastar inspeção pesada nele.

## Rodada com login: Drive, Gmail e ChatGPT

Mesmo ambiente, com Chromium com janela, perfil descartável e login manual. A
captura grava só metadados, sem cookies nem corpos. Os três serviços
funcionaram normalmente com o proxy oferecendo só HTTP/1.1, incluindo o login
do ChatGPT, que passa por desafio do Cloudflare. Nenhum sinal de pinning.

### Google Drive

Host do upload: `drivefrontend-pa.clients6.google.com`, caminho
`/upload/v1/items:upload`.

| Arquivo | Sequência | CPF visível |
|---|---|---|
| 50 bytes | Uma requisição `multipart/related` (`x-goog-upload-protocol: multipart`): parte de metadados em JSON + parte com o arquivo **em base64** | **Não em texto puro**: a parte do arquivo tem 68 bytes, que é 50 bytes em base64 |
| 40 MB | `POST` com `x-goog-upload-command: start` (anuncia o tamanho total, sem conteúdo) e depois **um único `PUT` com os 40 MB inteiros**, `x-goog-upload-command: upload, finalize`, resposta `x-goog-upload-status: final` | Sim |

O servidor anunciou granularidade de 2 MB, mas o Drive web não dividiu o
arquivo. O `PUT` declara `Content-Type: application/x-www-form-urlencoded`,
embora o corpo seja o arquivo.

### Gmail (anexo em rascunho)

Host do upload: `mail.google.com`, caminho `/_/upload`. Mesmo protocolo
retomável do Google: `POST` com `start` e depois **um único `POST` com o
arquivo inteiro** e `upload, finalize`. Valeu para 50 bytes e para 12 MB. O
corpo é o arquivo bruto (`Content-Type: text/plain`), CPF visível. O anexo sai
da máquina ao ser anexado, antes de o e-mail ser enviado.

### ChatGPT

Arquivo e texto seguem caminhos diferentes, e o arquivo vai para **outro
domínio**:

| Etapa | Requisição | CPF visível |
|---|---|---|
| Reserva do arquivo | `POST chatgpt.com/backend-api/files` (só metadados) | - |
| **Envio do arquivo** | `PUT` para `sdmntprbrazilsouth.oaiusercontent.com/files/<id>/raw` (armazenamento Azure), corpo bruto, resposta 201 | Sim |
| Processamento | `POST chatgpt.com/backend-api/files/process_upload_stream` (só o id) | - |
| **Texto ainda sendo digitado** | `POST /backend-api/conversation/experimental/generate_autocompletions` e `POST /backend-api/f/conversation/prepare`, em JSON | **Sim, antes de o usuário enviar** |
| Envio do prompt | `POST /backend-api/f/conversation`, JSON, resposta em streaming (`text/event-stream`) | Sim |

O WebSocket `ws.chatgpt.com` ficou aberto, mas não carregou o prompt.

### O que a rodada com login acrescenta

7. **O MVP cobre os três serviços com requisição única.** Drive (inclusive
   40 MB), Gmail e ChatGPT mandaram cada arquivo numa requisição só. O sinal de
   fim no Google é `x-goog-upload-command` contendo `finalize`. O upload em
   pedaços pode ficar para depois sem perder esses serviços.
8. **Decodificar antes de inspecionar.** O Drive manda arquivo pequeno em
   base64 dentro de `multipart/related`. O parser precisa tratar
   `multipart/related` além de `multipart/form-data` e aplicar o
   `Content-Transfer-Encoding` de cada parte (base64, quoted-printable).
9. **Não confiar no `Content-Type` da requisição.** O Drive declara
   `x-www-form-urlencoded` num corpo que é o arquivo. O tipo real tem que vir
   do conteúdo (assinatura de bytes), como a Fase 5 já prevê.
10. **O texto sai antes do "enviar".** O ChatGPT manda o que está sendo
    digitado para autocompletar e preparar a conversa. Inspecionar só o
    endpoint de envio deixa o dado vazar. A regra deve ser inspecionar todo
    corpo de texto ou JSON que sai para o domínio, não endpoints escolhidos a dedo.
11. **Exceções e bloqueio precisam ver o domínio de armazenamento.** O arquivo
    do ChatGPT não vai para `chatgpt.com`, e sim para `*.oaiusercontent.com`.
    Uma lista de exceções ou de alvos por domínio tem que contar com esses
    domínios auxiliares.

## Pendências

Sinais de finalização esperados pela documentação pública das APIs. A interface
web pode usar outro caminho, por isso cada linha precisa de captura real.

| Serviço | Modelo esperado | Sinal de pedaço final | Situação |
|---|---|---|---|
| Google Drive | Retomável do Google | `x-goog-upload-command: upload, finalize` | **confirmado** |
| Gmail | Retomável do Google | `x-goog-upload-command: upload, finalize` | **confirmado** |
| ChatGPT | `PUT` único para `*.oaiusercontent.com` | requisição única | **confirmado** |
| OneDrive | Sessão de upload, `PUT` com `Content-Range` | último byte do `Content-Range` igual ao total | a confirmar |
| Outlook web | anexo enviado antes do e-mail | a levantar | a confirmar |
| Dropbox | `upload_session/start`, `append`, `finish` | chamada `finish` | a confirmar |
| WeTransfer | em pedaços para armazenamento externo | a levantar | a confirmar |
| WhatsApp Web | criptografia no navegador | não inspecionável | limitação conhecida |
