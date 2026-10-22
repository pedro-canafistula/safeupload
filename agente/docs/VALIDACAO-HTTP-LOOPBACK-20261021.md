# Validação do transporte HTTP do agente — 21/10/2026

Continuação da macro **Consolidar a base do agente Windows**, sobre o candidato local `1771442db3ecc7529266f859fee61633ef5201cd`.

Atualização posterior: [verificação das rotas no repositório](VERIFICACAO-ROTAS-POLITICA-20261021.md). A orientação atual é verificar o código e aguardar a disponibilização da integração; as perguntas ao final deste checkpoint são históricas e não devem ser enviadas como pedido de confirmação de existência.

## Entrega

Dois testes de integração do agente usam `HttpClient` real, sockets TCP em loopback e fila/cache em diretórios temporários. A fixture é exclusiva da suíte; não é um novo servidor do produto. Escuta apenas em `127.0.0.1` com porta alocada pelo sistema, sem reserva HTTP.sys, serviço, registro ou driver. Suporta o corpo chunked emitido pelo cliente JSON e limita cabeçalhos/corpos. Não usa proxy nem segue redirecionamentos.

Nenhum contrato, configuração ou fluxo do produto foi modificado. Java, Angular, banco e driver permanecem fora do diff. Não houve chamada a API externa.

### Cenário 1 — Política, falha parcial da API e reinício

1. Consulta real `GET /agent/policy?endpointId=PC%20SINTETICO%2F01`, com identidade sintética escapada corretamente.
2. A política versão 7 é aceita como remota e salva no cache de teste; ACL protegida está explicitamente desativada apenas nessa fixture.
3. Um evento bloqueado e sua justificativa são gravados na fila real de teste.
4. Heartbeat recebe 404 e auditoria recebe 503. Ambos os registros permanecem pendentes.
5. Novas instâncias de cache/fila simulam a reabertura após reinício. A consulta remota passa a responder 404; a política vem do disco, preservando versão/categorias.
6. Com heartbeat ainda 404, auditoria recebe recibo completo e o agente confirma os dois registros.
7. O teste compara os dois corpos HTTP enviados: são idênticos. ID/horário são preservados e os trechos locais não trafegam.

### Cenário 2 — Conexão perdida antes do recibo

1. O servidor sintético recebe e registra o lote em memória, depois fecha o socket sem resposta HTTP.
2. O cliente real lança erro de transporte e a fila continua pendente.
3. Após reabrir a fila, o agente reenvia o mesmo corpo e recebe ambas as contagens completas.
4. Evento e justificativa são confirmados somente após esse recibo.

Esse cenário demonstra entrega pelo menos uma vez e preservação local; **não testa persistência nem deduplicação no Java/MySQL**. A fixture não implementa banco, credenciais ou identidade de instalação.

## Verificações

| Execução | Resultado |
|---|---|
| Dois testes novos em Debug | 2 aprovados, 0 falhos, 0 ignorados |
| Build da solução Release | 0 avisos, 0 erros |
| Recorte de integração Debug, incluindo os novos testes | 49 aprovados, 0 falhos, 0 ignorados |
| Suíte completa Release | 727 aprovados, 7 falhos, 4 ignorados; total 738 |

A comparação dos TRX anterior e atual confirma que os sete testes falhos têm os mesmos nomes. Permanecem erros de privilégio de symlink e atribuição de proprietário no Windows. Não houve filtro na suíte completa, alteração de asserções existentes ou novos skips. O build Debug dos projetos usados nos testes também concluiu sem avisos de compilação.

Os contratos PowerShell passaram no checkpoint anterior e não foram repetidos nesta rodada, pois nenhum script ou arquivo de instalador foi alterado. Instalação, conta SYSTEM, UI, API externa, deduplicação e par real agente/driver seguem pendentes.

## Atualização das referências

- Main permanece `efe93cf75aa668f2870c0951b48b3ef2c6332226`.
- PR #42 / instalador permanece `9f608153f9a7e7e0daa6d904a87c760820316202`.
- M2 avançou de `688c61af` para `06bafa7d`. O diff desse intervalo contém quatro documentos de design/revisão em `driver/`, sem mudança de código do agente. Nada desse intervalo foi importado. A lista de conflitos do checkpoint anterior permanece histórica; não foi alegada uma nova qualificação da M2.

## Alinhamento necessário com Thiago

O usuário pediu para reunir as perguntas ao final desta tarefa. Nenhuma mensagem foi enviada à equipe.

1. Qual será o fluxo definitivo de cadastro e heartbeat do agente: manter as rotas de compatibilidade `/agent/heartbeat` e `/agent/policy`, ou adaptar ao cadastro `/agent/api/synchronize` e heartbeat `/agent/api/heartbeat` com `id_usuario_so`? Confirmar também como a identidade sobrevive a reinício e reinstalação.
2. Qual a rota de consulta de política por endpoint? Solicitar exemplo JSON da resposta, incluindo versão, categorias, escopos e clipboard, e o comportamento quando não existir política publicada.
3. Qual ambiente de teste e mecanismo de autenticação devem ser usados no cadastro, heartbeat, política e `/agent/events`? Confirmar que reenvios já persistidos também entram nas contagens de recibo, para o agente conseguir confirmar sua fila.

Recomendação técnica: fechar o fluxo completo e seus exemplos antes de alterar o adaptador C#. Não trocar somente BaseUrl, pois rotas e DTOs diferem. Em seguida validar o agente contra a API da equipe, preservando o modelo de fila e a confirmação integral.

## Reprodução

Na raiz do candidato:

```powershell
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Debug --filter FullyQualifiedName~AgentHttpLoopbackTests --logger trx
dotnet build agente/SafeUpload.Agent.sln -c Release
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Release --no-build --logger trx
```

Registrar exit codes e preservar os TRX. A suíte completa continua reprovada neste ambiente e precisa de execução no Windows com os privilégios adequados. O pacote local desta continuação inclui os logs, os TRX, comparação dos nomes falhos e patches verificáveis. A macro permanece aberta; não houve publicação nem merge.
