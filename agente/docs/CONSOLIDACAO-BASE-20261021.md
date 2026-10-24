# Consolidar a base do agente Windows

Data da inspeção: 21/10/2026. Candidato local, sem publicação e sem merge.

Este é o checkpoint inicial. Estado posterior: [homologação operacional e publicação em rascunho](HOMOLOGACAO-INSTALADOR-20261021.md), com PR #49, atividades #43–#48 e evidências reais do candidato 0.1.4. As limitações e resultados iniciais abaixo permanecem como histórico.

Continuação: [validação com HTTP real em loopback](VALIDACAO-HTTP-LOOPBACK-20261021.md), com dois novos testes, 49/49 controles focados e atualização das dependências. Os resultados abaixo preservam o checkpoint inicial.

## Escopo e proveniência

Alterações limitadas a `agente/`: C#/.NET, instalador PowerShell/Inno Setup, testes e documentação do agente. Java, Angular, banco, driver e workflows não são alterados. Arquivos sincronizados em `sources/` permanecem preservados.

| Referência atualizada | Commit |
|---|---|
| main | `efe93cf75aa668f2870c0951b48b3ef2c6332226` |
| feat/agente-instalador, PR #42 | `9f608153f9a7e7e0daa6d904a87c760820316202` |
| feat/driver-m2 | `688c61af6fa80a4560a8816008eeb21e374cf6e8` |

Branch local: `tarefa/consolidar-base-agente-windows`, criada sobre a main acima. Foram aplicadas somente as alterações de `agente/` do PR #42, com três novos casos de regressão e documentação desta análise. O PR #42 permanece em rascunho. O workflow e os documentos da raiz do PR #42 não foram copiados; o contrato necessário acompanha o candidato em `agente/docs/`.

Os três ZIPs foram abertos somente para leitura:

- `safeupload-main (4).zip`: 23.977 entradas no total; seus **233 arquivos em agente/** coincidem byte a byte com os blobs Git da main atual. Comparação por SHA-1 do objeto Git, incluindo cabeçalho e tamanho, sem normalizar quebras de linha. Portanto, não há código adicional do agente para importar desse ZIP.
- `Safe Upload- Análise e projeto de software (3).zip`: exportação textual do grupo; informa que M2 ainda depende de qualificação e que o agente possui trabalho compartilhado com o responsável do driver. É contexto histórico, sem substituir o código atual ou autorizar operação de VM.
- `TC.zip`: exportação textual de alinhamento com Thiago; confirma responsabilidade pelo instalador e envio de metadados de auditoria, com API web sob responsabilidade dele. Conversas não foram incorporadas ao código ou ao patch.

Os inventários, hashes SHA-256 dos ZIPs e a comparação por arquivo estão no pacote local de evidências que acompanha esta entrega.

## Resultado da comparação

Main e instalador têm merge textual limpo na simulação `git merge-tree --write-tree`; isso não comprova compatibilidade operacional. A main incorporou a coleta isolada de auditoria (#41) e novos endpoints administrativos desde a base do PR #42.

A M2 difere da main em 318 arquivos do agente no diff desde o ancestral comum, com 53.235 adições e 1.207 remoções. A comparação do ZIP com o tip M2 encontra 103 arquivos idênticos, 97 diferentes, 232 somente na M2 e 33 somente no ZIP.

A simulação entre os tips M2 e instalador encontrou **14 conflitos no agente**:

- `README.md`
- `SafeUpload.Agent.ContractSmoke/Program.cs`
- `SafeUpload.Agent.Core/Domain/Policy.cs`
- `SafeUpload.Agent.Core/Infrastructure/CachedPolicyStore.cs`
- `SafeUpload.Agent.Core/Infrastructure/DurableHttpPolicyStore.cs`
- `SafeUpload.Agent.Core/Infrastructure/LocalQueueAuditSink.cs`
- `SafeUpload.Agent.Service/Dispatch/HttpAgentDispatcher.cs`
- `SafeUpload.Agent.Service/Notifications/JustificationPipeServer.cs`
- `SafeUpload.Agent.Service/Policy/RefreshingPolicyStore.cs`
- `SafeUpload.Agent.Service/Program.cs`
- `SafeUpload.Agent.Tests/CachedPolicyStoreTests.cs`
- `SafeUpload.Agent.Tests/ClipboardServiceTests.cs` (modificado/excluído)
- `SafeUpload.Agent.Tests/DispatcherReliabilityTests.cs`
- `SafeUpload.Agent.Tests/RefreshingPolicyStoreTests.cs`

A mesma simulação encontra dois conflitos em Java; foram apenas identificados, sem resolução ou alteração. Não ocorreu merge de branches. O relatório bruto da simulação está no pacote local.

Há conflitos semânticos mesmo fora dessas linhas: a M2 não contém o canal `Web` presente na main; seu transporte amplia o protocolo base v18 com extensões staged e capacidades específicas, além de leitura estrita de política para autorizar staging. Não copiar arquivos de protocolo isolados, remover o canal Web ou substituir cache/fila/boot policy escolhendo um lado inteiro. A integração M2 deve ocorrer como tarefa separada, sobre o commit acordado com o responsável pelo driver e com par exato de artefatos.

## Contratos de API verificados na fonte atual

| Uso do agente | Java na main | Resultado |
|---|---|---|
| `POST /agent/events`, lote com eventos e justificativas | `AgentEventsController` e `AuditContracts` | Rota e formato de recibo compatíveis na fonte; validação real pendente |
| `POST /agent/heartbeat`, endpointId/hostname/os/agentVersion/policyVersion | `POST /agent/api/heartbeat`, exige `id_usuario_so` | Rota e identidade incompatíveis; mudar só BaseUrl não resolve |
| `GET /agent/policy?endpointId=...` | Sem controller implementando essa rota em `web/back/src` | Consulta central bloqueada por dependência da API |
| Sincronização de identidade | `POST /agent/api/synchronize`, objetos host/usuarioSo | Não implementada pelo agente atual |
| Solicitação de revisão | `POST /agent/api/tickets`, IDs relacionais e descrição | Sem tradução/fluxo acordado no agente |

`AuditContracts.Batch` aceita schemaVersion 1, hostname e agentVersion, ignora campos desconhecidos e limita cada lista a 100 registros. O agente limita o lote a 100 de cada tipo, envia enums File/Clipboard/Web e preserva ID, horário e política originais. Há limites de tamanho/validação no servidor que ainda precisam ser testados com os produtores reais; esta inspeção não comprova aceite de todo evento possível. Registros recusados continuam na fila.

O candidato separa projeção de rede da fila local, remove trechos mascarados do envio e reduz destinos Web à origem HTTP(S). Recibo só confirma quando ambas as contagens coincidem, inclusive zeros explícitos. Não há fallback silencioso de rota nem implantação de autenticação inventada nesta entrega.

## Validação desta execução

| Verificação | Resultado |
|---|---|
| Build da solução Debug | 0 avisos, 0 erros |
| Build da solução Release | 0 avisos, 0 erros |
| Suíte completa Debug antes dos três novos casos | 722 aprovados, 7 falhos, 4 ignorados; total 733 |
| Suíte completa Release, incluindo novos casos | 725 aprovados, 7 falhos, 4 ignorados; total 736 |
| Recorte Debug de auditoria/dispatcher/política após novos casos | 47 aprovados, 0 falhos, 0 ignorados |
| Contratos do instalador PowerShell 7.6.5 | 39/39 |
| Contratos do instalador Windows PowerShell 5.1 | 39/39 |
| Ambiente de módulos/ACL sem instalar serviço | 4/4 |
| Parsing de scripts do instalador PowerShell 7 | Sem erros |

As sete falhas da suíte completa são cinco casos de criação de symlink sem privilégio e dois de handback com atribuição de proprietário recusada pelo Windows. Um destes últimos esperava cancelamento, mas recebeu IOException causada pela recusa de proprietário. Os nomes e rastros completos estão nos TRX. As falhas não foram removidas, os testes não foram flexibilizados e a suíte completa continua **reprovada neste ambiente**. Os quatro testes ignorados já possuem esse comportamento na suíte; não foram adicionadas exclusões.

Os três novos casos exercitam heartbeat 404 sem impedir auditoria e respostas 401/403 mantendo evento e justificativa após reabrir a fila, seguidas de reenvio bem-sucedido. São testes de componente com fila real e transporte HTTP simulado. Não comprovam Java/MySQL, driver, serviço instalado, SYSTEM ou proteção ativa.

Instalação/desinstalação real, artefato EXE, assinatura, upgrade/repair, Windows 10/11, UI em sessão comum e par agente/driver não foram executados nesta rodada. O smoke do instalador altera serviço e deve ser executado em máquina descartável pelo fluxo existente, preservando suas verificações de ambiente. Resultados históricos do PR #42 não são apresentados como novos resultados.

## Prioridades e dependências

1. **P0 — Contratos de identidade, heartbeat e política:** Thiago confirma o contrato publicado, registro inicial, IDs/credencial por instalação, autorização e retorno de política. O agente implementa o adaptador somente depois desse alinhamento; não altera Java/banco. Critério: polling e heartbeat reais, política inválida/indisponível observável e auditoria independente.
2. **P1 — Candidato instalado:** validar esta consolidação do instalador/auditoria em VM Windows 10/11, conta comum e SYSTEM, preservando políticas e fila após reinício. Confirmar servidor HTTPS e ausência de conteúdo de arquivo nas requisições.
3. **P1 — Integração M2 do lado do agente:** responsável pelo driver confirma commit/par, capacidades, readiness e boot policy. Resolver os 14 conflitos preservando inspeção estrita, cache protegido, Web e auditoria; submeter o diff do agente à revisão conjunta antes de execução integrada.
4. **P1 — Auditoria ponta a ponta:** Thiago e responsável pelo painel verificam persistência, deduplicação, contagens no reenvio e visualização. Ensaio com API indisponível, resposta perdida, 401/403, recibo parcial e reinício; os mesmos ID/horário devem sobreviver.
5. **P2 — Operação prolongada:** medir crescimento/leitura da fila e definir retenção, compactação e proteção local, sem descartar pendências. Upgrade/repair e assinatura dependem do processo de distribuição.

As conversas indicam oportunidades de alinhamento com Thiago e com o responsável pelo driver; nenhuma mensagem foi enviada ao WhatsApp ou ClickUp.

## Checklist de aceite da macro

- [x] Atualizar referências e inspecionar os três ZIPs.
- [x] Identificar divergências textuais e semânticas.
- [x] Preparar candidato restrito a agente, preservando trabalhos existentes.
- [x] Compilar Debug/Release e registrar testes completos, falhas e recorte focado.
- [x] Preservar PR #42 em rascunho e não fazer merge.
- [ ] Publicar atividades/branch/PR: conector informa push=false e a criação de issue retornou HTTP 403, Resource not accessible by integration.
- [ ] Alinhar heartbeat/política/identidade com a API da equipe.
- [ ] Aprovar suíte completa no ambiente com privilégios necessários.
- [ ] Validar instalação e integração real com API e par de driver acordado.
- [ ] Obter revisão e aprovação explícita antes de merge.

A macro permanece aberta. O patch e os textos de publicação são a entrega verificável enquanto o acesso de escrita não está disponível.

## Reprodução local

Na raiz do candidato, executar:

```powershell
dotnet build agente/SafeUpload.Agent.sln -c Debug
dotnet build agente/SafeUpload.Agent.sln -c Release
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Debug --logger trx
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Release --logger trx
pwsh -NoProfile -File agente/installer/tests/Test-InstallerContracts.ps1
powershell.exe -NoProfile -File agente/installer/tests/Test-InstallerContracts.ps1
pwsh -NoProfile -File agente/installer/tests/Test-InstallerEnvironment.ps1
```

Registrar cada exit code e preservar TRX/logs, inclusive falhas. O recorte de 47 testes está documentado no roteiro local da entrega e não substitui a suíte completa. Para instalação real, seguir `agente/installer/README.md` em máquina descartável.
