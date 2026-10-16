# Integração do agente — continuidade em 10/10/2026

## Base e escopo

Análise do `safeupload.zip` disponibilizado pelo usuário, cujo `.git/HEAD` apontava para `feat/integracao-contratos-atuais`. Retomado o contexto de “Integrar e testar projeto”. O conteúdo foi extraído em `integration-review`, sem modificar o repositório em `C:\Documentos\safeupload`, sem commit e sem push. Não foram extraídos o histórico Git, dependências, artefatos de build nem os arquivos do driver.

A atualização da equipe sobre estabilização do driver e 69 cenários aprovados é um relato recebido. Não executei essa suíte nem confirmei que todos esses commits estão no ZIP. A validação abaixo cobre o código do agente e sua comunicação HTTP com o backend.

## Situação encontrada

| Parte | Evidência no código do ZIP |
|---|---|
| Backend Java | Rotas `/agent/policy`, `/agent/heartbeat` e `/agent/events`; persistência, validação e reenvio idempotente já implementados |
| Contrato de auditoria | Java aceita `File` e `Clipboard`; ausência de canal assume `File`; clipboard admite nome e extensão vazios |
| Agente C# | `HttpPolicyStore`, `LocalQueueAuditSink` e `HttpAgentDispatcher` existentes; serviço aponta para `http://127.0.0.1:8080/agent/` |
| Teste entre linguagens | `ContractSmoke` ainda enviava somente três eventos de arquivo; a ampliação sugerida no chat anterior não estava aplicada no ZIP |
| Política de clipboard | Java publicava `1Pasrd`, enquanto o padrão C# usa `1Password` |
| Angular | Modelo já contém `channel`, mas a tabela não distingue clipboard de arquivo e exibe nome vazio nesse caso |

## Alterações entregues

1. `web/back/src/main/java/com/safeupload/application/AgentService.java`: corrigida a exclusão `1Password` na política de clipboard e alinhada a indentação do método.
2. `web/back/src/test/java/com/safeupload/FunctionalMigrationTest.java`: conferência das exclusões reais da política e teste de rejeição atômica de lote com canal desconhecido ou evento File sem nome. Preservado o HTTP 422 vigente.
3. `agente/SafeUpload.Agent.ContractSmoke/Program.cs`: política de clipboard, três eventos File e um Clipboard, fila local, dispatcher real, confirmação de reenvio, API de auditoria, metadados mascarados, totais e inventário.

O construtor usado no teste é o do ZIP: `Dispatched` seguido de `Channel`. Não foi copiada a chamada com um argumento `null` adicional sugerida no histórico, pois ela não corresponde a essa versão.

## Validação executada

| Verificação | Resultado |
|---|---|
| Maven `package`, incluindo testes Java | 17 testes aprovados; JAR gerado |
| ContractSmoke C# → Java real, porta 18080, H2 em memória | Aprovado |
| Suíte completa do agente | 302 aprovados, 1 falha, 1 ignorado; 304 no total |
| Reexecução isolada do teste que falhou | Aprovada |

O teste `InspectionServiceTests.Cache_nao_reaproveita_veredito_de_arquivo_editado` esperava `Blocked` e recebeu `Approved` na suíte completa. Passou isoladamente, sem alteração no código. Isso indica uma instabilidade a investigar; não equivale a uma suíte integralmente aprovada. O teste ignorado envolve autoridade certificadora da máquina.

O ContractSmoke usou o serviço Java real e as implementações reais de fila e dispatcher C#, com eventos sintéticos. Foram confirmados quatro eventos após envio e reenvio: dois bloqueados, um aprovado e um liberado sem inspeção; um canal Clipboard e três File. O evento Clipboard manteve o UUID, origem, destino, nome/extensão vazios e trecho mascarado. O heartbeat deixou o endpoint online com quatro inspeções.

Não foi instalado/carregado driver, iniciada a aplicação WPF, simulada uma colagem real ou validado o navegador. Não foi testado MySQL; a persistência deste ensaio usou H2. O servidor temporário foi encerrado ao final.

Logs da execução na cópia de trabalho: `backend-validation.log`, `agent-validation.log`, `cache-validation.log`, `contract-validation.log` e `contract-backend.log`.

## Próximos passos da integração

1. **Apresentação no painel:** usar o canal para mostrar “Arquivo” ou “Área de transferência”, identificar clipboard sem nome de arquivo e exibir processo de destino em vez de caminho. Cobrir o comportamento com os testes de navegador existentes.
2. **Convergência com a equipe:** identificar o commit/branch de entrega do driver estabilizado e comparar contratos com esta branch antes de qualquer merge. O relato de 69 testes não demonstra compatibilidade HTTP nem substitui a validação da integração.
3. **Homologação em VM Windows:** executar agente instalado + driver estabilizado + backend + painel, com salvar/mover arquivos, aplicativos comuns, arquivos grandes e indisponibilidade/restabelecimento da rede. Conferir os mesmos UUIDs, canais e versões de política na fila e na auditoria. Investigar a instabilidade do teste de cache antes de declarar a suíte verde.
4. **Fechamento para distribuição:** definir configuração de servidor, identidade/autenticação do endpoint, política efetiva e recuperação após indisponibilidade. Hoje a política Java é fixa; clipboard está `Off` e `sourcePaths` está vazio. O envio de justificativas permanece incompleto: o dispatcher envia `overrides` vazio. O `HttpPolicyStore` usa o padrão embutido quando a busca falha, sem persistir a última política recebida.

## Uso desta entrega

O pacote de alterações contém somente os três arquivos modificados e este documento, com seus caminhos relativos. Compare-os com sua branch antes de aplicar, preservando alterações locais posteriores ao ZIP. Não substitua o projeto inteiro pela cópia de análise.

Para reproduzir, use Java 21, Maven e SDK .NET 10. Execute os testes Java e do agente e inicie o backend com H2 isolado antes do ContractSmoke. O teste espera banco vazio na porta 18080 e cadastra um usuário sintético.

```powershell
mvn -B -f web/back/pom.xml package
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj --verbosity minimal
java -jar web/back/target/backend-0.1.0.jar --server.port=18080 --spring.datasource.url=jdbc:h2:mem:contract --spring.datasource.username=sa --spring.datasource.password= --spring.jpa.hibernate.ddl-auto=create-drop
```

Com o servidor pronto, em outro terminal:

```powershell
dotnet run --project agente/SafeUpload.Agent.ContractSmoke/SafeUpload.Agent.ContractSmoke.csproj
```

No ambiente desta análise foi utilizado o SDK .NET 10.0.401 portátil existente em `.tools/dotnet`; o `dotnet` global não tinha SDK. O Maven recebeu a variável `SAFEUPLOAD_DB_PASSWORD` com um valor sintético para os testes. Não é uma credencial de produção.
