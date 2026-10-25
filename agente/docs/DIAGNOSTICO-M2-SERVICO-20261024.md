# Diagnóstico M2 explícito no serviço — 24/10/2026

Atividade #61, continuidade de #60 e parte de #46/#43. Fonte `23107f2066a37c9027e71a81a433fef16da26d6d`.

## Entrega

O serviço agora expõe `m2-counters` e `m2-stage-streams` no pipe administrativo existente `SafeUpload.Agent.Diagnostics`. Ambas usam o cliente M2 preparado em #60, sobre a conexão FilterPort já mantida pelo interceptor. Não abrem outra porta ou conectam um driver por conta própria. O bloqueio de binding e a proteção de vida útil existentes permanecem; sem driver conectado, retornam erro, sem dados parciais.

As consultas são executadas somente quando solicitadas. `counters`, `deny-ring`, inspeção, política, readiness e monitoramento automático mantêm seu comportamento. Não há seleção automática de perfil, retry com layout legado ou mudança na inicialização staged do interceptor.

O cliente PowerShell instalado admite os dois nomes. Em PowerShell elevado, usar `Get-SafeUploadDiagnostics.ps1 -Query m2-counters` ou `Get-SafeUploadDiagnostics.ps1 -Query m2-stage-streams`. O resultado possui objetos aninhados; `ConvertTo-Json -Depth 12` permite inspecioná-los. O canal mantém a ACL anterior, restrita a SYSTEM/Administradores. Os nomes podem conter finais de caminhos, assim como os diagnósticos já existentes; não foram expostos na interface de usuário ou APIs remotas.

## Contrato de resposta

O envelope `ok/query/data` do pipe permanece. Dentro de `data`:

- `profile=m2-e0df8d1c`, `referenceDriverCommit` e `protocolVersion=18` descrevem o contrato selecionado, não a identidade do driver carregado.
- `compatibilityVerified=false` e `protectionVerified=false` evitam converter sucesso de consulta em qualificação do par ou evidência de enforcement.
- `atomic=false`: contadores e writer-state são duas respostas sequenciais; stage-streams também não representa estado transacional.
- Contadores ficam em `snapshot.counters.prefix`, `snapshot.counters.stage` e `snapshot.writerState`. Todos os campos públicos dos structs são serializados, preservando números inteiros de 64 bits no JSON do serviço.
- Stage-streams fornece `total`, `count`, `truncated` e até 16 registros. Campos numéricos e bits desconhecidos são preservados. `name` serve para exibição; a serialização JSON pode substituir surrogate isolado. `nameCodeUnits` preserva as unidades WCHAR originais, inclusive NUL e surrogate truncado. GUID e geração são mantidos.

O consumidor deve preservar os tipos numéricos; converter uint64 para ponto flutuante pode perder precisão. Nenhum desses valores autoriza uma operação de arquivo.

## Validação

Local Release: **82/82** no recorte de integração do serviço, transporte M2, stage-streams e diagnósticos legados, tanto padrão quanto com `SafeUploadAdmissionEvidence=true`. Há sete casos novos e expansão do teste existente de pipe. A flag foi testada nesse recorte, não em matriz completa.

Os casos novos passam por transporte simulado e pelo cliente real até a projeção JSON: inteiros máximos, prefixos/caudas, GUID, flags desconhecidas, geração, nome com NUL/surrogate, truncamento, lista vazia válida, erro nativo e segunda resposta inválida sem resultado parcial. O teste existente usa pipe real para conferir descoberta em `help` e erro de ambas as consultas sem driver conectado. Não houve envio bem-sucedido ao driver real ou teste de sucesso ponta a ponta no pipe com driver conectado.

Contratos PowerShell locais: **43/43 em PS7 e 43/43 em PS5.1**. O novo caso executa os parâmetros e o switch reais extraídos por AST, substituindo apenas o envio ao pipe, e confere os nomes enviados. Não requer elevação nem abre conexão nesse teste.

[CI do agente 40148093248](https://github.com/pedro-canafistula/safeupload/actions/runs/40148093248): **três jobs aprovados**. C# Debug e Release: **893 aprovados, zero falhas, quatro skips em 897 casos** por configuração. Os sete casos novos foram conferidos em ambos os TRX, e os artefatos C# tiveram tamanho e SHA-256 verificados. Contratos PowerShell **43/43 em PS7 e 43/43 em PS5.1**, ambiente **4/4**; instalação/inspeção/reinício/desinstalação e controles existentes de interrupção/cancelamento da fila e volume cheio aprovados. Esses testes de instalação não exercitam a conexão com driver M2.

[Functional web 40148095459](https://github.com/pedro-canafistula/safeupload/actions/runs/40148095459): três jobs reprovados. `migration` sem bean `EmpresaRepository`; `agent-contract` passou C# e não conseguiu iniciar o backend; `installed-service` informou backend encerrado antes de iniciar. Logs desta execução preservados, sem correção em componentes dos colegas. Os horários UTC dos recibos são de 25/10; a execução ocorreu em 24/10 no horário de São Paulo.

Recibos locais, metadados do CI, logs, TRX e manifesto SHA-256 estão em `evidencias/diagnostico-m2-servico-20261024/`. Os commits posteriores de documentação não alteram a fonte testada acima.

## Aceite e dependências

- [x] Consultas explícitas no canal administrativo e cliente PowerShell.
- [x] Nenhuma consulta M2 automática ou substituição dos leitores legados.
- [x] Metadados de perfil/limites, inteiros e representação fiel de WCHAR.
- [x] Testes locais C# e PowerShell, com evidências preservadas.
- [x] CI do agente aprovado, recibos e hashes conferidos; falhas externas do fluxo web registradas.

#46 permanece aberta para qualificação do par exato agente/driver e integração de enforcement/composição. O interceptor atual não deve ser considerado compatível com o M2 apenas por estas consultas. #44/#47 continuam dependentes de contratos de API da equipe. Não houve Java, Angular, banco ou driver editados, novo teste de VM ou substituição do pacote homologado 0.1.14. PR #49/#42 permanecem em rascunho e sem merge.
