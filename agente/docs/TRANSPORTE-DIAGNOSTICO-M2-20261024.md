# Transporte explícito de diagnóstico M2 — 24/10/2026

Atividade #60, parte de #46/#43. Fonte: `09e56f5c2c9b07c537ef4e317c7e05fcf8c1ea19`. Continuidade do decodificador preparado em #59. A revisão anterior confirmou main `efe93cf75aa668f2870c0951b48b3ef2c6332226`, sem novidade de API consumível; esta entrega avança somente o lado C# do agente.

## Problema e resultado

No driver de referência `feat/driver-m2`, commit `e0df8d1c1f889418a133d3ae66a87a6c76a7bd5f`, os comandos de diagnóstico exigem igualdade entre a capacidade de saída e o tamanho da estrutura. Um buffer genérico maior ou a leitura legada não satisfaz esse contrato, embora a versão base continue 18.

| Consulta | Comando | Saída M2 | Saída legada |
| --- | ---: | ---: | ---: |
| Contadores | 28 | 296 bytes | 120 bytes |
| Writer-state | 12 | 304 bytes | 288 bytes |
| Stage-streams | 29 | 2.576 bytes | indisponível neste leitor |

`M2DiagnosticClient` seleciona explicitamente esse perfil, valida os bytes efetivamente retornados, tamanho declarado e versão quando existente. Writer-state tem `SectionInFlightNow` no segundo campo, sem campo de versão. Contadores preservam o prefixo legado e acrescentam 176 bytes; writer-state acrescenta quatro uints. Stage-streams reutiliza o decodificador limitado e estrito de #59.

`FilterPort.M2Diagnostics.cs` implementa o adaptador sobre `QueryControl`, reutilizando o cabeçalho v18/16 bytes/reservado zero, a conferência da contagem nativa e a proteção de vida útil da porta. Só admite consultas 12/28/29 e capacidades exatas. Criar o cliente não conecta nem carrega um driver. Comandos e buffers inválidos são recusados antes do envio.

Falhas são propagadas, sem repetição em perfil legado ou sucesso vazio. As duas consultas de contadores são sequenciais, sem atomicidade; se a segunda falhar, o método não entrega um conjunto parcial.

## Validação e evidências

Local Release: **75 aprovados, zero falhas, zero skips** no recorte de transporte M2, stage-streams e diagnósticos legados, tanto na configuração padrão final quanto com `SafeUploadAdmissionEvidence=true`. São 28 casos novos de transporte; os outros 47 são regressões. A configuração com flag é um recorte, não uma matriz completa.

Os testes usam transporte simulado com bytes independentes dos structs, contagens/versões inválidas, erro de comando não suportado e falha na segunda consulta. O adaptador real só é exercitado em recusas anteriores ao P/Invoke e porta descartada, com handle inválido não proprietário construído por reflexão apenas no teste. Não houve envio nativo ao driver.

Resultados do CI, recibos e hashes estão em `evidencias/transporte-diagnostico-m2-20261024/`. O resumo identifica o commit testado; documentos posteriores não modificam essa fonte. A suíte de homologação é [40118521355](https://github.com/pedro-canafistula/safeupload/actions/runs/40118521355); o fluxo que depende do backend é [40118526116](https://github.com/pedro-canafistula/safeupload/actions/runs/40118526116).

CI do agente: **três jobs aprovados**. Em Debug e Release, **886 aprovados, zero falhas, quatro skips em 890 casos**, incluindo os 28 novos casos de transporte, conferidos nos dois TRX. Artefatos C# conferidos por tamanho e SHA-256 publicado pelo GitHub. Contratos PowerShell **42/42** em PS7 e **42/42** em Windows PowerShell 5.1; ambiente **4/4**. O job de instalação, inspeção, reinício e desinstalação passou em Windows descartável, assim como os controles existentes de interrupção/cancelamento e volume cheio. Esse CI não carrega o driver M2 nem homologa sua integração nativa.

Functional web: **três jobs reprovados**. `migration` falhou por ausência do bean `EmpresaRepository`; `agent-contract` passou seus testes C# (886/890, quatro skips) e falhou ao aguardar o backend; `installed-service` informou que o backend encerrou antes de iniciar. Logs desta execução preservados, sem alteração em backend.

## Limites e próximas entregas

- Não há registro deste cliente no serviço, pipe ou UI; leitores e structs legados permanecem intactos. Esta entrega não resolve a incompatibilidade da composição atual do serviço com o driver M2.
- O perfil é fixado no contrato de referência, sem negociação de capacidades. Versão 18 isolada não comprova compatibilidade; a composição staged e suas extensões continuam em #46.
- O envio continua síncrono, com as características existentes de vida útil/espera da porta; não foi acrescentado cancelamento ou timeout nativo.
- Não houve driver real, teste de enforcement, novo pacote de distribuição ou homologação em VM. O pacote 0.1.14 anteriormente homologado não é um rebuild desta fonte.
- #46 permanece aberta para selecionar e qualificar um par exato agente/driver, revisar capacidades/composição e integrar o serviço. #44/#47 continuam dependentes do contrato de API da equipe. Não foi aberto listener no agente.

## Aceite desta atividade

- [x] Transporte C# explícito com capacidades exatas e somente três comandos de leitura.
- [x] Validação estrita, ausência de fallback e de resultado parcial em falha.
- [x] Preservação dos contratos legados e da composição do serviço.
- [x] Testes locais padrão e com flag; evidências locais preservadas.
- [x] CI do agente aprovado e evidências finais com hashes preservadas; falhas externas do Functional web registradas.

Nenhuma edição de Java, Angular, banco ou driver. Sem merge; PR #49 e #42 permanecem em rascunho.
