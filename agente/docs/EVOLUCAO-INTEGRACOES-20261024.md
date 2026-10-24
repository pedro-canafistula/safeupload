# Revisão da main e avanço das integrações do agente — 24/10/2026

Atividade #59, parte de #46/#43, PR #49 em rascunho. Fonte C# `cc41f9dd5e07b6eacb0b7b908166fc1d1c457747`. Escopo exclusivo do agente: repositório remoto lido como referência, sem merge/rebase, edição de Java, Angular, banco ou driver. Arquivos sincronizados preservados. Nenhuma mensagem enviada à equipe.

## O que mudou no repositório

**A main não mudou**: GitHub compare e fetch remoto confirmaram `efe93cf75aa668f2870c0951b48b3ef2c6332226`, igual à base anterior; zero commits/arquivos novos desde ela. Os únicos PRs abertos encontrados foram #42 e #49, ambos nossos e mantidos em rascunho. Isso não prova o estado de um servidor externo nem ausência de trabalho não publicado.

| Frente | Referência conferida | Resultado para o agente |
| --- | --- | --- |
| Main/API | `efe93cf7` | Sem novo contrato de políticas para incorporar. `/agent/api/synchronize` e heartbeat seguem com identidade própria; publicação tenta POST no host em `8426/receive/politica`. Não abrir listener ou trocar URLs implicitamente. |
| Políticas de Luiz | `develop-luiz-avanco-telas`, `e8afeb4d` | Mesmo tip da inspeção anterior. A conclusão de GET com resposta fixa permanece; não confundir existência da rota com política publicada consumível. |
| Heartbeat histórico | `api-web-heartbeat`, `7766bb3c` | Mesmo tip anterior; não restaurar backend histórico. |
| Integração de contratos antiga | `feat/integracao-contratos-atuais`, `76d4904e` | Tip já é ancestral da main; não é uma entrega nova pendente de importação. |
| Driver M2 | `feat/driver-m2`, `e0df8d1c` | Avançou desde o cache `06bafa7d`; contém novo diagnóstico stage-streams e mudanças do lado C#. É material de preparação, não um par qualificado para esta base. |
| Branch antiga de integração M2 | `feat/agent-m2-integration`, `ebb3b534` | Não substituir nossa branch por ela nem presumir compatibilidade com o tip M2 atual. |

A inspeção anterior de políticas segue como contexto em [VERIFICACAO-ROTAS-POLITICA-20261021.md](VERIFICACAO-ROTAS-POLITICA-20261021.md). Main idêntica preserva essa conclusão; não perguntar novamente se a rota existe. #44/#47 continuam dependências da API real, identidade/autenticação, persistência e deduplicação.

## Novidade M2 aproveitada no C#

O comando somente de leitura **29**, adicionado em `366952de` e presente em `e0df8d1c`, descreve até 16 versões de stage. Preparado `StageStreamDiagnosticsContract.Decode`, sem transporte ou chamada automática no serviço. Layout fixado ao protocolo **18**: cabeçalho 16 bytes, registro 160 bytes, snapshot **2.576 bytes**, nome de até 48 unidades UTF-16. Referência nativa é o blob de Protocol.h registrado nos recibos, lido sem editá-lo.

O decodificador exige comprimento recebido e tamanho declarado exatos, versão 18 e Count até 16 e não maior que Total. Aloca por Count validado, nunca por Total. Campos são lidos explicitamente em little-endian, incluindo GUID Windows e geração de destino de 64 bits. NameChars define o comprimento: NUL embutido e surrogate truncado são preservados como unidades UTF-16; comprimento fora do buffer é recusado, sem truncar silenciosamente nem expor conteúdo na mensagem de erro. Bits desconhecidos de flags/seções permanecem brutos e não concedem permissão. Slots fora de Count não são interpretados.

Retorno bounded e somente de leitura informa truncamento quando Total excede Count. O snapshot nativo não é transacional: seus campos podem refletir instantes diferentes. **Não representa readiness, autorização ou proteção ativa.** Não foi adicionado comando ao FilterPort, pipe, script ou composição do serviço. A futura ligação de transporte depende do par exato e de capacidades compatíveis.

## Por que não incorporar a M2 inteira

Embora ambos usem versão 18, os diagnósticos existentes divergem: contadores atuais do agente **120 bytes**, M2 **296**; writer-state atual **288**, M2 **304**. A versão do protocolo sozinha não garante todos os layouts. Copiar a branch inteira ou trocar apenas o cabeçalho misturaria transporte, publicação staged, recuperação e diagnóstico sem aceite conjunto.

A M2 também corrigiu a recuperação de um stage cancelado quando o driver já liberou a versão. O arquivo correspondente não existe nesta base do serviço: não transplantar a alteração isoladamente, pois depende do ciclo de vida staged daquela frente. Relatos de testes/aceites na branch do driver pertencem aos pares lá registrados, não homologam nosso agente ou pacote.

## Validação e andamento

**47 testes locais aprovados**, zero falhas/skips, em Release padrão; **47/47** também com `SafeUploadAdmissionEvidence=true`. São vinte casos novos do contrato preparado e 27 regressões dos diagnósticos existentes. Fixtures independentes conferem offsets, GUID, capacidade máxima, Total extremo sem alocação por ele, UTF-16, bits futuros, tamanhos/versões/contagens/nomes malformados e preservação do buffer de entrada. Não há carregamento de driver ou conexão nativa nesses testes. O recorte com a flag não é suíte completa nem homologação do build staged.

[CI 40117002930](https://github.com/pedro-canafistula/safeupload/actions/runs/40117002930) da fonte exata aprovado nos três jobs. C# **858 aprovados, zero falhas e quatro skips em 862**, por configuração Debug/Release. Os vinte casos novos Passed foram conferidos nos dois TRX originais; ZIPs baixados verificados por tamanho/digest do GitHub. PS7/PS5.1 **42/42** cada, ambiente **4/4**, controles existentes de interrupção, volume cheio, cancelamento observado e instalação aprovados. A flag de admissão foi exercitada apenas no recorte local descrito acima, não na suíte CI completa.

[Functional web 40117008298](https://github.com/pedro-canafistula/safeupload/actions/runs/40117008298) reprovado nos três jobs: migração sem bean EmpresaRepository, installed-service com backend encerrado antes de iniciar, agent-contract com backend não iniciado (C# 858/862, quatro skips). Trechos dos logs preservados; backend não alterado e nenhum aceite de integração real. Não declarar PR inteiro aprovado.

#59 concluída no escopo de preparação do contrato C#. Nenhuma nova versão do instalador ou homologação de pacote no clone nesta entrega; o pacote 0.1.14 homologado anteriormente tem fonte/hash próprios e não transfere seu aceite a um rebuild com esse componente.

Próximos passos de integração, em ordem:

1. #46: acordar e qualificar o par exato, reconciliar layouts/capacidades e composição staged do lado C#; só depois ligar a consulta preparada e testar com o driver correspondente.
2. #44: quando a equipe publicar contrato consultável de política, reinspecionar a fonte e adaptar apenas o agente, mantendo cache e operação offline. Não implementar receptor HTTP presumido.
3. #47: executar auditoria contra a API real disponível, preservando identidade, IDs, recibos completos e reenvio; resolver backend/painel continua com os colegas.

Não há alteração nova na main que elimine hoje essas dependências. O avanço desta entrega é um componente C# delimitado e validado da integração M2. #43/#44/#46/#47 permanecem abertas; PR #42/#49 em rascunho e sem merge.

[Referências, comparação da main, TRX e hashes](evidencias/evolucao-integracoes-20261024/resumo.json).
