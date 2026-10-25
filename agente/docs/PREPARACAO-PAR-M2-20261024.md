# Preparação da coleta para homologação M2 — 24/10/2026

Atividade #62, continuidade de #61 e parte de #46/#43. Fonte do coletor `6288643e93372295f80d7e80d7b7c03efa2ff263`; configuração final de CI `02ae15d925edc76664f7948c8506d06758b52b5a` (apenas checagem adicional do exit code de PS7). Escopo: ferramenta PowerShell do lado do agente, sem alteração no driver ou nos componentes web.

## Disponibilidade do par

A API do GitHub ainda informa `feat/driver-m2` em `e0df8d1c1f889418a133d3ae66a87a6c76a7bd5f`. A consulta de releases retornou zero; a busca de execuções Actions para esse commit também retornou zero. A árvore Git dessa referência não contém `.sys`/`.cat`. Nos ZIPs locais examinados (`SafeUpload-VM-kit.zip`, `SafeUpload-candidata-m2-a2900ee5.zip`, `m2-a2900ee5-source.zip`) não foram encontrados esses binários; a busca nos arquivos locais de `outputs/` e `sources/` também não os encontrou. Isto não exclui pacote privado ou build externo da equipe, apenas delimita o material disponível nesta tarefa.

Não foi ligado clone, instalado/carregado driver ou iniciado o serviço com um par presumido. O histórico de outro par e o mesmo número de protocolo não substituem a identificação dos artefatos.

A sonda C# existente `SafeUpload.Minifilter.Probe/Program.cs` foi inspecionada: seu fluxo padrão conecta e envia uma política de teste. Ela não foi executada. O novo coletor consulta o serviço já conectado para manter esta coleta restrita aos diagnósticos.

## Ferramenta entregue

`agente/scripts/Test-SafeUploadM2Diagnostics.ps1` usa `Get-SafeUploadDiagnostics.ps1` para executar, nessa ordem, `m2-counters` e `m2-stage-streams` no pipe administrativo já existente. O serviço deve estar previamente conectado ao driver acordado. A ferramenta não instala/carrega driver, abre FilterPort, para serviço, muda política ou configura o Windows. É entregue no código-fonte, junto do módulo `support/SafeUpload.M2Diagnostics.psm1`; não foi incorporada ao payload do instalador nesta atividade.

Em PowerShell elevado, a partir de `agente/scripts`, executar:

```powershell
.\Test-SafeUploadM2Diagnostics.ps1 -OutputPath C:\Homologacao\m2-receipt.json
```

A pasta precisa existir e o arquivo deve ser novo. O coletor recusa sobrescrita antes da consulta e usa `CreateNew` na gravação para cobrir a corrida entre verificação e criação. Falha em qualquer consulta/validação não produz recibo de sucesso parcial no pipeline; erros de gravação não equivalem a homologação concluída. Sem OutputPath, o JSON é retornado no console. Os diagnósticos podem conter finais de caminhos; o canal exige elevação e mantém a ACL existente de administradores/SYSTEM.

O módulo valida perfil/commit de referência, protocolo, flags de qualificação falsas, ausência de atomicidade, tamanhos 296/304, versão do prefixo de contadores, `denyRecorded`, campos M2 de stage-lifetime e quatro campos finais de writer-state. Confere contagens/limite de 16 registros, total/truncamento, GUID, campos numéricos dos registros, geração uint64 e até 48 unidades WCHAR. Não recompõe todas as invariantes dos campos legados, semântica do estado interno ou causalidade temporal. Bits desconhecidos são permitidos dentro do intervalo uint32; WCHARs incluem NUL/surrogate, sem derivar fidelidade do texto de exibição.

PowerShell 7 usa BigInteger para certos inteiros vindos de JSON; 5.1 usa Decimal acima de Int64.MaxValue. Ambos são aceitos somente dentro do intervalo inteiro, sem converter strings, booleans ou ponto flutuante em números confiáveis. O teste de round-trip passa novamente pela validação após serializar o recibo.

Só após as duas respostas válidas é emitido `status=diagnostics-only-passed`. O recibo mantém **driverIdentityVerified=false, pairQualified=false, protectionVerified=false**, UTC da coleta, dados consultados e SHA-256 dos três arquivos do coletor/módulo/cliente. `referenceDriverCommit` descreve o contrato selecionado, não o binário carregado. O prazo configurável é o timeout de conexão do cliente existente, não um limite rígido para consulta nativa síncrona.

## Validação e aceite

Local: **9/9 em PS7 e 9/9 em PS5.1**. Casos cobrem ordem das consultas, emissão única, uint64 máximo/round-trip, arrays vazios, perfil/versão, layouts incompletos/legados, flags incorretas, contagens/truncamento, GUID/intervalos/WCHAR, falha na segunda consulta sem recibo parcial e sintaxe/elevação do wrapper. Transporte simulado: nenhum desses casos acessa driver ou pipe real. A gravação do wrapper elevado e o ensaio real ainda não foram executados na VM.

Os nove testes foram acrescentados ao job do agente nas duas versões PowerShell, além dos contratos existentes. Resultados finais e hashes ficam em `evidencias/preparacao-par-m2-20261024/`.

[CI final do agente 40148901756](https://github.com/pedro-canafistula/safeupload/actions/runs/40148901756), commit 02ae15d9: **três jobs aprovados**, contratos M2 **9/9 em PS7 e 9/9 em PS5.1**, contratos anteriores **43/43 em ambas as versões**, ambiente **4/4**. Regressão C# Debug e Release: **893 aprovados, zero falhas, quatro skips em 897 casos** por configuração; os sete casos de integração de serviço da entrega anterior foram novamente conferidos nos TRX. Artefatos C# verificados por tamanho/digest. Instalação/inspeção/reinício/desinstalação e controles existentes de interrupção/cancelamento e volume cheio aprovados em Windows descartável. O coletor não foi executado contra driver real nesse CI.

[Functional web 40148907061](https://github.com/pedro-canafistula/safeupload/actions/runs/40148907061): três jobs reprovados, com ausência de `EmpresaRepository` em migration, backend sem iniciar em agent-contract (C# passou) e backend encerrado antes de iniciar em installed-service. Logs desta execução preservados; nenhum componente dos colegas foi alterado. Horários UTC dos recibos em 25/10 correspondem à noite de 24/10 em São Paulo.

- [x] Busca de pacote correspondente registrada, sem presumir disponibilidade externa.
- [x] Coletor e validação local prontos, com limites explícitos.
- [x] CI do agente e recibos finais conferidos; falhas externas do fluxo web registradas.
- [ ] Par exato, identidade do driver carregado e ensaio real — continuam em #46.

## Dependência para executar o ensaio real

A equipe do driver precisa disponibilizar o pacote `.sys`/`.inf`/`.cat` correspondente ao commit e0df8d1c, ou indicar outro commit para revermos o contrato, com SHA-256 dos artefatos, arquitetura/build, instruções de assinatura/test mode e pré-requisitos de instalação/rollback. Depois disso, qualificar o par em clone isolado: identidade de artefatos e ambiente, composição compatível do agente, diagnóstico nativo, reconexão e testes de inspeção/enforcement separados. O coletor sozinho não comprova nenhum desses aceites.

PR #49/#42 permanecem em rascunho e sem merge. #44/#47 continuam dependentes de contratos de API. Nenhum Java, Angular, banco ou driver editado; nenhuma nova homologação do pacote 0.1.14 nesta atividade.
