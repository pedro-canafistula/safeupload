# Classificação conservadora de temporários — 25/10/2026

Continuidade de #48/PR #49, base `02706e2b`. Escopo: agente C#, consulta
administrativa PowerShell e testes sintéticos; sem VM, driver ou API externa.

## Ciclo observado na fonte

`RewriteDispatchedAsync` cria `queue.jsonl.<GUID N>.tmp` na mesma pasta, com
CreateNew/FileShare.None; lê a fila publicada e escreve a cópia linha por linha,
alterando somente as confirmações selecionadas. FlushAsync e fechamento precedem
File.Move(overwrite:true). Cancelamento é conferido antes da publicação. O finally
remove o temporário ainda existente quando o processo consegue executar a limpeza;
Kill/queda podem impedir esse finally. A fila válida continua sendo a publicada.

Não há marcador durável de completude, versão da fila de origem, hash da cópia
original ou recibo de confirmação vinculado ao nome do temporário. Um arquivo
bem formado pode ser cópia antiga, subconjunto ou conteúdo fabricado; não demonstra
posse, abandono, confirmação do servidor ou substituição segura. Nem tamanho nem
mtime resolvem isso. **Um temporário aparentemente completo nunca ganha preferência
sobre uma fila válida.** Não foi implementada recuperação automática, inclusive
quando a fila publicada está ausente.

## Consulta explícita e estados

O inventário `audit-temporaries` permanece somente de metadados. A nova consulta
`audit-temporary-classification` lê candidatos sob demanda, no mesmo pipe
administrativo e lock da fila, sem depender de driver:

```powershell
.\agente\scripts\Get-SafeUploadDiagnostics.ps1 -Query audit-temporary-classification
```

Não roda no startup nem em timer. Usa o serviço já instalado quando solicitado;
esta entrega não instalou/ligou o serviço no host ou na VM. A opção foi validada
com transporte simulado nas duas versões PowerShell; testes C# usam pipe real
com nome isolado, sem driver, para sucesso e erro sanitizado. ACL/prazo do pipe
existentes não foram alterados.

| Contagem retornada | Critério observado | O que não permite inferir |
| --- | --- | --- |
| `inUseCandidates` | Abertura exclusiva recusada pelo Windows com sharing/lock violation | Não identifica processo, escritor ou abandono; até leitor pode impedir a consulta. |
| `unterminatedCandidates` | EOF antes de LF na última linha, dentro dos limites | Indício de cauda sem terminador, inclusive JSON íntegro sem LF; não prova causa da interrupção. |
| `structurallyCompleteCandidates` | Ao menos uma linha, todas terminadas, UTF-8 estrito e registros conhecidos desserializáveis com verificações mínimas | Não prova cópia integral/atualizada, identidade/recibo do servidor, ausência de IDs duplicados ou autorização para publicar. |
| `suspiciousCandidates` | Vazio, linha vazia, JSON inválido, UTF-8 inválido, propriedade repetida, registro desconhecido ou campos mínimos incompatíveis | Não declara malícia/corrupção; inclui formato legítimo futuro não suportado. |
| `unavailableCandidates` | Não foi possível consultar/abrir/ler/validar metadados; erro distinto de compartilhamento | Não é tratado como em uso, íntegro ou descartável. |
| `indeterminateCandidates` | Tamanho, orçamento agregado ou linha excede limite | Não presume parcial nem completo. |
| `unsafeCandidates` | Diretório, reparse, hardlink/múltiplos links ou identidade de handle divergente | Nenhuma leitura de conteúdo ou tentativa de reparar o vínculo. |

Só nomes exatos da fila + GUID N + `.tmp`, sem recursão. No máximo **10.000
entradas de diretório e 16 candidatos**, **4 MiB por arquivo, 16 MiB agregados**,
**64 KiB por linha**. Memória de leitura usa buffers fixos de 8/64 KiB e objetos
JSON limitados à linha; não retém conteúdo/IDs entre candidatos. BytesRead são
bytes lógicos entregues pelas leituras, não I/O físico. Limites são diagnósticos,
não novos limites de tamanho aceito pela fila.

Evento exige ID não vazio, data não padrão, usuário/host, listas não nulas,
tamanho não negativo, enums de canal/veredito reconhecidos e dispatched booleano.
Justificativa exige tipo conhecido, ID/data/usuário/host e texto não vazio;
dispatched, quando presente, deve ser booleano. Campos adicionais continuam
permitidos. Não há validação integral da semântica dos demais campos nem
comparação com IDs/contagens/bytes da fila publicada. Regras dos leitores e
confirmações existentes permanecem inalteradas.

O diagnóstico retorna apenas contagens, limites e flags; não expõe caminhos,
nomes, GUIDs de candidatos, eventos, trechos, justificativas ou exceções. Flags
**ownershipVerified, recoveryEligible, promotionSupported e deletionSupported
permanecem false em todos os casos**. Complete descreve a varredura, nunca um
arquivo elegível à recuperação; qualquer candidato gera RequiresAttention.
Limite, inacessibilidade, vínculo inseguro ou travessia bloqueada deixam Complete
false. Cancelamento propaga sem resultado parcial de sucesso e libera o lock.

## Abertura segura e concorrência

Implementação Windows usa CreateFileW com acesso somente de leitura,
ShareMode=None e OPEN_REPARSE_POINT. Confere atributos, tipo de arquivo, contagem
de links e caminho final do mesmo handle antes de ler. Reparse em ancestral é
recusado; resolução para caminho diferente também é recusada, cobrindo troca
de caminho antes de abrir. Sem fallback para abertura menos restritiva.

A exclusividade mantém afastados escritores/renomes por handles comuns enquanto
o candidato é observado; não certifica dono ou impede administrador/kernel
hostil, mapeamento prévio ou alteração entre candidatos. O inventário do diretório
não é snapshot transacional. O lock espera o próprio sink terminar uma confirmação;
`inUse` pode observar outro processo, não prova simultaneidade com seu próprio
rewrite. Abrir exclusivamente também pode fazer um acesso concorrente falhar.
Varredura é administrativa e explícita, sem tentativas repetidas/remoção.

O prazo existente do pipe é cooperativo; chamadas nativas síncronas podem não
obedecer a um prazo rígido, especialmente em filesystem remoto. Esta entrega
não promete SLA nem suportou automaticamente caminhos fora do contrato Windows.

## Aceite e evidências

- [x] Classificação sem escrita, exclusão, promoção ou alteração de configuração.
- [x] Cópia completa com confirmações conflitantes não substitui a fila válida.
- [x] Preservação de hashes de fila/candidatos; IDs/metadados/pendentes anteriores mantidos após reabertura, append e confirmação normais.
- [x] Em uso, sem LF, vazio, desconhecido, JSON/UTF-8 inválido, duplicatas de propriedades e limites têm estados conservadores distintos.
- [x] Testes de orçamento de 16 MiB, linha/tamanho/candidatos, cancelamento prévio, ausência e nomes fora do padrão.
- [x] Hardlink/diretório recusados; symlinks e ancestral reparse têm testes exigindo ambiente preparado.
- [x] Pipe real isolado sem driver e roteamento PowerShell sem campos indevidos.
- [x] Conferir CI da fonte final e recibos, incluindo os dois testes de symlink no runner preparado.

Local Release: **69 aprovados e duas falhas de privilégio em 71**, antes da
criação das fixtures symlink. Primeira etapa anterior à inclusão desses casos:
18/18 novos casos aprovados. Local Debug: **69/69** no recorte explicitamente
sem os dois casos symlink, não suíte completa. PowerShell 7 e 5.1: **44/44 em
cada**, incluindo novo contrato de despacho. Os dois testes que não puderam ser
montados localmente continuam obrigatórios no CI; não foram convertidos em skips.
Uma compilação inicial de teste falhou por inferência de lambda e foi corrigida
antes das execuções finais; log preservado. Nenhuma falha foi ocultada.

Fonte **`acaf3bd9bfdb7b39f2dde075ed8d8546a9278ab2`**.
[CI do agente 40204229092](https://github.com/pedro-canafistula/safeupload/actions/runs/40204229092):
**três jobs aprovados**, C# **918 aprovados, zero falhas e quatro ignorados em
922 por configuração Debug/Release**. Todos os **23 casos novos passaram em
ambas**, incluindo os dois symlinks. ZIPs C# conferidos por tamanho/digest antes
da extração e resultados novos conferidos nos TRX originais. Contratos PS7/PS5.1
**44/44 cada**, ambiente **4/4**, contratos M2 **9/9 cada**, controles/instalação
gerais existentes aprovados. Não há aceite novo da consulta em VM ou serviço
instalado LocalSystem: sua execução específica foi no Core/pipe isolado dos
testes, além do roteamento PowerShell simulado.

[Functional web 40204235168](https://github.com/pedro-canafistula/safeupload/actions/runs/40204235168)
reprovado: migration sem EmpresaRepository; installed-service com backend
encerrado antes de iniciar; agent-contract com backend que não iniciou. Trechos
dos logs e IDs dos jobs preservados, sem corrigir backend fora do escopo. Não
declarar integração ponta a ponta ou PR inteiro aprovado.

[Manifesto de evidências, TRX, contratos e registros administrativos](evidencias/classificacao-temporarios-20261025/resumo.json).
TRX de CI preservados como extraídos dos ZIPs; logs obtidos pelo conector são
texto decodificado com terminadores normalizados, não cópia binária do stream.
Os resultados locais com falha de privilégio permanecem ao lado dos resultados
do runner, sem substituição retroativa.

Reprodução: compilar `agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj`
em Debug/Release; executar filtro `FullyQualifiedName~QueueTemporaryClassificationTests`.
O recorte adicional usa AuditQueueTemporaryTests, QueueStreamingConfirmationTests,
QueueBoundedReadTests, AuditQueueIntegrityTests e AppendInterruptionRecoveryTests.
Requer Windows e privilégio para criar symlinks nos dois casos de reparse; manter
TRX/logs e exit codes, inclusive falhas. Contratos PowerShell:
`agente/installer/tests/Test-InstallerContracts.ps1 -ResultsPath <arquivo-novo>`
em PS7 e Windows PowerShell 5.1 (ExecutionPolicy Bypass apenas no processo de teste,
quando necessário). Nenhum ensaio requer serviço instalado, VM ou rede externa.

O checklist corrente da #48 foi atualizado: volume cheio e append **controlado**
concluídos, interrupção nativa sem instrumentação e energia/durabilidade abertas.
Os relatos históricos continuam preservados, mesmo quando descrevem pendência
que foi resolvida depois. Esta entrega não fecha #48: tratamento/recuperação de
órfãos, retenção, energia e operação por dias continuam separados.

Não houve ensaio de troca concorrente de caminhos/mapeamentos durante a consulta;
guardas de handle e testes de vínculos estáticos não constituem prova contra
administrador/kernel hostil. Tratamento de indisponibilidade é conservador,
mas ACL de leitura negada não foi provocada especificamente nos testes novos.

PR #42 preservado; nenhum Java, Angular, banco, driver, `sources/`, VM ou pacote
0.1.14 homologado alterado. Rebuild do CI terá identidade própria e não herda o
aceite do pacote da VM. Sem merge; dependências #44/#46/#47 não foram resolvidas
aqui. Nenhum workflow foi disparado manualmente; Functional web automático foi
registrado acima, sem alterar componentes da equipe.
