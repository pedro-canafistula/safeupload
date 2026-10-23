# Volume cheio e retomada da fila — 23/10/2026

**Aprovado no CI e no clone Windows 10**, com erro real de disco cheio e retomada nas quatro operações. Atividade #52, parte de #43/#48, no PR #49 em rascunho. Mudanças apenas em ferramenta, testes, CI e documentação do agente; nenhum código de produção, Java, Angular, banco ou driver alterado nesta atividade.

## Escopo do ensaio

Ferramenta self-contained QueueFullVolumeProbe usa os componentes reais da fila e do monitor de auditoria, em processo administrativo isolado, não como serviço SCM/SYSTEM. Cada uma das quatro operações usa fila sintética própria com três eventos e uma justificativa: gravação de evento, gravação de justificativa, confirmação de eventos e confirmação de justificativas. A ferramenta preenche um NTFS descartável de 64 MiB com bytes efetivamente escritos até obter erro real de disco cheio; não simula exceção. Relatórios ficam fora do volume.

Guardas recusam host comum antes de criar arquivos/volumes, disco de sistema, caminhos redirecionados, geometria inadequada, GUID/marcador divergentes e imagem externa. No clone, UUID e pasta são fixos; no CI, exige runner GitHub-hosted e repositório esperado. O disco físico selecionado é exclusivamente o derivado da imagem recém-criada e conferida. Sem comando clean, sem limpeza de fila ou temporários. Libera apenas o filler da própria fase; desmonta a imagem em finally e retém VHD localmente, fora de artifacts/Git. Não é defesa contra troca hostil concorrente de caminhos.

## Primeira rodada

Fonte limpa 3697d1513fd59e7af286d16b0b5f81bdc94535a6, [CI 40013019968](https://github.com/pedro-canafistula/safeupload/actions/runs/40013019968): três jobs aprovados; C# Debug/Release 812 aprovados, zero falhas e quatro skips em 816 cada. Contratos PowerShell e ambiente aprovados, incluindo ensaio real de volume cheio no PowerShell 7.

Quatro fases aprovadas, todas com zero bytes disponíveis e HRESULT -2147024784 (ERROR_DISK_FULL/112). Monitor registrou disk_full, degradação e retomada após liberar espaço, conservando contador de falhas. Prefixo original preservado; confirmação falha manteve bytes publicados idênticos. Reabertura conferiu IDs/metadados. Nenhum registro tentado nos appends falhos apareceu como registro completo nessa rodada; o contrato não pressupõe que toda falha de append deixe registro ausente.

Artifact fila-volume-cheio 12527990017: ZIP 37.638.048 bytes, SHA-256 129A54C1E7CDEAFBE82587026CA9B2F3957E9F3C96611F03E42EB843D134BF80 conferido localmente. Ferramenta 89.514.791 bytes, SHA-256 5A68A8E049ACB2E2008D2623DBF6D0B59E46EA1AC6808617D6DAF2016B276361; três arquivos de publicação conferidos também no clone.

Primeira tentativa no clone Windows 10/PS5.1: roteiro retornou failed/DiskPart falhou antes do probe, embora o log registre criação e montagem bem-sucedidas. Imagem desmontada pelo finally; recibos e imagem retidos, sem sobrescrever a tentativa. Não é aceite do teste no clone. Substituída a captura de processos de Start-Process/PassThru por Process com handle controlado até ExitCode e leitura assíncrona de stdout/stderr; códigos DiskPart agora registrados. CI passa a executar o wrapper no PowerShell 5.1. Teste pequeno de captura com saída 7 e stdout/stderr conhecidos passou tanto no host PS5.1.26100.9711 quanto no clone PS5.1.19041.3803.

## Validações locais

Guardas C# Debug 11/11; guardas/monitor/leitura limitada Release 38/38. Contratos PowerShell 7/5.1 41/41 cada, ambiente 4/4; parser PS5.1 e recusa do host comum conferidos. Nenhum volume foi montado/preenchido nem instalador executado no host. Não houve nova execução da suíte completa no host nesta atividade; os resultados completos dos demais ciclos permanecem nos respectivos relatórios.

## Limites e dependências

Saúde operacional retomada não significa reparo de cauda inválida nem recuperação automática da tentativa de append perdida. Confirmações continuam regravando o arquivo inteiro; retenção/compactação, dias de operação, energia e persistência física continuam pendentes em #48. Sem API/driver/disco de sistema cheio/serviço instalado ou pipe neste probe. A homologação do instalador 0.1.11 pertence ao EXE SHA 66BA476103B5F9F32FAB0126F979CE60B1F85A04172EDA5BAA6C4494F951C671, fonte 42e34afd; rebuilds de CI desta atividade não herdam esse aceite. #44/#47 dependem da API/autenticação/idempotência; #46 do par exato do driver.

[Functional web 40013024926](https://github.com/pedro-canafistula/safeupload/actions/runs/40013024926) reprovado: migration sem EmpresaRepository, contrato sem backend iniciado e installed-service sem inicialização do backend. C# do agent-contract passou (812/816, quatro skips). PR não está inteiramente verde; backend não alterado.

## Retomada aprovada no PowerShell 5.1 e no clone

Fonte limpa **8689572dc1b60cf3da3ed7e2783ef8d65a424949**, [CI 40014416126](https://github.com/pedro-canafistula/safeupload/actions/runs/40014416126): três jobs aprovados. C# **812 aprovados, zero falhas, quatro skips em 816**, Debug e Release, sem filtros. Contratos PS7/PS5.1 **41/41** cada; ambiente **4/4**. Ensaios de interrupção existentes, geração estática e smoke instalado também aprovados; sem atribuir ao rebuild o aceite do EXE homologado anteriormente.

Wrapper executado no **Windows PowerShell 5.1** do runner: quatro fases aprovadas, códigos de criação/particionamento/probe iguais a zero, desmontagem conferida. Artifact 12528305955, ZIP **37.637.989 bytes**, digest **DDF57FFB81287C4686F21287100C52A9E2A5BF5FDED52F6957A54C30293EAD7F** conferido. Ferramenta **89.514.791 bytes**, SHA-256 **C4A77B513765826A11D3BBB801D2E33AAEE6DFEDF80798B0DA8717A82DADBB74**. Mesmo binário e três arquivos de publicação conferidos no clone; wrapper e orquestrador comparados por hashes e parser PS5.1.

Clone isolado UUID 3a9992db-4644-405c-b642-9766edd10650, Windows 10 Pro 22H2/19045, PowerShell 5.1.19041.3803, .NET 10.0.13 self-contained. Processo administrativo, **isSystem=false**, sem serviço/UI do agente instalado, NICs/pastas compartilhadas ausentes. Usuário confirmou UAC. Não houve instalador, configuração de rede/API ou driver nesta rodada. Um pedido anterior de elevação expirou antes de iniciar o roteiro; ausência de recibo/processo conferida antes do reenvio.

| Operação | Falha real | Retomada | Fila original após falha |
| --- | --- | --- | --- |
| WriteEvent | disk_full / 112, livre 0 B | aprovada | prefixo e hash preservados |
| WriteOverride | disk_full / 112, livre 0 B | aprovada | prefixo e hash preservados |
| ConfirmEvents | disk_full / 112, livre 0 B | aprovada | bytes publicados idênticos |
| ConfirmOverrides | disk_full / 112, livre 0 B | aprovada | bytes publicados idênticos |

Cada fase reteve uma falha no contador, saiu de degradada após sucesso e registrou 3101/3102 sem exceção anexada/conteúdo de documento. Reabertura conferiu IDs/metadados; zero linhas inválidas/desconhecidas após falha e retomada, sem candidatos temporários nessas quatro filas. Nessa execução o append falho não deixou registro completo e o hash permaneceu igual; não generalizar isso para qualquer estágio de escrita.

Política, fila anterior com **17 IDs** e arquivos de quarentena/temporários preservados: **oito hashes idênticos** antes/depois, mais junction com mesmo tipo/destino. Fila anterior **9.514 bytes**, SHA-256 **64A3D85FD9B5091B11D88D6D32614D7EB2F7898686F01D9AC1F5B28947C8BA6A**. Discos virtuais de ambas as tentativas retidos e **desmontados**. Conferência final independente em usuário comum confirmou ausência da letra P, pasta instalada, serviço e UI; disco de apoio permaneceu com mais de 2 GiB livres. Clone desligado normalmente, original consultada/desligada, sessão com credencial descartada. Recibos originais copiados por bytes e comparados com inventário de hashes da VM.

[Functional web 40014423114](https://github.com/pedro-canafistula/safeupload/actions/runs/40014423114) permanece reprovado nos três jobs: migration sem EmpresaRepository, agent-contract sem backend iniciado e installed-service com backend encerrado antes de iniciar. C# desse contrato passou (812/816, quatro skips). Excertos e referência dos jobs preservados; nenhuma correção fora do escopo.

## Aceite desta atividade

- [x] Guardas de ambiente/identidade/volume e recusa do host comum.
- [x] Erro real nas quatro operações, preservação de dados e retomada observada.
- [x] Suite C#/PowerShell, CI com PS5.1 e clone Windows 10 conferidos.
- [x] Primeira falha, correção, hashes, recibos e desmontagem registrados.
- [x] Dados anteriores e junction preservados; VMs desligadas.

Atividade #52 concluída neste escopo; #43/#48 e dependências #44/#46/#47 continuam abertas. PR #49/#42 em rascunho, sem merge. Próximo trabalho de fila: reduzir custo de confirmações e definir retenção/compactação com aceite próprio; energia, append em andamento e operação prolongada exigem outros ensaios.

[Evidências e hashes](evidencias/volume-cheio-20261023/resumo.json). Sem VHD, executável, fila sintética grande ou conteúdo dos documentos no Git.
