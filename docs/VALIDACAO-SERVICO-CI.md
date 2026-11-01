# Serviço Windows em runner descartável

O job `installed-service` do workflow `Functional web` valida a composição
do serviço em uma máquina Windows temporária hospedada pelo GitHub. Ele publica
o serviço .NET 10, inicia um backend Java com H2 em memória e instala somente o
serviço de modo usuário, com `Interception:Mode=FileSystemWatcher` e TLS desligado.

O roteiro de validação em `agente/scripts/Test-InstalledServiceCi.ps1`:

1. Recusa execução fora do runner Windows hospedado pelo GitHub, portas ocupadas
   ou instalação/pastas SafeUpload preexistentes.
2. Prepara a política com a ACL exata já exigida pelo produto e inicia o serviço
   sob `LocalSystem` pelo gerenciador de serviços do Windows.
3. Confere que o serviço recebeu a política Java e persistiu o cache com proprietário
   SYSTEM e DACL protegida. A ferramenta C# verifica o descritor completo pelo
   construtor de produção, sem opção de dispensar ACL.
4. Para o backend, reinicia o serviço e exige no log de aplicação a origem `disk`
   da política inicial. Confere que o cache não foi alterado durante a indisponibilidade.
5. Cria um arquivo sintético no escopo vigiado. Exige evento pendente, resultado
   `Blocked`, versão correta e ausência do CPF em claro no JSONL.
6. Reinicia o Java e confere o mesmo UUID na API administrativa e na trilha local,
   agora confirmada. Encerra somente os processos e o serviço criados pelo teste.

As evidências são publicadas no artefato `installed-service-diagnostics`, incluindo
`result.json`, descrições dos passos, logs do Windows, logs do Java, cache e fila.
O indicador de aprovação é `status: passed`; existência de um artefato, sozinha,
não confirma sucesso.

A origem da política no log (`Origem=disk`, `default` ou `memory`) é diagnóstico
operacional. Não registra conteúdo inspecionado nem altera a escolha da política.

O job mantém `SAFEUPLOAD_MACHINE_TESTS=0` para a suíte habitual. A instalação
deste serviço fica restrita à máquina descartável do job; o script não foi feito
para ser executado no computador de desenvolvimento. Não instala driver,
certificados nem regras de interceptação de rede. O gatilho FileSystemWatcher
observa um arquivo depois de sua criação e não comprova bloqueio em modo kernel.
A homologação do minifiltro e de aplicativos reais continua sendo uma etapa separada.
