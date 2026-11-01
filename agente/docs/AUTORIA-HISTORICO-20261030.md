# Autoria local dos novos eventos — 30/10/2026

## Resultado

O histórico passa a preferir o SID do dono capturado pelo serviço, em vez de depender só do nome exibido. Novo `AuditEvent.OwnerSid` é metadado local, persistido na fila/notificação, **excluído do DTO HTTP explícito**. Não cria credencial, autenticação do dispositivo ou campo novo na API Java.

Web: a ponte usa o SID e a conta qualificada do token do processo do navegador. Se não puder resolver o nome, preserva o SID como identificação exibida. A decisão e a inspeção TLS não mudam. Clipboard: o servidor reutiliza a identidade do processo conectado e a grava na auditoria; não confia em um SID informado na mensagem da interface. O núcleo de classificação/colagem permanece igual.

Novas alocações de transferência persistem `AuditAccountName` junto do SID, sessão e criação do processo já capturados para aquela alocação. O publisher leva essa atribuição aos eventos, sem afetar caminhos de inspeção/publicação. Falha em resolver a conta usa o próprio SID, sem fazer a alocação depender de uma consulta de domínio bem-sucedida. O manifesto rejeita atribuição sem a identidade correspondente. Transferências antigas, sem o marcador novo, mantêm o `UserName` original nos eventos: alterar esse campo para o mesmo ID poderia conflitar com o payload já aceito pelo servidor. Nenhuma migração retroativa ou mudança de protocolo do driver.

Para eventos com OwnerSid, o histórico exige correspondência com o SID autenticado, inclusive quando o nome é igual ao de outra conta. Não há fallback para nome ou compartilhamento do computador se o SID for diferente. A renomeação da conta e a indisponibilidade da tradução do SID não escondem seus eventos novos. Registros antigos sem SID conservam o critério anterior de conta qualificada e a exceção explícita do FileSystemWatcher; nomes legados sem domínio não são adivinhados. Não se afirma reatribuição dos eventos antigos ou dos caminhos de minifiltro legado não qualificados neste recorte.

## Identificação de clientes locais

Antes de interpretar o PID do pipe no computador atual, `SessionResolver` exige confirmação de transporte local. O retorno `ERROR_PIPE_LOCAL` (229) é o único resultado aceito; nome remoto ou qualquer outro erro nega a identidade. A chamada Unicode informa capacidade do buffer em bytes. Notificações e clipboard fecham a conexão se não houver identidade local. A consulta administrativa mantém sua DACL existente; não se adiciona uma negação geral ao grupo NETWORK, que também ocorre em alguns logons administrativos locais.

Referências primárias: [GetNamedPipeClientComputerNameW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-getnamedpipeclientcomputernamew), [GetNamedPipeClientProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid) e [ERROR_PIPE_LOCAL](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-). O transporte local real foi exercitado nos pipes de histórico/clipboard. Não houve ensaio SMB entre dois computadores.

## Aceite e validação

Critérios: identidade capturada no serviço, autorização por SID sem fallback permissivo, reabertura/reconexão, rejeição de marcador sem identidade, transporte local confirmado, metadados antigos mantidos e SID ausente do HTTP. Nenhuma alteração de Java/SQL/Angular, política central ou kernel.

Primeiro recorte local: 96 aprovados. Recorte ampliado: 151 aprovados e três falhas antigas na preparação de links simbólicos por privilégio ausente nesta conta; zero ignorados. Nova rejeição do marcador e clipboard: 14/14, acrescentando um caso distinto (união 152 aprovados + três falhas nativas preservadas). Testes de pipe real, produtor Web → fila → histórico, novo/antigo publisher e reabertura do manifesto, além de exclusão do SID no tráfego. O teste de transporte nega erros desconhecidos e resultados remotos, sem tentar operações de rede.

O CI inclui os grupos de allocator/publisher/journal e clipboard, além dos controles já existentes. Registrar o SHA aprovado e o resultado remoto antes de integrar. Testes de componente do publisher não qualificam o par do Vitor, o Word ou a autoridade de política exigida pelo driver.
