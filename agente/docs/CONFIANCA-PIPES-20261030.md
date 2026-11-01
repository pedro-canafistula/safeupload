# Interface confirma o serviço antes de trocar dados — 30/10/2026

## Comportamento

Os clientes de notificações, clipboard e justificativas confirmam o processo servidor antes de aceitar mensagens ou enviar dados. Um pipe com o nome correto, criado por outro processo, não é suficiente.

Os três clientes mantêm o destino local fixo `.`. O processo apontado pelo handle conectado deve ser o PID do serviço `SafeUploadAgent`, em estado Running e tipo own-process no Service Control Manager. Seu cadastro deve indicar LocalSystem e o executável exato no diretório `service` irmão da pasta `ui` instalada. O caminho é extraído apenas de um executável absoluto explicitamente entre aspas; argumentos ou comandos ambíguos não viram imagem. O estado/PID é reconferido após a leitura do cadastro, recusando reinício durante a validação. Usa somente SC_MANAGER_CONNECT e SERVICE_QUERY_STATUS/QUERY_CONFIG, sem acesso ao processo SYSTEM, escrita, depuração, mudança de ACL ou configuração.

Falha ou identidade divergente fecha a conexão. Notificações não marcam o agente conectado nem apresentam status antes da conferência. Clipboard não escreve o texto e conserva a regra atual de retorno nulo em falha; justificativa falha sem escrever a razão. Logs não ganham caminhos, conteúdo, identidade remota ou mensagens brutas do sistema.

O vínculo de confiança é com o serviço registrado por administrador e com o caminho instalado. Não é verificação Authenticode, autenticação do dispositivo/backend ou proteção contra um administrador que controle o SCM/instalação. A interface passa a exigir o serviço Windows registrado; um processo de depuração em console com o mesmo nome de pipe é recusado. Não há opção de produção para desativar essa conferência. Testes usam nomes exclusivos de pipe, sem alterar os nomes do agente instalado.

## Critérios e validação

Aceite definido antes do ensaio: nenhum byte de clipboard/justificativa enviado a servidor não comprovado, nenhum status vindo dele apresentado, recusa de PID/imagem/estado/tipo incorretos e funcionamento com serviço real sem privilégios administrativos efetivos.

Primeiro recorte local: 11 testes aprovados, zero falhas/ignorados. Dois servidores reais de pipe receberam EOF sem nenhum byte dos pedidos sintéticos; outro não conseguiu marcar conexão ou apresentar status. Oito combinações exigem estado/PID/tipo/imagem corretos. O recorte final acrescenta sete comandos cadastrados e cinco contas, mantendo esses controles. Build do probe C# Release sem avisos/erros. Nenhum serviço foi instalado neste computador para o ensaio.

O workflow de recibos inclui os testes e o instalador compila o utilitário de aceite. Em runners Windows descartáveis, o probe usa token derivado com o grupo Administradores apenas para negação e privilégios desabilitados (exceto travessia), afirma que não é SYSTEM nem administrador efetivo, conecta ao serviço real, verifica sua imagem, recusa uma imagem diferente e recebe status sem enviar conteúdo. Executado após inicialização/reinício offline do serviço e contra o executável do pacote instalado. Esse teste não equivale a login completo em outra conta nem qualifica toda a bandeja no Windows 10/11.

Registrar o SHA e os resultados remotos antes do merge. A consulta de metadados locais do SCM é síncrona: o cancelamento é conferido antes do envio, sem promessa de prazo físico de E/S do sistema operacional. Sem benchmark ou alteração no núcleo de clipboard/TLS/driver.

A primeira rodada do cenário LocalSystem não chegou a executar o probe: o workflow compilava o utilitário apenas no cenário de contrato, e o arquivo faltava no cenário instalado. Falha e artefato preservados. O preparo do cenário instalado agora compila o probe e o preflight exige o arquivo antes de criar banco/serviço. Não foi alterado o critério de confiança para contornar a falha.

O primeiro pacote também expôs acesso negado ao abrir diretamente o processo SYSTEM sob token sem Administradores. A implementação foi corrigida para usar a autoridade do SCM (PID Running/own-process + conta/executável cadastrados), que suporta a leitura por usuário comum, sem conceder mais direitos no processo ou na fila. A leitura de configuração refere-se ao cadastro e pode refletir uma alteração administrativa destinada ao próximo reinício; não é medição da imagem/hash atual em memória. O limite de confiança permanece o administrador que controla o SCM e a instalação. Evidências da primeira falha do pacote preservadas.

## Fontes primárias

- [GetNamedPipeServerProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid)
- [QueryServiceStatusEx e validade do PID nos estados do serviço](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
- [QueryServiceConfigW e limites da configuração cadastrada](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw)
- [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
