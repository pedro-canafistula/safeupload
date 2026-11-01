# Identidade persistente por id_host — 29/10/2026

Decisão direta de Lucas: seguir id_host, como o backend atual. Este incremento conserva um cadastro existente; não implementa cadastro automático ou a proposta de upsert por endpointId do PDF.

## Uso no serviço

Para a integração escolhida, configurar CentroAdministracao:HeartbeatProtocol=AgentApi e BaseUrl do servidor terminada em /agent/.

No primeiro provisionamento, informar RegisteredHostId com o id_host confirmado no cadastro do backend. A inicialização grava o vínculo em %ProgramData%\SafeUpload\identity\host-registration.json. O serviço não consulta nem valida a existência desse ID no servidor ao gravá-lo; o operador precisa fornecê-lo corretamente.

Nos próximos reinícios, RegisteredHostId pode ser omitido. O serviço recupera o ID do arquivo e continua enviando somente {"id_host":...} no heartbeat. Manter o ID na configuração também funciona, desde que seja igual ao salvo.

A configuração de protocolo permanece explícita. O modo Legacy e a operação local são preservados por compatibilidade; não usam nem alteram esse arquivo. A seleção padrão distribuída não foi trocada, evitando quebrar instalações ainda sem identidade provisionada. Para esta integração, o modo a usar é AgentApi.

## Integridade do vínculo

O arquivo contém somente schemaVersion=1, serverBaseUrl normalizada e registeredHostId positivo. O vínculo distingue esquema HTTP/HTTPS, host, porta e caminho de contexto. Caixa do hostname e porta padrão são normalizadas; caixa do caminho é preservada. Trocar localhost por IP ou por outro nome exige revisão explícita, mesmo que se refira ao mesmo servidor físico.

A pasta dedicada e o arquivo exigem proprietário SYSTEM/Administrators e DACL protegida exata com acesso somente a SYSTEM e Administrators, reutilizando a política de ACL já usada no cache. O serviço SYSTEM é o contexto de produção. Não há reparo automático de permissões de uma identidade encontrada.

A primeira gravação usa temporário protegido, flush e rename sem sobrescrever. Em inicializações concorrentes, só se aceita o vínculo já gravado se servidor e ID forem iguais. Não se substitui identidade por parâmetro de configuração.

Arquivo inválido, grande, com campos repetidos/desconhecidos, ID conflitante, servidor diferente ou acesso negado exige revisão administrativa. O conteúdo e as exceções originais de I/O não são reproduzidos nas mensagens. Não se trata erro de leitura como ausência para cadastrar de novo.

No modo AgentApi, falhar ao recuperar ou persistir a identidade impede a inicialização configurada; não há fallback silencioso para Legacy, outro ID ou novo cadastro. Nenhuma fila/política é apagada. Sem rede, uma identidade local válida é recuperada sem chamada HTTP, permitindo seguir os mecanismos existentes de política em cache e fila.

## Reprovisionamento e limites

Este arquivo é um vínculo local protegido, não uma credencial ou prova de autenticação. Administradores continuam sendo confiáveis conforme a fronteira do projeto. Ele não atesta uma máquina clonada.

Recriar o banco no mesmo endereço pode reutilizar números de hosts. O agente não consegue detectar essa mudança apenas pelo id_host e URL; é necessária conferência administrativa. O backend ainda precisa definir repetição segura do cadastro e eventual identidade da instância do servidor.

Para trocar servidor/host, parar a composição em manutenção, preservar o arquivo antigo para recuperação e reprovisionar de forma controlada após conferir o cadastro. Não apagar a identidade para tentar corrigir erro de rede ou repetir synchronize após timeout.

endpointId continua sendo usado na auditoria pelo contrato existente; não é substituído por id_host neste incremento. O vínculo no painel/backend permanece uma integração separada.

## Validação

Testes do novo grupo RegisteredHostIdentityTests cobrem persistência, reabertura sem ID configurado, corpo de heartbeat recuperado, diferença de servidor/porta/contexto, ID conflitante, arquivo inválido/bloqueado, concorrência e recusa de pasta sem ACL adequada. Os testes lógicos usam a fronteira interna sem ACL, como a suíte do cache; o teste negativo usa o construtor de produção.

O teste adicional RegisteredHostIdentitySystemTests usa o construtor público em duas execuções SYSTEM separadas: primeiro provisiona e verifica proprietário/DACL; depois recupera sem ID fornecido e verifica preservação diante de outro servidor. O script Test-HostIdentitySystem.ps1 fica restrito ao runner descartável do GitHub Actions, usa tarefa temporária com nome único e a remove no finally. Ambas as fases precisam ter exatamente um caso Passed, sem skips.

A compilação local passou sem erros/avisos. O Windows local bloqueou a DLL dos testes por Controle de Aplicativos (0x800711C7) antes dos casos; nenhuma proteção foi alterada. Os resultados executáveis deste incremento devem ser conferidos no CI do HEAD, sem herdar o aceite de 0fa5bda0.

Os testes não iniciam o serviço instalado, driver, UI, cadastro ou banco reais. A qualificação da composição completa continua própria; o teste SYSTEM do arquivo não é uma nova homologação do agente instalado.
