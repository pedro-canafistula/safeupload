# Núcleo do agente — consolidação independente — 31/10/2026

Reúne sobre a main 5219afb5 correlação entre operação e evento, privacidade dos novos campos livres, logs diretos do serviço e proteção da fila. Pacote de desenvolvimento 0.1.17; commit e hash continuam obrigatórios para identificar o binário.

## Comportamento

- Notificação usa o evento cuja escrita terminou para a operação. Chamada em cache gera outro evento; falha de fila não reutiliza um evento antigo.
- Novos campos livres usam os detectores existentes para omitir valores reconhecidos. Reenvio antigo preserva ID e conteúdo canônico, inclusive após resposta perdida. Novas transferências staged têm projeção versionada no journal.
- Logs diretos revisados do serviço conservam IDs/códigos sem exceção bruta/caminhos. Não há filtro global de runtime/framework/Windows.
- Fila nova e temporários nascem protegidos. Verifica pasta e arquivo aberto antes do I/O; recusa proprietário/ACL indevidos, reparse ou múltiplos nomes físicos. Não repara nem descarta fila insegura. Herança antiga somente de SYSTEM/Administradores continua aceita.

O construtor público do observador FSW conserva caminhos de máquina. Sobrecarga interna direciona arquivos às pastas das fixtures; não acrescenta sincronização de política, novos canais ou configuração de produção. A callback de recarga existente na main também usa o tratamento seguro de logs.

## Verificação

Workflows exigem testes de correlação, privacidade, logs e fila além da regressão anterior. O roteiro SYSTEM em dois processos exige agora criação, recuperação e confirmação de eventos/justificativas com ACL de produção. Ausência, skip ou falta de evidência reprova o roteiro. O ensaio do instalador permanece no runner Windows descartável, com reinício/preservação de dados.

Os 85 casos dos quatro grupos novos passaram no ensaio inicial desta consolidação. Na seleção de 172, 169 passaram e três testes antigos de staging falharam ao criar links simbólicos sem privilégio do Windows. Não remover esses testes; CI deve executar os grupos completos. Conferir checks do SHA exato antes de integrar; este documento não antecipa recibo SYSTEM ou do pacote.

## Integrações separadas

Não inclui ConsoleByIp, leitura atual/estado/cache da política candidata, configuração AgentApi/host do instalador candidato ou contrato novo de autenticação. Essas frentes conservam branches/evidências para reconciliação com os responsáveis. Backend, painel, kernel e bibliotecas Network não são modificados. Não altera ABI M2 nem qualifica par agente/driver, Office ou Windows adicionais.

O instalador mantém seus limites de instalação inicial, sem atualização/repair/rollback automática. ACL não autentica alteração histórica nem garante persistência contra perda de energia ou concorrência entre processos. Não declara agente final integrado ou produção pronta.
