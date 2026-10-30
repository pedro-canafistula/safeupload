# Resultado do teste real entre agente e backend

Em 28/10/2026, a comunicação de heartbeat e auditoria funcionou entre a fonte candidata do agente e o backend Java atual, com persistência conferida em MySQL real. Os testes também demonstraram reenvio sem duplicação após desconexão e após perda da resposta posterior ao commit do Java. A integração completa do produto continua pendente de política, identidade/autenticação, painel e qualificação do serviço/driver.

## Fonte e ambiente

| Item | Referência |
| --- | --- |
| Agente e utilitário portátil | b9acbdb44bf16422507c47bff129e913a9631649 |
| Java e esquemas SQL | d6605e4db8043d56e25e0e05adc075f797aa77c9 |
| Java | Temurin 21.0.12.101, Spring Boot 3.3.4 |
| Banco | MySQL Community 8.4.13, processo isolado no Windows |
| Esquemas | app e acesso, criados do zero com 01_schema_acesso.sql e 02_schema_app.sql da referência Java |
| Acesso | Somente loopback; MySQL 13306 e Java 18081; proxy de resposta perdida em porta local temporária |
| Confirmação | HTTP/recibo e consultas SQL novas, sem mock do backend ou da persistência |

O MySQL foi obtido pelo CDN oficial, com checksum conferido contra a página da Oracle. Não foi instalado como serviço. O código Java, o SQL versionado, o painel e o driver não foram alterados. Somente a configuração de execução apontou para o banco descartável. O pacote Java foi gerado com skipTests depois de registrar a falha da suíte; isso não é uma aprovação dos testes Java.

O backend utiliza Clock em America/Sao_Paulo. O ensaio configurou MySQL/JDBC em UTC; a atualização relativa de visto_por_ultimo foi comprovada, mas o alinhamento de fusos e o job de inatividade de 11 minutos não foram qualificados. Na reunião, conferir NOW(), UTC_TIMESTAMP() e o fuso da sessão; não reutilizar o resultado como aceite de detecção temporal de offline. O agendador MySQL permaneceu desativado no ensaio.

## O que passou

| Verificação | Resultado observado | Utilidade para o projeto |
| --- | --- | --- |
| Backend sem alteração de fonte inicia com MySQL | Aplicação pronta e HTTP ativo | Distingue falha da fixture de teste de falha da aplicação real |
| Cadastro controlado | POST /agent/synchronize devolveu 201 e os dois IDs | Confirma o contrato de provisão explícita, sem autorizar cadastro automático |
| IDs distintos | Host alvo 2 e usuário de SO 3 | Evita que coincidência entre sequências oculte uso do identificador errado |
| Heartbeat e auditoria pelo agente | Saída 0; Heartbeat/Audit Success, ambos HTTP 200; fila pendente passou a zero | Comprova que o cliente e o dispatcher atuais interoperam com o Java |
| Host certo atualizado | Host 2 passou de ativo=0 para 1 e horário avançou; host 1 de controle permaneceu igual | Comprova identificação correta no heartbeat |
| Nenhum cadastro extra durante heartbeat | Dois hosts antes e depois | Heartbeat não reexecuta o cadastro |
| Auditoria no banco | Uma linha para o evento; endpointId sintético conferido | Confirma persistência central, além do recibo HTTP |
| Replay explícito | Mesmo evento, payload e horário; continuou uma linha | Confirma deduplicação da ingestão para reenvio idêntico |
| Backend indisponível | Saída 1; um pendente; bytes da fila preservados | Confirma que falha de rede não descarta a trilha local |
| Retomada em outro processo | Backend reiniciado, utilitário executado novamente; saída 0 e mesmo evento persistido | Confirma continuidade da fila de teste entre processos |
| Resposta perdida após commit real | Proxy recebeu 200 do Java, conexão com agente foi encerrada; banco já tinha uma linha e agente manteve um pendente | Reproduz a dúvida real entre envio realizado e confirmação recebida |
| Reenvio após resposta perdida | Saída 0; mesma linha e payload no banco | Confirma ausência de duplicação no cenário de falha mais importante |
| Contrato antigo recusado | id_usuario_so no heartbeat atual: 400; rota antiga /agent/api/heartbeat: 404 | Confirma a necessidade da adaptação de #64 |

São 13 verificações positivas registradas em real-integration-checks.json. Há três verificações de requisitos ainda não atendidos abaixo; não apresentar o resultado como suíte inteiramente verde.

No exemplo dos hosts, o alvo passou de 2000-01-01 00:00:00.000000/ativo=0 para 2026-10-28 20:21:37.255149/ativo=1. O controle manteve o valor anterior. Esses IDs e horários pertencem somente ao ambiente local criado para este teste; não reutilizar id_host=2 no ambiente do Thiago sem consulta.

## Pendências observadas em execução

| Item | Evidência | Encaminhamento |
| --- | --- | --- |
| Política consultável | GET /agent/policy?endpointId=synthetic e /agent/policies?id_host=2 retornaram 404 | Thiago/Luiz precisam fechar rota, JSON efetivo, versão e destino. O agente já tem refresh/cache, mas esse fluxo ainda não pode ser aceito |
| Host inexistente | POST /agent/heartbeat com id_host inexistente retornou 500 | Thiago deve tratar ausência com resposta de cliente apropriada, por exemplo 404. Não confundir esse erro com falha do transporte C# |
| Repetição segura do cadastro | Segundo POST de cadastro do mesmo host retornou 201 e produziu dois hosts com hostname ALVO | Acordar identidade/chave de idempotência; manter cadastro explícito e não repetir automaticamente após timeout |

Consultas administrativas verificadas: /api/endpoints, /api/auditoria e /api/painel retornaram 404. Isso qualifica essas rotas, não toda a interface Angular: o painel não foi aberto nem testado. Ingestão de auditoria funcional não comprova sua exibição para o administrador.

## Resultado da suíte Java existente

Maven test: sete testes, sete erros de inicialização do contexto e zero testes bem-sucedidos. A causa inicial é a ausência de EmpresaRepository na configuração isolada usada por AgentEventsIntakeTest, exigido pelo AgentController. Nenhuma correção foi aplicada a essa fixture.

A fixture também referencia ../../db/initdb/05_agent_audit_ingest.sql, que não consta da referência atual; a tabela está no script 02_schema_app.sql. Essa segunda inconsistência foi observada no código, mas não foi a causa alcançada pelos sete erros, pois a inicialização falhou antes. Thiago deve revisar a fixture sem perder a cobertura de persistência.

Empacotamento com skipTests: aprovado. Execução real Java/MySQL: os fluxos positivos acima passaram. Essas três informações têm significados diferentes e devem continuar separadas no PR/CI.

## Limites

- Não foi iniciado o serviço Windows instalado nem usado LocalSystem, UI local, minifiltro ou inspeção real de arquivo. O evento Blocked do utilitário é sintético.
- O banco foi criado do zero: não foi validada migração de um banco antigo do Thiago. Não apagar dados reais para reproduzir o ensaio.
- Teste em loopback não qualifica firewall, rede entre máquinas, HTTPS ou credencial individual de dispositivo. A API conferida usa permitAll.
- O restart demonstrado foi do backend e do processo de ensaio, com armazenamento local preservado; não equivale a restart de um serviço instalado ou da máquina Windows.
- Não foi qualificado o job temporal de offline, o vínculo entre endpointId de auditoria e id_host, a publicação/aplicação de política nem o painel.
- Java e MySQL temporários foram encerrados ao final; diretórios e evidências foram preservados. Nenhum banco ou serviço existente foi utilizado.

## Evidências

real-integration-evidence.json preserva respostas, saídas do utilitário, snapshots SQL, cenário de resposta perdida e confirmação do encerramento dos processos. real-integration-checks.json registra cada aceite separadamente. Logs originais e relatório Surefire foram preservados localmente; o pacote de reunião contém cópias de logs sanitizadas, sem a senha temporária gerada automaticamente pelo Spring.

O MySQL 8.4 LTS é a família declarada no Dockerfile do projeto. A execução deste teste foi Windows/ZIP, não o contêiner Ubuntu da equipe. Método de execução: [documentação oficial de MySQL para Windows](https://dev.mysql.com/doc/refman/8.4/en/windows-installation.html).
