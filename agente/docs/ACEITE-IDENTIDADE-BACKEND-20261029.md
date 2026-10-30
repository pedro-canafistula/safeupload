# Aceite do serviço com identidade e backend real — 29/10/2026

## Resultado a comprovar

O serviço Windows instalado como LocalSystem recupera o mesmo id_host após reinício, sem ID na linha de comando, e atualiza o host correto no Java/MySQL, sem criar hosts ou usuários novos.

O ensaio fica em runner Windows descartável. Não executar sobre instalação/estado existente: o script recusa esse cenário e exige GitHub-hosted Windows. A máquina de Lucas tem estado SafeUpload preexistente e não foi usada para esta instalação.

## Composição e cenário

- Serviço self-contained da fonte do PR, via SCM/LocalSystem, modo FileSystemWatcher e TLS desligado.
- Backend Java da mesma árvore, sem alteração, empacotado com skipTests. A fixture Java existente ainda tem falhas próprias; empacotamento não é aprovação desses testes.
- MySQL Community 8.4.13 Windows, ZIP oficial com SHA-256 conferido, banco novo e bind somente em loopback. Inicialização efêmera sem senha, restrita ao runner isolado; não é configuração de produção.
- Scripts SQL existentes 01/02/03; fuso SQL/JDBC/JVM São Paulo, como Docker/ClockConfig do projeto. A JVM recebe user.timezone explicitamente, pois o runner usa UTC. A idade do último heartbeat é conferida pelo relógio do banco. Event scheduler desligado no ensaio; não qualifica a rotina temporal de offline.
- Dois cadastros sintéticos explícitos: alvo e controle. Só esses preparos chamam synchronize.

Sequência de aceite:

1. Registrar IDs, contagens e timestamps dos dois hosts. Marcar ambos inativos com horário de referência.
2. Instalar/iniciar serviço com ID do alvo; conferir conta LocalSystem, heartbeat persistido no alvo, controle intacto e contagens iguais.
3. Conferir identidade persistida, servidor/ID, hash, proprietário SYSTEM e DACL protegida.
4. Parar serviço e backend. Retirar RegisteredHostId da linha de comando; manter AgentApi e URL.
5. Reiniciar serviço com backend offline; conferir novo processo, identidade intacta e ausência de mudança no banco.
6. Voltar o backend e conferir novo heartbeat no mesmo alvo, controle inalterado, contagens estáveis e bytes da identidade preservados.
7. Parar/remover apenas o serviço criado e encerrar somente os processos Java/MySQL pertencentes ao ensaio. Falha de limpeza reprova o aceite.

Cada verificação tem resultado próprio em result.json. Após os critérios passarem, encerrar esse recorte; não iniciar novas baterias genéricas. O script guarda somente logs sanitizados e snapshots sintéticos no artefato host-identity-backend.

## Referências e limites

O pacote MySQL está em https://cdn.mysql.com/Downloads/MySQL-8.4/mysql-8.4.13-winx64.zip . O hash foi comparado ao mesmo pacote oficial já usado no ensaio Java/MySQL anterior: E9CD98B1D23F122987B1AFCA26AD942EFEC5891481103D48AE3CDE237FA3EA54. [Inicialização Windows no manual oficial](https://dev.mysql.com/doc/refman/8.4/en/windows-initialize-data-directory.html).

Não é aceite de driver/minifiltro, bloqueio real de arquivo, interface, política central, autenticação de dispositivo, instalação pelo pacote final ou migração de banco antigo. A consulta de política ainda está ausente no backend atual; o ensaio não acrescenta uma rota fictícia para esconder essa lacuna. Não cria eventos de inspeção para alegar auditoria real.

O resultado da execução deve ser conferido no check Identidade do serviço com Java e MySQL para o HEAD exato. Roteiro implementado não equivale a teste aprovado. O backend e o schema permanecem os da main de referência.
