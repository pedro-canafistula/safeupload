# Perfil proposto para operação prolongada da fila — #48

25/10/2026. Fonte `8cf74192df24c7cb1ec029f234c5c05df9ee7e65`, base
`a372e8f05b2bfa8e063492a6f0ee6889c9956dc1`, PR #49. **Planejamento estático:
zero segundos de carga executados nesta entrega, ambiente ainda não acordado.**
Somente agente e suas integrações; nenhum componente de produção ou de colegas alterado.

## Proposta concreta para revisão

[proposed-72h.json](../tools/QueueSoakProbe/proposed-72h.json) representa uma carga
sintética inicial modesta, para uma máquina Windows disponível e diretório local
descartável. Não inicia processos, instala agente, abre a fila real ou agenda tarefa.

| Item | Valor proposto |
| --- | --- |
| Fases | 24 h offline sem consumidor; 24 h de recuperação sem produtor; 24 h de produção com confirmações locais |
| Produção | Um evento a cada dez segundos, sem compensar atrasos com rajadas; justificativa a cada dez eventos |
| Consumo sintético | A cada minuto, até 1.000 eventos e 1.000 justificativas; só fases de recuperação e mista |
| Amostras | A cada minuto; atrasos e intervalos efetivos preservados |
| Teto de eventos | 20.000; atingir limite encerra com incomplete, preservando pendentes |
| Teto de saída | 128 MiB; checado entre operações, sem promessa de quota rígida |
| Espaço livre mínimo | 4 GiB ao iniciar e durante carga; atingir o limiar interrompe sem limpeza |
| Semente | safeupload-queue-soak-proposed-72h-v1 |

As 72 h são tempo solicitado dos laços de fase; preparação, I/O em curso,
verificações e fechamento podem alongar o tempo total. O total de eventos efetivo
depende de agendamento e custo da fila; reduzir vazão não transforma o ensaio em
falha de SLA sem acordo específico. Equipamento deve permanecer disponível e sem
suspensão automática durante a execução, por decisão do operador; não alteramos
configuração de energia, serviço, sistema ou VM para obter isso.

Este perfil é um subconjunto do roteiro conceitual de [retomada](RETOMADA-EVIDENCIAS-20261025.md).
O coletor atual não implementa resposta HTTP perdida/503, reinício de processo,
serviço instalado, mistura de destinos reais ou diagnósticos periódicos via pipe.
Reabre/verifica o sink apenas nas fronteiras de fase. Rodar este perfil no futuro
não concluirá automaticamente todos aqueles critérios nem a atividade #48.

## Compatibilidade calculada, não desempenho medido

[Test-SoakProfile.ps1](../tools/QueueSoakProbe/Test-SoakProfile.ps1) valida campos,
calcula limites sob hipóteses explícitas e confronta orçamentos/limites do analisador.
Não consulta espaço livre real nem inicia o gerador. O resultado foi
compatible-under-model-assumptions, mantendo autorização de execução e qualificação falsas.

Modelo v1: até 2.048 bytes por linha de evento, 1.024 por justificativa/operação,
2.048 por amostra e 2 MiB de reserva para metadados. Há uma operação extra por fase
para acomodar entrada no laço antes do prazo e execução após atraso. As margens por
linha excedem as linhas observadas no piloto fixo (513/241/404 caracteres para evento,
justificativa/amostra), mas **não são limites impostos ao serializer**. Rever o modelo
se mudar o payload, formato do trace ou implementação; hashes das fontes constam do recibo.

| Resultado do modelo | Valor |
| --- | --- |
| Eventos por fase produtora, limite calculado | 8.641 |
| Eventos totais / justificativas, limites calculados | 17.282 / 1.728 |
| Amostras / ciclos de confirmação, limites calculados | 4.323 / 2.882 |
| Fila sob as hipóteses | 37.163.008 bytes |
| Operações / amostras sob as hipóteses | 20.647.936 / 8.853.504 bytes |
| Saída com reserva de metadados | 68.761.600 bytes, abaixo de 128 MiB |
| Saída mais uma cópia temporária de fila | 105.924.608 bytes, sob as mesmas hipóteses |
| Limite de leitura por arquivo no analisador | 256 MiB; nenhum arquivo calculado excede |
| Drenagem nominal do backlog offline | Nove ciclos; até nove minutos de espera por ciclos, excluindo leitura/regravação e demais custos |

Ter capacidade nominal de consumo não garante recuperar backlog em nove minutos.
Operações lentas podem consumir toda uma fase. O orçamento é estimativa condicionada;
espaço livre mínimo é margem de parada, não reserva alocada. Começar com exatamente
4 GiB livres pode provocar parada após a primeira escrita; o operador precisa dispor
de espaço **além do limiar**, considerando saída, temporário e demais consumidores do disco.

**Regravação é um custo separado do tamanho final.** Um limite deliberadamente
folgado de duas regravações por ciclo, cada uma do tamanho máximo calculado, soma
214.207.578.112 bytes de destinos reescritos. Não é previsão de escrita física, espaço
simultâneo necessário ou medição de desgaste; vários ciclos não regravam nada ou usam
fila menor. Serve para deixar explícito que fila pequena não garante I/O acumulado
pequeno. CPU, latência, memória e custo real de disco só poderão ser medidos na execução.

## Oito controles novos aprovados

[Test-SoakProfileContracts.ps1](../tools/QueueSoakProbe/Test-SoakProfileContracts.ps1):
perfil proposto compatível; orçamento de eventos insuficiente; orçamento de saída
insuficiente; arquivo acima do limite do analisador; consumo nominal insuficiente;
duração inválida; campo desconhecido; recusa de sobrescrita de relatório. Rejeições
são resultados esperados dos controles, sem iniciar qualquer carga. Todos verificam
que o planejamento não concede autorização/qualificação. Perfil fonte permaneceu inalterado.

Comandos de reprodução em [QueueSoakProbe/README](../tools/QueueSoakProbe/README.md).
[Recibos, perfis sintéticos e manifesto](evidencias/perfil-prolongado-20261025/resumo.json):
18 arquivos conferidos por tamanho/SHA-256. source-profile.json preserva os bytes do
perfil revisado; os casos reserializam os mesmos campos com outra formatação e podem
ter hashes diferentes. Ao executar futuramente, conferir e registrar o arquivo exato
efetivamente usado, não presumir igualdade de hash entre cópias formatadas de modo diferente.

Somente os controles novos de cálculo foram executados, em PowerShell 7.6.5. Sem
repetição do piloto, suíte de produto, build C#, homologação ou instalação; nenhuma
VM foi ligada. Commits com skip ci evitam reexecutar suítes existentes; nenhum workflow
alterado e nenhum aceite de CI atribuído. A falha funcional anterior do backend permanece.

## Condições que ainda faltam para a execução

O usuário escolheu **outro Windows isolado**, em 25/10/2026. Não usar o computador
atual ou a VM homologada por inferência. Ainda falta identificar essa máquina e
diretório, disponibilidade contínua e orçamento de CPU/memória/disco; confirmar o
perfil acima ou registrar a alteração desejada. A escolha do tipo de ambiente não
prova sua disponibilidade nem autoriza instalar componentes. Identificar build,
perfil e hashes antes de iniciar; preservar os arquivos ao parar. Nenhum job ou
automação foi criado e a execução longa não está em andamento.

Critério futuro: duração efetiva e lacunas registradas, comparação de IDs/metadados/
estados em cada fronteira, recibo final coerente e análise independente, mantendo
separados pendentes e confirmados. Um recibo partial/incomplete ou erro do coletor
não conclui o aceite. Energia, escrita nativa sem instrumentação, API real, retenção
e recuperação de órfãos permanecem aceites próprios. PR #42 preservado, PR #49 em
rascunho e nenhuma autorização de merge.
