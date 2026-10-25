# Preparação do coletor de operação prolongada — #48

25/10/2026. Fonte do coletor `52fc6497877993d3b5f17671bc0ee8ca28294fbf`, branch
`tarefa/consolidar-base-agente-windows`, PR #49. Somente ferramenta de ensaio e
documentação do agente; código de produção, formato da fila, retenção, HTTP,
serviço e instalador inalterados. Java, Angular, banco e driver preservados.

## Escopo corrigido e permanente

Por determinação explícita do usuário, o foco é exclusivamente o agente Windows
e suas integrações em qualquer contexto. Mudança para outra frente exige pedido
explícito; dependências de colegas são registradas, não implementadas por nós.
O desenho do painel introduzido indevidamente em d18d3284 foi retirado por reversão
dd8adf29, preservando histórico e todo o trabalho anterior. As seções correspondentes
na descrição do PR #49 e na #44 também devem ser retiradas, preservando o restante.
PR #42 permanece rascunho e intocado; nenhum merge autorizado.

## Lacuna e incremento entregue

O [inventário de retomada](RETOMADA-EVIDENCIAS-20261025.md) já propõe 72 horas, mas
perfil, orçamento e aceite operacional precisam ser acordados antes dessa execução.
O benchmark anterior de 50 mil eventos/120 s e os ensaios aprovados de append,
volume cheio e temporários SYSTEM continuam válidos nos seus limites, sem repetição.

Entregue [QueueSoakProbe](../tools/QueueSoakProbe/README.md), coletor independente
para diretório sintético novo. Perfil explícito controla três fases: offline sem
consumidor, recuperação sem produtor e carga com confirmações sintéticas. IDs,
instantes e demais metadados são regeneráveis por semente/índice; uma justificativa
a cada dez eventos. Não mantém o histórico inteiro esperado na memória.

O coletor registra amostras de memória/CPU/alocação/disco, atraso e intervalo real
entre coletas; operações têm latências e atraso de produção. Reabre o sink entre
fases sem escritor ativo, compara todas as linhas/metadados/estados de confirmação,
confere contagens de integridade e hash antes/depois da consulta. Memória e CPU
incluem gerador, logs e verificação, e não medem exclusivamente o serviço instalado.
O laço é sequencial; não mede concorrência, pipe ou aplicação da política.

Há limites de eventos/saída/espaço, validação do perfil e recusa de dados instalados,
UNC e ancestrais reparse. Checagens entre operações não constituem quota rígida;
um I/O pode ultrapassar um limite. Falha/limite/Ctrl+C gera incomplete, preserva a
pasta e nunca promove/apaga dados. Não há garantia de recibo íntegro diante de
Kill/queda durante sua própria escrita, nem proteção contra troca maliciosa de
caminho. Nenhuma automação ou execução de dias foi iniciada.

## Validação nova, local e limitada

Build Release do novo projeto aprovado, zero erros. Quatro avisos NU1900 porque
o serviço de vulnerabilidades NuGet não estava acessível; não houve atualização
ou instalação de componentes na VM. Dependências existentes do Core foram usadas.

| Fase do piloto | Eventos totais | Confirmados | Pendentes | Justificativas totais / confirmadas | Bytes da fila |
| --- | --- | --- | --- | --- | --- |
| Offline | 32 | 0 | 32 | 3 / 0 | 16.977 |
| Recuperação | 32 | 32 | 0 | 3 / 3 | 17.174 |
| Mista | 64 | 62 | 2 | 6 / 6 | 34.352 |

Perfil: dois segundos por fase, intervalo mínimo de escrita 50 ms, confirmação e
coleta 100 ms, lote 10, teto 200 eventos/8 MiB e mínimo 2 GiB livres. **Duração
medida 6,057133 s e 55 amostras**. Em cada fase, IDs/metadados/ordem/estados foram
conferidos e a consulta preservou o hash. Isso valida o funcionamento do coletor
nessa carga curta, não estabilidade por dias, vazão garantida ou orçamento de produção.

Três controles novos aprovados por Test-ProbeGuards.ps1:

- Limite de um evento: saída não zero, status incomplete, evento pendente mantido.
- Perfil com duração inválida: recusa antes de criar a pasta de saída.
- Caminho de dados instalado: recusa antes de criar subpasta ou abrir fila.

As exceções nos logs desses controles são recusas esperadas do coletor. Não são
falhas do produto nem ensaios de corrupção/energia. Os comandos para reproduzir
estão no README; totais efetivos variam com o agendamento, e não devem ser fixados
como oráculo do próximo piloto. O aceite é preservação/estados e limites corretos.

## Evidências e limites de aceite

[Manifesto e recibos brutos](evidencias/operacao-prolongada-piloto-20261025/resumo.json):
19 arquivos conferidos por tamanho/SHA-256, com atributos Git para preservar bytes.
Inclui perfil, amostras, operações, fila sintética, recibo final, recusas e recibo
incomplete. Nomes copiados recebem prefixos pilot-/budget-/guards-; referências
internas dos recibos originais mantêm os nomes da execução. O manifesto externo
descreve os nomes efetivamente preservados. Não há documentos ou dados de usuários.

Não foram repetidas suítes do produto nem homologações aprovadas. Commit do coletor
usa `[skip ci]` para evitar reexecução automática das suítes existentes, pois não
altera produção/workflows; esta ferramenta nova foi validada localmente, sem aceite
de CI. A falha de Functional web registrada em [temporários SYSTEM](TEMPORARIOS-SYSTEM-20261025.md)
continua aberta. Não se declara PR inteiro verde, backend corrigido ou API real validada.

Continuam pendentes: perfil/orçamento acordados e execução efetiva por dias;
interrupção nativa sem instrumentação; energia/durabilidade física; regras de
retenção/recuperação. Confirmações deste coletor não passam por servidor nem provam
recibo durável/deduplicação. #44/#47 dependem de contrato e ambiente reais da equipe;
#46 depende do par M2 identificado. Não se abriu listener 8426 ou alterou contrato.
Nenhuma VM foi ligada, nenhum pacote reinstalado e nenhum merge realizado.
