# Clipboard: integração com auditoria

## Fluxo implementado

O `ClipboardService` usa a mesma `IAuditSink` do serviço de arquivos. Ao receber uma sonda de foco para um destino de saída com clipboard sinalizado, grava um `AuditEvent` local. O `HttpAgentDispatcher` existente envia esse evento ao Java; a API administrativa e o painel já aceitam o canal `Clipboard`.

A implementação atual do aplicativo envia sondas de foco, não confirma Ctrl+V nem aplica o bloqueio retornado. Por isso o evento usa `AllowedWithoutInspection` e `notInspectedReason = clipboard_focus_observed`, inclusive se a política sugerir `Block`. A interface apresenta “Observação de clipboard” e “Monitoramento”, com aviso de que não houve confirmação de colagem ou bloqueio. Não é adicionada uma nova opção ao enum do contrato HTTP.

Os resumos atuais incluem essas observações em `liberadosSemInspecao`; não contam como aprovação ou bloqueio. Um futuro resumo específico de monitoramento pode separá-las sem alterar o registro original.

## Dados e privacidade

- O estado da cópia conserva somente origem, categorias, tamanho e versão da política de classificação, além do identificador e sinalização existentes. Não conserva texto nem trechos detectados.
- A fila recebe categorias, origem, destino e identidade obtida do cliente do named pipe. Se a identidade não estiver disponível, registra “Não informado”, sem atribuir o usuário LocalSystem ao evento.
- `sizeBytes` representa o tamanho UTF-16 informado pelo protocolo: duas vezes o número de unidades de código. Para texto truncado usa o tamanho original declarado. Não é uma medição de tráfego de rede.
- `fileName`, `extension` e `maskedSnippets` ficam vazios. PID e duração indisponíveis usam zero para compatibilidade com o contrato atual; a interface apresenta “Não informado/a” para essas observações.
- A versão da política pertence à classificação guardada na cópia. As regras de destino usam a política consultada no momento da sonda.

## Comportamento operacional

Não são gravados eventos para copiar texto, canal desligado, cópia limpa, origem excluída, destino local, cópia substituída/desconhecida ou identificador de outra sessão. Cada nova observação de foco elegível recebe um UUID próprio. Reenvios HTTP da mesma linha mantêm o UUID e usam a deduplicação existente no backend.

O `EventId` só é retornado após a escrita local concluir. Falha de disco não muda a decisão do canal e gera log somente com o tipo da exceção; o evento que não pôde ser escrito não fica garantido para reenvio. Cancelamento solicitado é propagado. Quando o servidor está indisponível, eventos já gravados permanecem na fila para o dispatcher.

O modo padrão da política continua `Off`. A entrega conecta a auditoria, mas não ativa coleta nas máquinas nem instala agente/driver. Para homologação, publicar uma política de clipboard em `Audit` em ambiente de teste; o backend desta branch ainda publica política fixa em código. Não interpretar o resultado dos testes como validação de bloqueio real.

## Adaptação à main em 14/10/2026

O motor agora é `ClipboardInspectionService` no Core, mantendo cache de política, estado do canal e a regra global `AuditOnly`. `ClipboardObservation` entrega apenas metadados; `ClipboardAudit`, na camada de serviço, escreve a fila e devolve o `EventId` após sucesso. O pipe resolve a identidade do cliente. O ContractSmoke usa o mesmo motor e escritor, sem recriar a antiga classe `ClipboardService`.

Os resultados históricos abaixo não certificam a nova revisão. Consulte [integração da main](../integracao-main-20261014.md) para verificações locais e pendências da VM.

## Validação em 10/10/2026

- Suíte C#: 309 aprovados, 1 ignorado (autoridade certificadora da máquina), 0 falhas.
- Testes incluem privacidade, falha de escrita, cancelamento, limites de texto, isolamento por sessão e usuário identificado através de named pipe real.
- `ContractSmoke`: classificação e sonda pelo `ClipboardService`, fila real reaberta em disco, dispatcher HTTP, Java/H2, consultas administrativas e reenvio idempotente aprovados. O input é sintético e o modo Audit é aplicado somente à instância de teste; a política Java permanece Off.
- Resultado do smoke: três eventos File e uma observação Clipboard; um bloqueado, um aprovado e dois liberados sem inspeção, sem duplicação no reenvio.
- Build Angular e seis testes de detalhes no navegador aprovados, incluindo a distinção entre observação e colagem.

Não houve interação com clipboard de aplicativos reais nem carregamento de driver. A próxima homologação deve exercitar a aplicação WPF em uma VM com política Audit e conferir o mesmo UUID no endpoint e no painel.
