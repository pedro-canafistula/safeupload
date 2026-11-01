# Comunicação na tela do agente

A tela **Status** recebe do serviço o resultado da última tentativa de heartbeat, envio de auditoria e consulta de políticas. A atualização é amostrada a cada cinco segundos, sem novas chamadas de rede. O horário mostrado é o horário local do Windows, com data completa.

| Texto | Significado |
| --- | --- |
| Não configurado | O serviço foi iniciado sem central configurada. |
| Aguardando tentativa | Ainda não houve tentativa desta operação neste processo; auditoria sem lote pode permanecer assim. |
| Tentativa em andamento | O serviço está executando a operação. |
| Última tentativa confirmada | A operação foi aceita conforme o contrato do cliente; consultar a data e hora. Não significa conectividade contínua. |
| Falha na última tentativa | A última operação falhou; não informa por si só se o computador está sem rede. |
| Última tentativa cancelada | A operação foi cancelada pelo chamador. |
| Serviço indisponível | O aplicativo perdeu o canal local com o serviço; dados anteriores são removidos da tela. |
| Informação indisponível nesta versão do serviço | Mensagem recebida sem os novos campos, compatível com serviço anterior. |

O cartão de segurança continua baseado no estado do interceptador. Uma consulta de política com HTTP 404 pode coexistir com heartbeat confirmado e proteção local ativa. A tela não afirma que o backend persistiu uma linha, que uma política foi aplicada ao driver ou que a fila inteira foi entregue. A confirmação de auditoria corresponde ao lote enviado e ao recibo validado; a central pode ainda ter pendências próprias.

## Integração interna

`CommunicationStatusPublisher` lê `CommunicationHealth` e envia apenas estados fechados e horários. Não divulga URL, id_host, usuário, código HTTP, corpo de resposta ou exceção pelo canal acessível ao usuário comum. O diagnóstico administrativo conserva detalhes sanitizados e sua ACL existente.

O novo campo opcional `communication` pertence à mensagem `StatusNotification`; não altera o contrato HTTP do backend nem cria comandos. `NotificationHub` conserva o último estado, combina-o com atualizações do interceptador e suprime publicações iguais. Estado não entra no replay de eventos. A emissão passa pelo registro durável já existente; falha de registro suprime entrega e a próxima amostragem tenta novamente. Nenhuma mudança de esquema do registro é necessária: a emissão mantém o tipo Status.

Um aplicativo antigo ignora o campo adicional. O novo aplicativo aceita ausência do campo sem apresentar confirmação fictícia. Os dois binários devem ser atualizados para visualizar os três resultados. A tela não necessita elevação nem acesso ao pipe administrativo.

## Demonstração para Thiago

1. Abrir o aplicativo de bandeja da mesma compilação do serviço e selecionar Status. Para abrir diretamente a janela ao iniciar, executar `SafeUpload.Agent.App.exe --show`; sem essa opção o início continua pela bandeja.
2. Observar os três resultados e horários. Confirmar o heartbeat no banco usando o roteiro de integração; a tela sozinha não substitui essa consulta.
3. Parar somente o backend de teste. Após o próximo ciclo configurado do despachante e até cinco segundos de amostragem, mostrar falha e a última confirmação anterior. O cartão de proteção local conserva o estado informado pelo interceptador.
4. Retornar o backend. Esperar o próximo ciclo; mostrar nova confirmação de heartbeat. Auditoria só muda se houver lote; consulta de políticas pode continuar falhando enquanto a rota não estiver disponível.
5. Parar o serviço de teste: a tela deve exibir Serviço indisponível e limpar horários. Reiniciar: o canal reconecta e recebe o estado deste processo.

Essa demonstração não cria eventos nem instala driver. Qualquer arquivo sensível, bloqueio real ou teste com banco compartilhado exige o roteiro e o ambiente próprios. O ensaio de identidade/heartbeat já aprovado continua documentado em [ACEITE-IDENTIDADE-BACKEND-20261029.md](ACEITE-IDENTIDADE-BACKEND-20261029.md).
