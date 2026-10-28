# Composição do heartbeat e da auditoria

Incremento de 28/10/2026 sobre o PR #64, fonte `9352bdfbf5273ba8bc8ca1fa56c5f5b4eacf96c0`, com backend de referência `d6605e4db8043d56e25e0e05adc075f797aa77c9`.

## Resultado

A composição reúne o heartbeat por `id_host` com a validação inequívoca dos recibos de auditoria do PR #63. Uma falha de heartbeat permite a tentativa de auditoria; recibos com contagens ausentes, duplicadas, não inteiras ou incompatíveis mantêm os registros pendentes. Depois de reabrir a fila, uma tentativa com recibo válido confirma os mesmos registros.

Somente o dispatcher, seus testes e a documentação foram alterados em relação ao #64. O formato da fila, o payload, as rotas e a identidade da auditoria permanecem os existentes. A auditoria continua identificada por endpointId; não converter esse campo automaticamente para id_host. Nenhum Java, Angular, banco, driver, instalador ou workflow foi alterado.

## Origem das alterações

| Fonte do PR #63 | Commit reaplicado nesta composição | Conteúdo |
| --- | --- | --- |
| `1881e31d535904f0019a5a4c2c12030c956b65f0` | `12aebfa8` | Validação dos recibos, testes e documentação |
| `1e98422459cb3fd6e8a0c9a6d30fb8afa7401cd6` | `3a6af101` | Remoção de import duplicado e registro histórico |

Os commits foram reaplicados com autoria e referência de origem preservadas. O workflow exclusivo de #63 não foi importado. A mensagem histórica do segundo commit contém skip ci; isso não concede aceite ou dispensa de checks para a composição. O commit final da composição não usa essa indicação.

Os PRs #63/#64 e suas branches remotas foram preservados. Esta é uma branch candidata local, `integracao/heartbeat-auditoria-20261028`, sem merge na main e sem publicação nesta etapa. #49 não foi incorporado.

## Validação local

Build Release das dependências e testes em Windows/.NET 10 concluído. **99 testes aprovados, zero falhas e zero skips**, nos grupos AgentApiClientTests, DispatcherReliabilityTests, DurableHttpPolicyStoreTests e RefreshingPolicyStoreTests. Evidência original: `composicao.trx` no pacote local de entrega.

Os testes existentes foram reutilizados. Um teste adicional cobre a interação da composição: heartbeat 503, resposta 200 de auditoria com contagem duplicada, bytes da fila preservados, reabertura com o evento e a justificativa ainda pendentes, recuperação do heartbeat e confirmação apenas com recibo válido. Confere o corpo `id_host`, a rota de heartbeat e o mesmo payload nas duas tentativas de auditoria; a política indisponível não impede esse fluxo.

Reabrir o armazenamento em teste não equivale a reiniciar o processo/serviço Windows. O teste não comprova persistência central ou deduplicação do servidor. Sem instalação, rede real, Java/banco, painel ou driver carregado.

Reprodução, na raiz do repositório, com dependências restauradas:

```powershell
dotnet test agente/SafeUpload.Agent.Tests -c Release --no-restore -m:1 -nr:false -p:UseSharedCompilation=false --filter "FullyQualifiedName~AgentApiClientTests|FullyQualifiedName~DispatcherReliabilityTests|FullyQualifiedName~DurableHttpPolicyStoreTests|FullyQualifiedName~RefreshingPolicyStoreTests" --logger "trx;LogFileName=composicao.trx"
```

## Teste conjunto com Thiago

1. Conferir URL, bancos/migração, id_host de teste e SHAs C#/Java. Usar o roteiro de heartbeat em INTEGRACAO-BACKEND-20261028.md. Escolher ambiente e fila de teste dedicados, sem apagar ou manipular a fila de uma instalação real.
2. Gerar um evento sintético pelo agente candidato e guardar seu eventId, endpointId, horário e metadados. Antes do envio, confirmar que está pendente. Se justificativa fizer parte do cenário, gerar e identificar também esse registro.
3. Enviar pelo dispatcher e conferir o recibo com ambas as contagens. Thiago consulta agent_audit_ingest em nova transação para conferir event_id, endpoint_id, occurred_at_utc e payload. Só então comparar com a confirmação local.
4. Em ambiente de teste controlado, simular resposta perdida após persistência: o agente deve manter pendente e reenviar o mesmo ID/conteúdo. Conferir que há uma única linha central para o evento. Não alterar IDs ou timestamps entre as tentativas.
5. Desconectar, gerar outro evento, reiniciar o serviço candidato e reconectar. Confirmar preservação do ID/horário e recebimento central. Esse reinício real continua pendente apesar do teste de reabertura local aprovado.
6. Conferir o evento no painel somente quando a API administrativa correspondente estiver disponível. Um recibo não comprova exibição web.

Consulta de referência para Thiago, apenas leitura e com ID do ensaio:

```sql
SELECT record_key, kind, event_id, endpoint_id, occurred_at_utc, received_at_utc, payload
FROM agent_audit_ingest
WHERE event_id = '<EVENT_ID_DO_ENSAIO>';
```

O pacote local contém um JSON sintético para conferir o contrato do endpoint em diagnóstico manual. Esse POST manual não percorre a fila/dispatcher e não substitui os passos de aceite do agente. Não contém conteúdo integral de arquivo, dado pessoal real ou credenciais. Não foi enviado a nenhum servidor.

## Situação e condição de encerramento

Preparação C# e verificação local da composição concluídas. O CI do #64 anteriormente publicado não constitui CI deste candidato; resultados anteriores de #63 também não o qualificam. Checks aplicáveis, revisão e teste real continuam necessários antes de merge.

Política consultável, identidade durável, autenticação de dispositivo e o par real do driver conservam seus contratos e aceites próprios. O utilitário portátil de heartbeat já entregue continua sendo de chamada única: não demonstra este dispatcher de auditoria nem um serviço instalado.

Encerrar este recorte após registrar os 99 testes e preservar a fonte/evidência. Próximo aceite: ensaio real da composição com Thiago. Se houver necessidade de diagnóstico adicional, aproveitar o mecanismo existente em #49 em recorte posterior, adaptando-o ao cliente AgentApi; não importar a consolidação inteira.
