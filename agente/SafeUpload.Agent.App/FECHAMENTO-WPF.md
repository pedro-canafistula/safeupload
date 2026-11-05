# Fechamento funcional WPF — Agente 3 — 05/11/2026

Base: PR #95, `3c13b3e7b41bb7a66f276ca2a99eac2766dfde08`.
Branch própria: `fix/agente-wpf-fechamento-20261105`.
Guia dos agentes, Trilha e entregas #90–#95 consultados. Não foram incorporadas as branches novas dos Agentes 2 e 5.
O aceite nativo e o pipe comprovados no #95 permanecem referências dessa composição; este incremento é de apresentação.

## Problemas corrigidos

- Atividade, histórico e fila divergiam: publicação não confirmada podia aparecer como restrição; Approved com achados
  não destacava alerta; motivos de falha afirmavam “liberado sem inspeção”, inclusive para Blocked.
- A bandeja anunciava proteção ativa desde a criação. Estado legado sem cobertura preventiva informada podia ficar verde.
  Agora a proteção exige política conhecida e cobertura pronta informada; conexão com backend é apresentada separadamente.
  Alertar explica que falhas de inspeção ainda podem bloquear. Ao perder o pipe, a versão fica como última conhecida,
  sem afirmar aplicação atual.
- Havia vínculos XAML com `PolicyIntegration` e `AuditWrites`, inexistentes no ViewModel. Foram removidos;
  comunicação usa os campos reais do contrato e os eventos sem confirmação vêm do histórico autorizado recebido.
- Replays sem evento aninhado podiam repetir avisos. Repetições agora são limitadas por identidade/fase;
  uma fase posterior continua aparecendo. Histórico preserva EventId e confirmação já recebida: um replay antigo
  com `Dispatched=false` não desfaz `true`, nem cria novo aviso/entrada.
- Textos visíveis passam pela omissão de valores reconhecidos pelos detectores existentes, inclusive nomes, destinos,
  motivos e trechos legados. Janela inconclusiva não pede remover dados que não foram identificados.
  Detalhes longos têm rolagem; resultado e arquivo ficam legíveis antes dos demais metadados do histórico.

| Resultado informado | Exibição |
| --- | --- |
| Approved com hash de publicação | Publicado |
| Blocked com achados | Restrito, janela de bloqueio, versão retida quando informada pelo serviço |
| Approved com hash e categorias | Publicado com alerta; aviso não é de bloqueio |
| Blocked com erro de inspeção | Inconclusivo / bloqueado; motivo da falha, sem afirmar liberação |
| `publication_failed` | Pendente |
| `publication_outcome_unknown` | Não confirmado; nunca sucesso nem bloqueio confirmado da publicação |
| Approved sem evidência de publicação | Aprovação da inspeção, sem afirmar envio |
| Publicação autorizada após inspeção inconclusiva | Publicado com ressalva; falha original continua visível |

## Validação dirigida e limites

```powershell
dotnet build agente/SafeUpload.Agent.App -c Release
$env:SAFEUPLOAD_WPF_SNAPSHOTS = 'C:\Teste\wpf-render'
dotnet test agente/SafeUpload.Agent.App.Tests -c Release
dotnet test agente/SafeUpload.Agent.Tests -c Release --filter 'FullyQualifiedName~AuditHistoryTests|FullyQualifiedName~CommunicationPresentationTests|FullyQualifiedName~DriveOutcomeNotificationTests|FullyQualifiedName~NotificationProtocolTests|FullyQualifiedName~DriveProtectionStatusTests|FullyQualifiedName~AuditTrailTests|FullyQualifiedName~NewAuditMetadataTests'
```

Os testes novos usam o assembly real da aplicação, os contratos NDJSON existentes e janelas/recursos XAML em STA.
Geram seis PNGs: status com falha do backend e proteção local pronta, cobertura indisponível, histórico de resultados,
bloqueio com dados omitidos, inspeção inconclusiva e detalhes com rolagem. Detectam erros de binding.
O teste legado da indicação verde foi atualizado para exigir cobertura preventiva explícita, preservando o caso positivo.
Nesta entrega: 32 testes específicos da WPF e 90 testes relacionados existentes aprovados, sem falhas/ignorados.
WPF e projeto novo de testes compilados em Release sem erros/avisos. A compilação da suíte anterior conserva apenas
o CA2022 preexistente no teste de leitura da fila, fora deste recorte.

**Renderização em memória não é entrega visual pelo pipe ou comprovação do balão do Windows.** Nenhuma VM compartilhada,
serviço instalado, driver, backend, autenticação ou script compartilhado foi alterado/usado neste recorte.
O cliente mantém a validação do serviço instalado existente; não foi criado bypass para um pipe simulado.
Autorização por SID/sessão continua sendo responsabilidade do serviço: ViewModel não concede autorização.

**Limitação de contrato para o Agente 2/serviço:** o status informa resultados das últimas tentativas, não conexão contínua,
total global de eventos pendentes ou recibos individuais ao vivo. A UI mostra exatamente essa distinção.
O contador é dos eventos autorizados do último histórico/mensagens recebidas; pode estar defasado até nova mensagem/reconexão.
Não interpretar falha de backend como falha da proteção local, nem zero nesse recorte como fila global vazia.

## Roteiro visual final para o Agente 1 — até 07/11/2026

1. Coordenar uma sessão interativa isolada na VM de teste. Preservar serviço/gate/configuração/política/fila/identidade
   da composição #95. Publicar somente a aplicação desta branch (`dotnet publish agente/SafeUpload.Agent.App -c Release -r win-x64 --self-contained true`)
   e instalá-la no diretório `app` ao lado do diretório `service`, mantendo o layout de validação do pipe existente.
   Não substituir serviço ou gate por branches das frentes de HTTP/autenticação para este aceite.
2. Abrir a aplicação na sessão do usuário autorizado, com `--show`. Conferir política informada, proteção local e backend
   separadamente. Executar os cenários reais já usados no #95: arquivo limpo, CPF/Bloquear, CPF/Alertar e DOCX inválido.
   Registrar EventId, revisão, hash quando publicado e imagem da janela/balão/histórico; não incluir CPF em claro na captura.
   Limpo deve dizer concluído somente após publicação; Alertar mostra alerta; DOCX inválido permanece inconclusivo/bloqueado.
3. Fechar e reabrir a WPF, inclusive dentro da janela de replay, mantendo o serviço ativo. Conferir uma entrada por EventId
   e ausência de alertas antigos repetidos. Em outra conta/sessão de teste, conferir que eventos/histórico do primeiro usuário
   não aparecem. Não usar um pipe sem o serviço autenticado para declarar essa autorização comprovada.
4. Com o backend de teste fora do ar, conferir falha nas últimas tentativas e proteção local ainda pronta quando informada.
   Reabrir a WPF após reconexão e conferir o histórico/confirmados sem duplicação. O contador deve indicar seu alcance limitado.
   Em ambiente isolado preparado pelo Agente 1, conferir que gate/cobertura não prontos ou pipe desconectado não exibem proteção ativa.
5. Se houver registro genuíno de recuperação `publication_outcome_unknown`, conferir “Não confirmado” na atividade e no histórico.
   Para publicação pendente, usar um cenário de destino indisponível controlado pelo Agente 1. Não adulterar fila/recibos nem
   provocar interrupção perigosa apenas para fabricar esses estados; se não disponíveis, manter esses itens visualmente pendentes.

Registrar Windows/DPI, revisão do app e serviço, IDs e resultado de cada observação. Somente após esse roteiro declarar
janela/balão/isolamento visual qualificados na composição final. Office/USB/SMB e aceites das demais frentes não são reabertos.
