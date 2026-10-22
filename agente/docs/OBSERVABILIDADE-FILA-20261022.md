# Falhas de auditoria observáveis — candidato 0.1.7

O serviço agora sinaliza falhas de acesso à fila antes que a camada de inspeção
aplique sua política de preservar o veredito. Fonte `39290c98609d154488d368dbf85b92f6744774e6`.
A implementação do arquivo JSONL, contratos HTTP, vereditos e retenção não mudaram.

## Comportamento

`MonitoredAuditSink` envolve a mesma instância de `LocalQueueAuditSink` no serviço.
Preserva `IAuditSink` e `IOverrideQueue`, inclusive a identidade qualificada nas
justificativas. Observa escrita de eventos/justificativas, leitura de histórico e
pendentes e confirmação de eventos/justificativas. A exceção original continua
para o chamador; a inspeção de arquivo conserva sua regra já existente de não
alterar o veredito quando não consegue auditar. Os canais que recebem esse sink
no serviço compartilham os mesmos contadores; consumidores que instanciam uma
fila diretamente fora dessa composição não ganham monitoramento automaticamente.

- Primeira falha de cada operação: log **Error / EventId 3101**.
- Falhas consecutivas da mesma operação incrementam o contador sem repetir o log.
- Sucesso posterior da própria operação: log **Warning / EventId 3102** e saída
  de degradação dessa operação. Uma leitura bem-sucedida não limpa falha de escrita.
- Falhas anteriores permanecem nos contadores. Retomada não significa que os
  eventos que falharam foram recuperados ou que uma escrita parcial foi revertida.
- Cancelamento solicitado pelo chamador é propagado sem marcar falha de disco.
  Cancelamento inesperado é sinalizado. Falha no provedor de log não substitui
  a exceção da fila nem faz uma operação já concluída falhar.

Os logs novos não recebem o objeto da exceção nem sua mensagem. Guardam operação,
classificação fixa e HRESULT numérico; o estado usa contadores e horários. Não
incluem conteúdo, trechos mascarados, nomes/caminhos de arquivos, contas ou
justificativas. Isso se aplica aos novos registros 3101/3102, não é uma auditoria
ou alteração de todos os logs preexistentes do agente.

## Consulta administrativa

O pipe administrativo existente `SafeUpload.Agent.Diagnostics` passa a iniciar
nos modos watcher e minifilter. A consulta `audit-health` não acessa o arquivo da
fila nem exige driver conectado. As consultas de driver continuam disponíveis
quando houver conexão, sem modificar o driver. A DACL existente foi preservada:
SYSTEM/Administradores e proprietário do processo, que é SYSTEM no serviço.
A consulta não foi adicionada ao pipe de usuários da interface.

No PowerShell elevado, a partir do repositório ou ferramenta de suporte:

```powershell
.\agente\scripts\Get-SafeUploadDiagnostics.ps1 -Query audit-health |
    ConvertTo-Json -Depth 6
```

Campos: `sinceUtc`, `degraded`, `failedWriteAttempts` e `operations`. Cada operação
mostra `failures`, `successes`, `lastFailureUtc`, `lastSuccessUtc`, `failureKind` e
`failureHResult`. `degraded=false` significa ausência de operação com última
observação falha; não é uma certificação de integridade de todo o arquivo.

O estado é **em memória, desde o início do serviço**. Reiniciar zera os contadores;
o log do Windows é independente da fila, sujeito à configuração e disponibilidade
do provedor/Windows. Falha simultânea desse log não altera a decisão: a consulta
em memória continua sendo o canal alternativo durante o processo ativo.

## Validação

- Local Release: **42/42** no recorte de saúde da fila, diagnóstico e longevidade.
- Local Debug: **138/138**, incluindo inspeção de arquivo/Web e HTTP.
- Contratos PowerShell **39/39** em PS7 e PS5.1; script de diagnóstico analisado
  pelo parser real do PS5.1. Nenhum serviço foi instalado no computador do usuário.
- Doze casos novos: fila real ocupada durante inspeção com veredito preservado;
  retomada sem reinserir o evento perdido; contadores/logs sem dados sensíveis;
  cancelamento; logger com falha; justificativas/identidade; falhas por operação;
  consulta real pelo pipe com driver desconectado.

CI do candidato: [39864662531](https://github.com/pedro-canafistula/safeupload/actions/runs/39864662531).
**CI aprovado nos três jobs:** 764 aprovados, zero falhas e quatro skips em 768
por configuração (Debug/Release); contratos PS7/PS5.1 39/39 e ambiente 4/4.
O smoke exclusivo do runner foi ampliado: instala como LocalSystem sem driver,
bloqueia o compartilhamento da fila existente, cria CPF sintético, consulta o
estado degradado, libera o arquivo, grava texto limpo e confere retomada e
contadores. Exige eventos 3101/3102 no Application log e valida que esses registros
não carregam caminho/CPF. Depois mantém os testes de reinício, recusa de
sobrescrita e remoção com dados preservados. Resultado final e evidências em
`evidencias/observabilidade-fila-20261022/`.
O recibo instalado confirmou `degraded: false → true → false`, com
`failedWriteAttempts: 0 → 1 → 1`, HRESULT -2147024864 (compartilhamento recusado)
e eventos 3101/3102 reais no Application log. O ZIP do artifact foi baixado e
seu SHA-256 confrontado com o digest informado pelo GitHub. Não foi instalado
na VM do usuário. O resumo de evidências contém os hashes dos recibos.

A classificação `disk_full` foi exercitada com HRESULT sintético, não com volume
real cheio. Não se alterou o espaço disponível do disco do usuário. Corrupção
silenciosa de linhas, queda de processo/energia, vários dias de operação e
retenção/compactação continuam pendentes em #48. O histórico anterior de teste
0.1.6 continua válido para aquele pacote; este 0.1.7 ainda exige homologação no
clone Windows 10. Não houve instalação desta versão na VM original ou no host.

O PR #49 permanece em rascunho e sem merge. Não foram editados Java, Angular,
banco ou driver.
