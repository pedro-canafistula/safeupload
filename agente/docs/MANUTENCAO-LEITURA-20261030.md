# Manutenção local somente leitura — 30/10/2026

Três consultas explícitas no pipe administrativo existente, restrito a SYSTEM/Administradores. Não há rotina agendada nem alteração de fila, driver, rede, arquivos retidos ou permissões. Recorte seletivo da branch preservada do #49 (`9680383e`), adaptado à leitura por janela da main atual; não importa sua composição M2 antiga.

## Consultas

`audit-temporaries`: inventário de metadados de nomes exatamente `queue.jsonl.<GUID formato N>.tmp`, no diretório configurado da fila. Sem recursão ou leitura do conteúdo; até 10 mil entradas examinadas. Informa contagens, bytes, erros, links ignorados, limite e completude. Recusa travessia por ancestral que esteja marcado como reparse point. Nomes e conteúdo não saem no resultado. Nome compatível não prova propriedade nem abandono. Observação do diretório não é transação contra outros processos; contagens incompletas são limites inferiores.

`audit-temporary-classification`: classificação de conteúdo opcional e limitada, apenas Windows. Examina até 16 candidatos/10 mil entradas, no máximo 4 MiB por arquivo, 16 MiB totais e 64 KiB por linha. Abre cada candidato sem seguir o reparse point da folha, sem compartilhamento, apenas leitura; confere arquivo regular, link único e caminho final do handle. Arquivo em uso, indisponível, inseguro ou acima dos limites tem categoria própria. UTF-8 inválido, campos duplicados/desconhecidos e estruturas incompatíveis não são classificados como completos. Ausência de LF indica cauda sem término, sem atribuir causa.

A classificação mantém o bloqueio local da fila durante a consulta limitada, para não disputar seu temporário de confirmação. Pode atrasar gravações enquanto lê; é consulta explícita e cancelável, não monitor periódico. Esse bloqueio só coordena a mesma instância, não outros processos. O prazo de cinco segundos do servidor depende da observação do cancelamento pelas operações de E/S; não é garantia de latência física do disco.

Mesmo um candidato estruturalmente completo pode estar defasado, incompleto ou ter sido fabricado. `ownershipVerified`, `recoveryEligible`, `promotionSupported` e `deletionSupported` são sempre falsos. A fila publicada continua sendo a autoridade. Nenhum candidato substitui a fila ou é excluído.

`audit-retention-preview`: exige `occurredBeforeUtc` em ISO 8601 com UTC explícito, diferente da data padrão. Conta linhas válidas confirmadas cuja **ocorrência** é estritamente anterior ao corte. Inclui duplicatas, separa eventos/justificativas e eventos confirmados sem horário. Reutiliza a janela capturada da análise de integridade, liberando o bloqueio antes da varredura completa. Erro/cancelamento não retorna um inventário parcial como completo.

Não existe horário de confirmação persistido, nem avaliação de vínculos, requisitos de retenção, provas de entrega central ou autorização para apagar. Um evento contado pode ser referenciado por uma justificativa pendente. `previewOnly=true`, `deletionSupported=false`, `timestampBasis=record-occurrence-time`. Não é uma política de retenção.

## Uso

Como administrador, consultar o serviço:

```powershell
.\agente\scripts\Get-SafeUploadDiagnostics.ps1 -Query audit-temporaries
.\agente\scripts\Get-SafeUploadDiagnostics.ps1 -Query audit-temporary-classification
.\agente\scripts\Get-SafeUploadDiagnostics.ps1 -Query audit-retention-preview -OccurredBeforeUtc '2026-10-01T00:00:00Z'
```

Resultados não contêm conteúdo, nomes de candidatos, caminhos ou IDs. Falhas de armazenamento retornam apenas categorias sanitizadas. Ausência de fila/diretório não cria arquivo. Não executar exclusão manual apenas porque o diagnóstico encontrou um temporário.

## Critérios e validação

Aceite declarado antes dos testes: escopo/nome exatos, limites, estados incompletos explícitos, cancelamento, rejeição de links/acessos inseguros, arquivo publicado/candidatos preservados e funcionamento do pipe sem driver. Sem testes longos de carga.

Local: 67 aprovados, duas falhas de preparação de links simbólicos por privilégio ausente nesta conta, zero ignorados; TRX preservado. Controles cobrem conteúdo completo/conflitante, cauda, formato futuro, ACL negando leitura sem alteração de ACL, hardlink, limites, corte UTC/exclusivo e consulta real de pipe com erro sanitizado. Regressão de integridade/concor­rência continua ativa. Scripts analisados em PowerShell 7 e cliente em Windows PowerShell 5.1, sem erros de sintaxe.

O workflow de recibos exige as três classes e preserva os controles anteriores. O roteiro do serviço LocalSystem consulta as três operações antes/depois de reinício offline, exige estados somente leitura e fila preservada; o recorte unitário testa candidatos não vazios. Registrar o SHA e os checks remotos aprovados antes do merge. Não fecha a definição conjunta de retenção, recuperação ou distribuição assinada.
