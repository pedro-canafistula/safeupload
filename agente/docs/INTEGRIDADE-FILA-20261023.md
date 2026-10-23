# Diagnóstico da fila local — candidato 0.1.8

A consulta administrativa `audit-integrity` percorre a fila atual sem modificá-la.
Permite localizar linhas que os leitores não conseguem consumir, sem interromper
a leitura dos registros válidos. Não altera JSONL, despacho, confirmação, retenção,
vereditos, permissões ou contratos HTTP. Não é reparo nem recuperação de eventos.

Em PowerShell elevado, com o serviço desta versão executando:

```powershell
.\agente\scripts\Get-SafeUploadDiagnostics.ps1 -Query audit-integrity |
    ConvertTo-Json -Depth 6
```

## Resposta e interpretação

- `fileExists`: arquivo presente; ausência não cria uma fila nova.
- `linesScanned`, `validEvents`, `validOverrides`, `blankLines`: contagens da
  varredura concluída. Eventos seguem a desserialização/ID do leitor existente;
  justificativas exigem ID, horário e identidade, como o leitor de justificativas.
  Registros já confirmados também entram nas contagens.
- `invalidLines`: JSON/campos incompatíveis, raiz não objeto, ID ausente/vazio ou
  justificativa incompleta. Motivos são códigos fixos, nunca mensagens de exceção.
- `unknownRecords`: objetos com `type` de texto diferente de `override`, separados
  de corrupção porque podem pertencer a um gravador mais novo.
- `requiresAttention`: há linhas inválidas ou tipos desconhecidos. Não certifica
  autenticidade, integridade criptográfica, semântica de todos os campos ou entrega.
- `issues`: até 20 pares `lineNumber` (base 1) e `reason`, na ordem do arquivo.
  `issuesTruncated` limita a amostra, sem limitar as contagens totais da varredura.

Repetir a consulta recalcula o estado do arquivo; não acumula a mesma linha como
falhas novas. A resposta não contém conteúdo, IDs de evento, trechos, nomes de
arquivo, contas, caminhos ou justificativas. Erro de I/O devolve falha sanitizada,
nunca um recibo saudável de leitura parcial.

## Limites operacionais

Consulta **sob demanda**, no pipe administrativo já existente e com a mesma DACL;
não é alerta automático nem novo contador de `audit-health`. Essa consulta antiga
continua retratando sucesso/falha das operações de I/O, não validação do JSON.
Nenhuma alteração foi feita no pipe de usuário ou na interface.

A varredura compartilha o lock da mesma instância de fila do serviço e pode atrasar
gravações; usa o prazo existente de cinco segundos do pipe, incluindo espera pelo
lock. Cancelamento/timeout encerra a consulta sem resposta de sucesso parcial.
Não executar repetidamente como polling frequente em filas grandes. A resposta
é limitada, mas a leitura ainda percorre o arquivo inteiro, alocando uma linha por
vez; não existe limite novo de tamanho por linha. Não há snapshot entre processos
externos escrevendo diretamente no arquivo nem detecção de toda corrupção de bytes.

Linhas inválidas e desconhecidas permanecem no arquivo. As regras anteriores de
confirmação/regravação continuam preservando seu texto, podendo normalizar o fim
de linha; somente a consulta é comprovadamente inalterada byte a byte. A escrita
posterior a uma cauda truncada continua inserindo um separador antes do registro
novo. Corrigir, remover ou migrar dados exige uma tarefa própria.

## Validação desta entrega

Dezesseis casos novos cobrem sequência válida/inválida/válida, byte a byte antes e
depois da consulta, justificativa, nove formas inválidas, tipo futuro, limite da
amostra, releitura, arquivo ausente/BOM/brancos, cancelamento, compartilhamento
recusado, confirmação/reabertura/append após truncamento e pipe real sem driver,
incluindo sanitização do erro de I/O.

Local: **35/35 Release** no recorte novo + saúde/justificativas/longevidade;
**62/62 Debug** com fila e diagnósticos do driver. Contratos PowerShell **39/39**
em PS7 e PS5.1; parser real PS5.1 aprovado para os scripts alterados. Uma checagem
inicial do comando de validação usou LASTEXITCODE após script PowerShell, embora
os 39 casos tivessem passado; foi corrigida para conferir o recibo, sem alterar
os testes ou a implementação.

O smoke do CI passa a consultar o serviço real LocalSystem: fila limpa, inserção
de linha truncada e tipo futuro sintéticos, duas ocorrências sem conteúdo sensível,
hash inalterado pela consulta e mesmos diagnósticos após reinício. Mantém os testes
anteriores e remoção preservando o arquivo. Restrição a runner Windows descartável
permanece; não foi instalado no host nem na VM nesta entrega.

CI completo e artefato 0.1.8 ainda precisam de conferência. A homologação Windows 10
anterior é do 0.1.7 e não se transfere automaticamente. #48 continua aberta para
queda de processo/energia, volume cheio real, operação por dias, durabilidade,
memória limitada e retenção. API e driver reais continuam dependências da equipe.
PR #49 e PR #42 permanecem em rascunho, sem merge; sem Java, Angular, banco ou driver.
