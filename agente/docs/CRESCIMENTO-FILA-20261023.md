# Diagnóstico do acúmulo da fila — 0.1.13

Atividade #54, parte de #43/#48, no PR #49 em rascunho. Fonte do agente `b749bc52f0dd77bfe18ca9a2ae2ed730e4dcfff9`; fonte final incluindo verificações do serviço instalado `008b4e36`. Somente agente e suas ferramentas/testes; nenhum Java, Angular, banco ou driver alterado.

## Comportamento entregue

A consulta administrativa existente `audit-integrity` passa a expor sete campos adicionais. Não há nova leitura automática nem alteração no arquivo, no envio ou na confirmação dos registros.

| Campo JSON | Significado |
| --- | --- |
| `queueBytes` | Tamanho lógico em bytes obtido do mesmo handle antes da varredura; não é espaço físico nem soma de temporários. |
| `pendingEvents` / `dispatchedEvents` | Linhas de evento válidas, separadas pelo estado local `dispatched`. |
| `pendingOverrides` / `dispatchedOverrides` | Linhas de justificativa válidas, separadas pelo mesmo marcador. |
| `oldestPendingUtc` | Menor data conhecida entre eventos e justificativas pendentes válidos, normalizada para UTC; null quando não existe data conhecida. |
| `pendingWithoutTimestamp` | Eventos pendentes aceitos pelo parser existente com data ausente/default. Não inventa idade para esses registros. |

Contagens são por linha, incluindo duplicatas, e não por ID único. Para registros válidos, pendentes + confirmados = total de seu tipo. Linhas inválidas, tipos futuros e linhas em branco continuam nas contagens já existentes, fora desse inventário de pendentes/confirmados. Justificativas sem data continuam inválidas pela regra anterior. Não muda aceitação do parser nem o significado de `requiresAttention`; a ausência de data pode exigir investigação mesmo sem esse indicador.

`dispatched` representa confirmação registrada localmente. O diagnóstico não consulta nem prova estado atual do servidor. Data vem do registro e pode sofrer relógio incorreto/futuro; não é tempo de espera monotônico nem SLA.

## Operação e limites

Administrador pode executar `agente/scripts/Get-SafeUploadDiagnostics.ps1 -Query audit-integrity`. O pipe continua restrito às mesmas identidades; resposta não acrescenta conteúdo, IDs, nomes de arquivo, caminhos, contas ou justificativas. Clientes antigos podem ignorar os campos adicionais. A interface do usuário não muda nesta entrega.

A varredura permanece explícita, O(tamanho da fila), sob o lock da mesma instância do processo. Os novos acumuladores são escalares; não retêm listas de pendentes nem acrescentam segunda leitura. Continuidade depende do limite existente de cinco segundos do serviço; uma fila grande pode excedê-lo e atrasar gravações. Cancelamento/falhas propagam sem publicar inventário parcial saudável. Outros processos não compartilham esse lock; alterações externas podem tornar tamanho e contagens de instantes diferentes. Ausência retorna arquivo inexistente e zeros, sem criar fila/diretório.

Para acompanhar crescimento, comparar amostras completas de `queueBytes` e pendentes ao longo do tempo. Reinício não zera essas métricas porque são lidas do arquivo. Não há limite/alerta automático, taxa calculada, retenção, compactação ou limpeza. Nenhum espaço livre mínimo é prometido para a próxima confirmação: sua cópia ainda pode crescer e depende do volume. #48 continua aberta para essas decisões e para operação prolongada.

## Validação

Local Release: **31 aprovados, zero falhas e zero skips**, incluindo três casos novos, regressões de integridade, confirmação em fluxo e temporários; TRX preservado. Verificados bytes UTF-8/Unicode, duplicatas, pendentes/confirmados, data UTC mais antiga de evento/justificativa, evento sem data, desconhecidos/inválidos, fila ausente/vazia, confirmação e reabertura. Pipe real sem driver confere campos camelCase e mantém erro sanitizado para arquivo ocupado. Testes existentes de cancelamento/leitura ocupada continuam aprovados.

PowerShell 7 e Windows PowerShell 5.1: **41/41 cada**; ambiente **4/4**. O teste de contratos inicialmente encontrou restrição de junction no sandbox; reexecutado fora dessa restrição com sucesso. A primeira tentativa de lote C# não iniciou por destino inexistente do log, corrigido antes da execução registrada. O teste instalado acrescenta conferências de tamanho e acúmulo antes/depois de linhas inválidas/futuras e após reinício. Sintaxe e argumentos das 59 chamadas Require conferidos; corrigida a separação de mensagem em três chamadas antes da fonte final.

[CI 40048369080](https://github.com/pedro-canafistula/safeupload/actions/runs/40048369080) aprovado nos três jobs, fonte limpa `008b4e367a1269bbc3b9d003e62bc1419ca0ef40`: **821 aprovados, zero falhas e quatro skips em 825**, tanto Debug como Release. Contratos PS7/PS5.1 41/41 cada e ambiente 4/4. Ensaios de interrupção e volume NTFS descartável cheio passaram novamente; não se presume interrupção de append ainda em andamento nem durabilidade em queda de energia.

Serviço instalado LocalSystem: inventário inicial **1.142 bytes / dois pendentes**. Após acrescentar uma linha inválida e um tipo futuro, **1.239 bytes / mesmos dois pendentes**; mais antiga `2026-10-24T01:10:29.860156+00:00`, sem pendentes sem data. Reinício conservou os valores; hash da fila preservado pela consulta. Instalação/inspeção/reinício/remoção passaram. É cenário sintético offline no runner, não homologação interativa do clone.

EXE **0.1.13**, **84.063.854 bytes**, 724 arquivos, self-contained, sem assinatura. SHA-256 **775A61F3BEF61BDDC84233551C343371AD9A6AAC7FC88453847B0D1ED7D8588D**; manifesto **950F2A7F6B1D7E5243F6B9CB4535B1B667ECAD40EBC87254976DA4296EE41797**. Artifact 12542177950, ZIP de 83.612.416 bytes, digest conferido com a API do GitHub; identidade completa no recibo. Instalador não executado no host. [Homologação própria do 0.1.13 no clone aprovada](HOMOLOGACAO-WIN10-0113-20261023.md): instalação/724 arquivos, campos novos confrontados com o arquivo, inspeções e atualização ao vivo, reconexão com a mesma UI, boot/login automático e remoção com painel aberto. Preservados 21 IDs e dez arquivos; inventário final de 11.820 bytes/21 pendentes. #54 concluída. Aceite offline específico deste pacote; não herda resultado anterior nem comprova API real.

[Functional web 40048373715](https://github.com/pedro-canafistula/safeupload/actions/runs/40048373715) reprovado nos três jobs: migração sem bean EmpresaRepository; installed-service com backend encerrado antes de iniciar; agent-contract sem backend iniciado. C# de agent-contract passou com 821/825 e quatro skips. Logs completos fora do Git; trechos identificados preservados. Backend não alterado.

API real/autenticação/idempotência (#44/#47), par do driver (#46), retenção/compactação e dias de carga (#48) continuam separados. Não declarar a macro concluída, PR inteiramente verde ou integração ponta a ponta. PR #49/#42 continuam em rascunho, sem merge.

[Recibos e hashes](evidencias/crescimento-fila-20261023/resumo.json).
