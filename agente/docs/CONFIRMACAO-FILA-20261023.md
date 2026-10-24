# Confirmação da fila em fluxo — candidato 0.1.12 — 23/10/2026

Atividade #53, parte de #43/#48, no PR #49 em rascunho. Fonte de produção `b49b1d960a6d0ab0bddb989a1d0574f66974441d`. Escopo: agente C#, testes e CI; sem Java, Angular, banco ou driver.

## Mudança e contrato

A confirmação antes acumulava a fila inteira num StringBuilder, criava outra string completa e só depois escrevia a cópia temporária. Agora lê, transforma e escreve uma linha por vez, com buffer de saída de 65.536 caracteres. Memória retida depende do lote, buffer e maior linha; não do texto completo da fila. Linhas individuais grandes continuam sem limite de bytes. A seleção de justificativas usa conjunto por igualdade de conteúdo do registro.

Mantidos o mesmo arquivo JSONL e estado dispatched, seleção de eventos por EventId, justificativas por conteúdo, duplicatas, metadados extras e linhas desconhecidas/inválidas. Como antes, regrava sem BOM e normaliza terminadores para Environment.NewLine. Nenhum registro é apagado por retenção. O semáforo continua por instância/processo; não acrescenta coordenação entre processos.

Cópia temporária na mesma pasta, criada como arquivo novo; original substituído somente após fechar streams e conferir cancelamento. Limpeza trata somente o temporário criado nesta execução, sem promover arquivos órfãos. Falha no meio deve deixar o original publicado intacto. Não acrescenta Flush(true), protocolo de energia ou garantia física de persistência.

## Medição sintética local

Mesmo QueueProbe, Release, .NET 10.0.13, Windows 26300, filas novas de 1 mil/10 mil/50 mil eventos, três confirmações de 100 por tamanho, cache aquecido. Fonte anterior `3d68abb3`; medições posteriores ocorreram antes do commit, com código de produção correspondente ao b49b1d96. Hash de cada DLL executada no recibo; esses binários locais não são o instalador do CI. Mediana de alocação global do processo por operação, não heap vivo ou escrita física.

| Eventos | Antes ms | Final ms | Antes MiB alocados | Final MiB alocados |
| --- | ---: | ---: | ---: | ---: |
| 1.000 | 16,43 | 15,88 | 3,77 | 2,08 |
| 10.000 | 51,61 | 31,57 | 32,03 | 12,62 |
| 50.000 | 171,77 | 127,77 | 157,88 | 59,49 |

Primeira implementação com buffer pequeno reduziu alocação, mas piorou a confirmação de 50 mil para 295,66 ms; resultado intermediário preservado. Com buffer maior essa regressão deixou de aparecer nesta medição. As rodadas não isolaram o agendamento/carga do host, incluindo testes independentes durante parte da execução; não é garantia de latência em outro volume/carga. Pico do processo completo: 254,39 MiB antes, 136,83 intermediário, 125,21 final; inclui geração, consultas e confirmações e não isola heap retido pela operação.

Todos os tamanhos reabriram com IDs únicos, contagem original e 300 eventos confirmados. Ensaio concorrente curto de ~10 s, resultado final: 10.039 eventos, 5.600 confirmados/4.439 pendentes, conferidos após reabertura. Não representa dias de operação. Destino estimado das reescritas nessa rodada: 290.063.928 bytes; não é I/O físico medido. Confirmação continua lendo e regravando a fila inteira, com custo O(tamanho do arquivo) e necessidade de espaço para a cópia.

## Testes locais

Seis casos novos: BOM/terminadores LF, CRLF e CR; Unicode, duplicatas e atributos futuros; justificativas com mesmo ID/conteúdo diferente; linha maior que buffer; confirmação sem correspondência; cancelamento antecipado sem alterar bytes e retomada. Casos existentes cobrem arquivo ocupado/falha da substituição e limpeza do temporário. Lote final Release: 17/17. Debug focado anterior: 16/16, antes do último caso de cancelamento.

Suíte completa local em Debug na implementação intermediária: **810 aprovados, sete falhas e quatro skips em 821**. Cinco falhas ao criar links simbólicos sem privilégio e duas na atribuição de SID/proprietário em devolução de arquivos; TRX/log completo preservados, sem filtrar as falhas. Esse resultado não é uma execução completa do último commit. CI executa a suíte final inteira em Debug/Release. PowerShell 7 e 5.1: 41/41 cada; ambiente 4/4. Sem alterar privilégios do host ou executar instalador nele.

## Crescimento da fila

Este ajuste reduz memória e não controla crescimento: a fila sintética de 50 mil tem ~25,84 MB e conserva todos os eventos. #48 permanece aberta. Próximo incremento deve primeiro expor tamanho/custo da fila e definir a política de retenção explicitamente; apagar auditoria automaticamente não faz parte desta entrega. Eventual compactação deve preservar todos os pendentes, justificativas não confirmadas e dados desconhecidos; cauda inválida/inventário incompleto devem impedir descarte silencioso. É proposta de aceite para atividade própria, não comportamento implementado.

## CI, pacote e homologação

[CI 40043624227](https://github.com/pedro-canafistula/safeupload/actions/runs/40043624227) aprovado nos três jobs, fonte limpa acima: **818 C# aprovados, zero falhas e quatro skips em 822**, Debug e Release, sem filtros. As sete falhas de privilégios do host passaram no runner; caso final de cancelamento incluído. PowerShell 7/5.1 **41/41** cada, ambiente **4/4**.

Doze ensaios de interrupção por configuração aprovados: três repetições de cada operação. Confirmações atingidas pela notificação de criação do temporário; appends observados na fronteira da operação, sem comprovar interrupção de append ainda em andamento. Reabertura/repetição/IDs/metadados conferidos. Volume NTFS de 64 MiB cheio: quatro fases aprovadas com HRESULT 112 e retomada, desmontagem conferida, fonte nova; não herda simplesmente o aceite anterior #52. Execução administrativa do probe não é serviço SYSTEM.

Pacote estático: 724 arquivos e manifesto conferidos. Smoke instalado como LocalSystem passou: inspeção sintética, diagnóstico de falha/retomada, integridade/temporários, reinício preservando dados e remoção. Esses recibos não substituem homologação própria no clone.

EXE **0.1.12**, **84.057.087 bytes**, self-contained, sem assinatura; SHA-256 **B12BF8730050EA0F5260A235D3E0BF770E61778F349B30AA928FFE1AD466D07B**. Manifesto **E22E4AF0B28C868A226DEE0C7243B85112B929CFCD3B766326A927F31081051E**. ZIP artifact 12540925430, 83.605.587 bytes, digest **FA5DB92759AB3ED43C882C0D7711B9D7D02D5EB32EFAFB67C0E812C4C984D6EC**; ZIP, EXE e manifesto conferidos localmente, sem executar instalador no host.

Homologação própria do novo instalador no clone **ainda pendente**. Roteiros preparados para instalação limpa com verificação do payload e dos oito hashes/17 eventos anteriores, inspeções e pipe de usuário comum, reconexão sem substituir UI, início automático após boot/login e desinstalação com painel aberto, preservando 19 eventos/quarentena/temporários após as novas fixtures. Contagens são critérios planejados, não resultados já obtidos. O aceite 0.1.11 não é herdado pelo novo pacote.

[Functional web 40043630567](https://github.com/pedro-canafistula/safeupload/actions/runs/40043630567) reprovado nos três jobs: migration sem EmpresaRepository; agent-contract sem backend iniciado; installed-service com backend encerrado antes de iniciar. C# de agent-contract passou com 818 aprovados/quatro skips em 822. Backend não editado; não afirmar PR inteiramente verde.

Dependências de API/autenticação/idempotência #44/#47 e driver #46 continuam separadas. Sem afirmação de ponta a ponta. PR #49 e #42 em rascunho, sem merge.

[Recibos, medições e hashes](evidencias/confirmacao-fila-20261023/resumo.json). Filas grandes, VHD e instalador ficam fora do Git.
