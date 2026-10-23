# Inventário administrativo de temporários da fila — 23/10/2026

Fonte: `8801944cdcd9a245a3eb02107305771c85b91a3a`, candidato **0.1.9**, PR #49 em rascunho. Escopo: Core, serviço, consulta PowerShell, testes e CI do agente. Sem mudanças de Java, Angular, banco, driver ou VM.

## Comportamento entregue

A consulta administrativa **audit-temporaries** inventaria metadados dos candidatos `<nome-da-fila>.<GUID com 32 hexadecimais>.tmp` no diretório da fila. Pode ser executada por administrador com `Get-SafeUploadDiagnostics.ps1 -Query audit-temporaries`, no mesmo pipe e DACL já existentes, inclusive sem driver.

Retorna quantidade de arquivos regulares examináveis, soma de tamanhos lógicos em bytes, entradas examinadas, candidatos cujos metadados não puderam ser consultados, links ignorados, limite atingido e bloqueio de percurso por link ancestral. Não retorna nomes, caminhos, conteúdo, IDs ou mensagens de exceção. Não abre os arquivos para leitura de conteúdo. Um arquivo com conteúdo bloqueado por compartilhamento ainda pode ter metadados consultáveis: não é automaticamente classificado como ilegível.

O nome compatível **não prova que o arquivo foi produzido pelo agente ou está abandonado**. Não há leitura/validação de JSON do temporário, promoção, exclusão, confirmação de entrega, reparo ou alteração da retenção. Tamanho lógico não mede alocação física nem todo o consumo de disco.

## Completude e limites

- Varredura somente do diretório imediato, sem recursão. Nomes incompatíveis e diretórios comuns não entram na contagem de candidatos.
- Máximo de **10.000 entradas de diretório**, incluindo nomes incompatíveis. Ao encontrar mais entradas, retorna limite atingido; contagens e bytes são limites inferiores.
- Links/reparse points com nome compatível são ignorados e contados; link no diretório configurado ou ancestral bloqueia a varredura inteira. Esta é uma verificação por metadados, não proteção atômica contra substituições concorrentes de caminhos.
- `complete=false` quando há limite, candidato inacessível, link ignorado ou percurso bloqueado. Não interpretar quantidade zero como ausência de problemas nesse caso. `requiresAttention=true` para candidatos encontrados ou resultado incompleto. Diretório ausente não é criado e retorna `directoryExists=false`.
- Erro global de enumeração/acesso gera resposta de falha sanitizada, sem recibo parcial saudável. Cancelamento se propaga e libera o lock.
- Usa o mesmo lock da instância da fila para não inventariar a própria reescrita em andamento. Pode atrasar gravações; a consulta usa o prazo existente de cinco segundos do pipe. Verificações de cancelamento ocorrem entre operações; I/O síncrono de metadados pode atrasar o atendimento ao cancelamento. Outro processo/instância pode mudar os arquivos, portanto não é snapshot atômico nem prova de durabilidade.
- Consulta sob demanda. Não aciona alerta automático, log de degradação, painel ou contadores de `audit-health`.

## Validação local

Seis casos novos de C# exercitam nomes exatos, temporários vazios, conteúdo bloqueado por compartilhamento, bytes preservados, subdiretórios ignorados, diretório/fila ausentes, limite de entradas, cancelamento e pipe real com resposta/erro sanitizado sem driver. Recorte Debug **22/22** com integridade; Release **34/34** com integridade/observabilidade, sem falhas/skips nesses recortes. Contratos PS7 e Windows PowerShell 5.1 **39/39** cada; sintaxe do smoke validada no 5.1.

Consulta adicional recusou um ancestral junction criado no laboratório. Também inventariou os dois temporários reais do ensaio local anterior de interrupção: **4.415.488 bytes** na confirmação de eventos e **3.940.352 bytes** na de justificativas, um candidato por diretório. Fila e temporários mantiveram hashes anteriores. São os arquivos locais de quatro cenários daquela etapa, não os tamanhos dos temporários dos runners anteriores.

## Aceite e pendências

- [x] Consulta somente administrativa e sem driver, sem conteúdo/caminhos na resposta.
- [x] Preservar bytes e não promover/remover candidatos.
- [x] Diferenciar resultado completo/incompleto e limitar o trabalho por quantidade de entradas.
- [x] Validar cancelamento, limites, erro sanitizado e temporários de interrupção real.
- [x] Conferir serviço SYSTEM instalado, junction, reinício e preservação após remoção no CI desta fonte.
- [ ] Homologação completa do 0.1.9: [tentativa reprovada na remoção com UI aberta](HOMOLOGACAO-WIN10-019-20261023.md), apesar dos diagnósticos/inspeção/reconexão/boot aprovados. [Correção 0.1.10](DESINSTALACAO-UI-20261023.md) com aceite próprio da VM pendente.
- [ ] Definir tratamento/limpeza segura com regra explícita; nenhum candidato é descartável apenas por nome, idade ou tamanho.

A #48 permanece aberta para append efetivamente interrompido, energia, volume descartável cheio, dias de carga, orçamento de recursos, segmentos/checkpoints e retenção. API real, autenticação de máquina e idempotência continuam dependências da equipe. O 0.1.9 não herda a homologação Windows 10 do 0.1.7. Nenhum merge realizado.

Recibos e hashes: [evidências](evidencias/temporarios-fila-20261023/).

## CI e identidade do pacote

[CI 39972212330](https://github.com/pedro-canafistula/safeupload/actions/runs/39972212330) **aprovado nos três jobs**. Suíte C# completa: **786 aprovados, zero falhas e quatro skips em 790**, Debug e Release; seis casos novos. PS7/PS5.1 **39/39** cada; ambiente **4/4**. Smoke real SYSTEM: zero candidatos inicialmente; depois um arquivo sintético de **25 bytes** e uma junction ignorada, com `complete=false` e atenção requerida. Mesmas contagens após reinício. Hashes da fila e temporário preservados na consulta; política, fila, temporário e junction preservados após remoção do serviço/instalação.

EXE **0.1.9**, fonte limpa acima, **84.058.879 bytes**, **724 arquivos de payload**, self-contained, sem assinatura. SHA-256 recalculado localmente e comparado aos recibos: **`03FBC7F0372E7B6CEF5B56D32C3CEDEAC431DBB2A18CA59E01F717753E06196F`**. ZIP do artifact 12509248753: **83.607.873 bytes**, SHA-256 `FB235C3BCAC9584006C8D0060D37C08C29607AFAD8476FA20D13D1CCCE96DBFB`, digest conferido. O pacote não foi executado no host ou na VM. Validação estática e smoke instalado são recibos distintos.

[Functional web 39972222258](https://github.com/pedro-canafistula/safeupload/actions/runs/39972222258) segue reprovado nos três jobs: migration sem EmpresaRepository, agent-contract com backend não iniciado e installed-service com backend encerrado antes de iniciar. Logs conferidos; nenhum código fora do agente alterado. Não afirmar PR inteiramente verde nem integração ponta a ponta.
