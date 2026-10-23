# Encerramento da interface ao desinstalar — 23/10/2026

**Correção aprovada no CI; homologação do candidato corrigido na VM ainda pendente.** Fonte `135369df7ddabbbc0902658029021dc63724a307`, candidato 0.1.10, atividade [#50](https://github.com/pedro-canafistula/safeupload/issues/50), PR #49 em rascunho. Java, Angular, banco e driver não foram editados.

## Falha encontrada na homologação

O 0.1.9 passou nos diagnósticos/inspeções/reconexão/boot do clone, mas a remoção retornou zero deixando a UI PID 3792 e 77 arquivos em uso (100.171.712 bytes). Log termina com Removed all? No, sem solicitar reboot. Serviço/startup foram removidos; UI/executável permaneceram. Os 77 resíduos conferiram individualmente com o manifesto original. [Relatório e recibos da reprovação](HOMOLOGACAO-WIN10-019-20261023.md).

A ação Uninstall removia somente serviço/startup. Fechar a janela da interface pode ocultá-la na bandeja; o smoke anterior não mantinha a UI aberta ao remover. Portanto o CI verde anterior não comprovava esse cenário, nem o retorno zero demonstrava remoção completa.

## Mudança controlada

Stop-SafeUploadInstalledUi recebe o caminho absoluto da UI no diretório de instalação que o chamador já validou por caminho/ACL. Abre/mantém o objeto e handle do processo, verifica o caminho completo do módulo e encerra somente o processo correspondente. Processos de mesmo nome em outras pastas são preservados. Processo que já saiu é tolerado; identidade inacessível/ambígua ou saída não concluída em dez segundos provoca erro e impede prosseguir com a remoção de serviço/startup. Não há encerramento global por nome.

O encerramento é explícito porque CloseMainWindow pode apenas ocultar o painel. Não é uma nova política de saúde, mudança do serviço, formato de fila ou regra de retenção. CheckUninstall segue sem encerrar processos; a ação ocorre somente em Uninstall depois das verificações existentes. A validação não é isolamento de processos hostis/concorrentes nem proibição de que outra sessão inicie a UI durante a remoção.

## Testes e pacote

Dois testes novos nos contratos: recusa de caminho relativo/nome diferente; dois processos .NET Framework reais com nome SafeUpload.Agent.App e caminhos distintos em laboratório temporário, encerrando apenas o esperado e preservando o externo, inclusive na segunda chamada idempotente. Limpeza usa somente os objetos criados pelo teste. Local: PS7 e PS5.1 **41/41** cada; sem instalação no host.

[CI 39981283188](https://github.com/pedro-canafistula/safeupload/actions/runs/39981283188) aprovado nos três jobs: C# **786 aprovados, zero falhas e quatro skips em 790**, Debug/Release; PS7/PS5.1 **41/41**, ambiente **4/4**. Smoke do runner abriu a UI real PID 7468 antes de desinstalar, confirmou runningBefore=true/exitedAfter=true e ausência dos executáveis, preservando política/fila/temporário/junction. O teste mantém as guardas de Windows GitHub-hosted descartável; não foi executado no host ou na VM por esse roteiro de CI.

EXE **0.1.10**, fonte limpa acima, self-contained, 724 arquivos, **84.062.842 bytes**, sem assinatura. SHA-256 **`2C63EC1A2BF984AB126E160428682F573BD371045AEBC7C3F19DD494D47DEDE0`**. ZIP do artifact 12513737472: 83.612.277 bytes, digest **`5FE792203073BFEFDEC7F5A51BFAF0B7EB88362A765CC6A16C4A3513273958A1`**, baixado/conferido. Manifesto SHA-256 `553D5F3A25D28FDFDBEEAF046F10763147F6557D54716D2DBD08BD10BFCDFA63`.

O módulo separado para recuperação foi reconstruído da fonte rastreada com CRLF e seu SHA-256 coincidiu exatamente com a entrada do manifesto CI: `B765D443CDEDD3DC7F7353DEB360FB679B349F30AD5D90261049DB07E957E8AB`. Isso permite verificar os bytes antes da importação no roteiro restrito ao clone; não foi executado instalador no host.

## Aceite restante

- [x] Reproduzir falha com UI aberta e conservar log/recibo reprovado.
- [x] Encerrar somente UI do caminho instalado; provar preservação de processo homônimo externo.
- [x] Smoke do CI com UI real aberta, saída confirmada e executáveis ausentes.
- [ ] Reconferir estado atual do clone e recuperar somente resíduos correspondentes ao manifesto 0.1.9, preservando dados; recuperação não transforma a remoção original em aprovada.
- [ ] Instalar/conferir 0.1.10 no clone e validar a remoção com a UI interativa aberta.
- [ ] Registrar os resultados finais e encerrar #50 somente após aceite completo.

[Functional web 39981289742](https://github.com/pedro-canafistula/safeupload/actions/runs/39981289742) segue reprovado: backend não iniciou/encerrou antes de iniciar; migration sem EmpresaRepository. Logs conferidos, sem alteração de backend e sem afirmar ponta a ponta. #48 permanece aberta para durabilidade, dias de carga, retenção e temporários. PR #42/#49 sem merge. [Evidências e hashes](evidencias/desinstalacao-ui-20261023/).
