# Homologação Windows 10 — agente 0.1.9

**Resultado: reprovado na desinstalação com interface aberta.** Instalação, diagnósticos, inspeção, reconexão e inicialização após boot passaram. Não aprovar o ciclo completo do candidato. Falha registrada em [#50](https://github.com/pedro-canafistula/safeupload/issues/50); correção do instalador na fonte 135369df, candidato 0.1.10, ainda com aceite próprio de VM pendente.

Fonte 0.1.9: `8801944cdcd9a245a3eb02107305771c85b91a3a`. EXE 84.058.879 bytes, 724 arquivos de payload, SHA-256 `03FBC7F0372E7B6CEF5B56D32C3CEDEAC431DBB2A18CA59E01F717753E06196F`, sem assinatura. Ensaio de 23/10/2026, aproximadamente 12:22–12:42 (Brasília), exclusivamente no clone `3a9992db-4644-405c-b642-9766edd10650`, Windows 10 Pro 19045.3803/PowerShell 5.1, sem rede, compartilhamentos, clipboard/drag-and-drop compartilhados ou driver. Não houve instalação no host/VM original, configuração de API real ou alteração de Java/Angular/banco/driver.

## Aceites exercitados

- [x] Hashes do pacote/manifesto conferidos dentro da VM. Instalação sobre dados preservados após remoção do 0.1.7; não foi atualização sobre instalação ativa. Os 724 arquivos instalados conferiram com o manifesto.
- [x] Serviço Running/LocalSystem, modo FileSystemWatcher, sem URL de API. Política, fila de onze eventos e quarentena anteriores preservadas por hash na instalação.
- [x] audit-integrity: onze eventos válidos, sem linhas inválidas ou tipos desconhecidos. audit-temporaries: zero candidatos inicialmente; depois dois arquivos sintéticos (25 bytes e vazio) e uma junction ignorada, complete=false e atenção requerida, sem conteúdo/caminhos na resposta. Consulta preservou os bytes. Nome compatível não prova abandono; sem limpeza/promoção.
- [x] Pipe administrativo recusou acesso ao token comum. Pipe de usuário entregou status/histórico sem acesso direto à fila privada.
- [x] Inspeções como usuário comum: texto limpo 39 bytes Approved, CPF sintético 28 bytes Blocked, aviso com trecho mascarado e movimentação real para quarentena. Painel atualizou automaticamente; treze eventos únicos após as duas novas gravações, com os onze IDs anteriores preservados.
- [x] Serviço reiniciado, PID 3900 → 5840, mantendo a UI PID 1756 e data de criação. Painel mostrou indisponibilidade e retomou v1/auditoria automaticamente. Política/fila mantiveram hashes; integridade treze eventos, inventário dois candidatos/25 bytes/uma junction.
- [x] Boot do Windows e login pelo usuário: serviço LocalSystem PID 2816, UI PID 3792 iniciada por Explorer PID 3752, após 12.783,898 ms. Não houve lançamento manual do executável. Os mesmos treze IDs foram recebidos pelo pipe não elevado; painel foi mostrado pela bandeja, sem aviso antigo observado na conferência.
- [x] Diagnósticos administrativos após boot: treze eventos válidos, sem erro de integridade; dois candidatos/25 bytes/junction ignorada; saúde sem degradação. Política/fila/quarentena/temporários tinham os hashes esperados antes da remoção.
- [ ] Remoção completa com a interface aberta: **falhou**. Desinstalador retornou zero e removeu serviço/startup, mas a UI PID 3792 permaneceu. Executável de serviço ausente, executável da UI presente, desinstalador já removido. Log: **Removed all? No**, sem solicitação de reboot. Restaram 77 arquivos (100.171.712 bytes), todos conferidos com o manifesto original.
- [ ] Aceite final de preservação após remoção e recuperação controlada: pendente. O roteiro parou na asserção UI permanece.; as verificações de hashes posteriores não foram executadas. Não apresentar o hash colhido antes de remover como prova posterior.

## Causa, correção e rastreabilidade

Invoke-AgentSetup.ps1 removia serviço/startup sem encerrar a UI. Fechar a janela pode apenas ocultá-la na bandeja. O smoke anterior não mantinha a interface real aberta ao remover; o CI aprovado do 0.1.9 não cobria esse cenário.

Correção 135369df: verificar caminho completo do módulo do processo e encerrar somente a UI pertencente ao diretório de instalação já validado por caminho/ACL, mantendo o objeto/handle do processo e aguardando saída. Sem encerramento global por nome. Se a identidade/saída não puder ser verificada, recusar a remoção antes de remover serviço/startup. CheckUninstall continua sem encerramento de processos.

Contratos reais de processo: 41/41 em PS7 e PS5.1, com dois executáveis de mesmo nome em pastas diferentes; apenas o caminho esperado encerra, o homônimo externo permanece, segunda chamada é idempotente. [CI 39981283188](https://github.com/pedro-canafistula/safeupload/actions/runs/39981283188) aprovado nos três jobs: C# 786 aprovados, zero falhas e quatro skips em 790 por configuração; PS7/PS5.1 41/41 e ambiente 4/4. Smoke agora abre a UI instalada e exige término e ausência dos executáveis após remover. Isso não substitui o aceite do 0.1.10 no clone.

Recibos originais de instalação/reinício/remoção foram copiados diretamente do convidado, preservando bytes. Capturas, scripts, logs, recibos derivados e hashes em [evidências](evidencias/homologacao-win10-019-20261023/). Conferência externa separada em conferencia-ui.json. O marcador de parada chegou depois da espera de 45 s: o recibo bruto tem stoppedUiObserved=false, mas a indisponibilidade foi observada e capturada externamente; o recibo não foi alterado para simular confirmação no prazo.

A consulta inicial à fila com token comum foi negada pela ACL; a conferência real ocorreu no roteiro elevado antes de instalar. Uma tentativa de elevação para o reinício expirou sem executar; a seguinte foi confirmada pelo usuário. Scripts usaram RemoteSigned somente no processo de teste, sem alteração permanente. Login e UAC foram feitos pelo usuário.

## Limites

Watcher inspeciona após escrita e pode mover arquivo; não prova bloqueio preventivo de upload. Sem API real, autenticação remota ou driver M2; dependências #44/#46/#47 permanecem. Não testou corte de energia, volume cheio ou dias de carga. #48 segue aberta para durabilidade, retenção, recursos e tratamento seguro dos temporários. PR #49/#42 permanecem rascunhos, sem merge. Nenhuma recuperação posterior pode converter a remoção original deste 0.1.9 em aprovada.
