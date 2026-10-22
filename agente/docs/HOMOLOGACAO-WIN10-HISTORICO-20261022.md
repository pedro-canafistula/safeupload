# Windows 10: instalação inicial e correção do histórico

## Evidência do candidato 0.1.4

Clone descartável `SafeUpload-Homologacao-Win10-20261021`, UUID
`3a9992db-4644-405c-b642-9766edd10650`, Windows 10 Pro 22H2,
build `19045.3803`. Clone completo do snapshot de ferramentas; a VM original
não foi restaurada nem usada como alvo. Clone sem rede, pastas compartilhadas,
clipboard compartilhado ou arrastar-e-soltar. Checkpoint anterior à instalação.

A consulta autenticada inicial confirmou: nenhum runtime .NET global, nenhum
agente/driver instalado, nenhum diretório SafeUpload existente. O acesso
`safeuploadlab` estava sem token administrativo. A senha foi digitada localmente,
usada em memória/stdin e não foi salva. A cópia inicial falhou por interpretação
do diretório de destino; foi corrigida para copiar cada arquivo ao caminho
completo. A segunda cópia passou, inclusive o hash dentro do convidado.

Instalador 0.1.4, SHA-256
`EAD34947B0AB8AAF60DD4AB9757BA5D1F5FA28E57736D9B4ECB360AA2AC5E099`.
O usuário executou o ensaio na sessão interativa, aprovou a elevação e enviou
capturas dos resultados. A captura de `result.json` informa
`service-validation-passed-ui-pending`: identidade/hash/estado limpo conferidos;
serviço LocalSystem ativo; SID, runtime incluído e startup conferidos;
CPF sintético auditado; reinício **do serviço** preservando política e evento.
O modo é FileSystemWatcher, após gravação; `Blocked` é a classificação de
auditoria, sem prova de bloqueio preventivo do driver. Não houve ensaio do driver.

As capturas seguintes confirmam aplicativo na bandeja e renderização das telas
Status e Histórico, após abertura normal pelo Explorador. O painel recebeu
política v1 e estado de auditoria, mas mostrou histórico vazio apesar do evento
persistido. Portanto, a integração do histórico do 0.1.4 **não foi aprovada**.
As capturas são evidência manual; os arquivos brutos do resultado e logs dentro
da VM ainda precisam ser coletados. Evidências locais ficam em
`outputs/homologacao-win10-20261021/`, fora do repositório publicado.

## Causa e mudança do candidato 0.1.5

`App` e as telas abriam `LocalQueueAuditSink` diretamente em ProgramData.
`ProtectedPolicyAcl` protege essa pasta para SYSTEM e administradores. Para o
token comum, `File.Exists` pode retornar falso sem revelar a negação, produzindo
uma lista vazia. Navegar entre abas repetia a leitura privada.

O serviço passa a ler a fila e entregar uma mensagem `history` no pipe existente,
depois do status e antes dos eventos ao vivo. O painel não abre mais a fila.
Nenhuma ACL da política, fila ou diretório foi ampliada. Não há listener HTTP
novo, mudança no backend ou dependência da API de política para este teste.

Regras da projeção:

- A identidade vem do token do processo conectado ao pipe, resolvido para conta
  qualificada. Identidade ausente/não resolvida recebe histórico indisponível.
- Consulta limitada aos últimos 500 registros da fila; entrega apenas registros
  deste endpoint com conta qualificada igual à identidade autenticada.
- Eventos legados de FileSystemWatcher com conta `MAQUINA$`, PID zero e processo
  `desconhecido` mantêm a mesma visibilidade de máquina já usada nas notificações
  ao vivo. Essa exceção não inclui clipboard, Web ou eventos com processo conhecido.
- Contas antigas sem domínio e eventos de terceiros não são inferidos nem
  ampliados para todos. A fila atual não guarda SID/sessão por evento: um histórico
  por SID e sessão, resistente a renomeação/reutilização de contas, requer evolução
  própria do contrato de auditoria. Não se afirma isolamento histórico por sessão
  entre duas sessões da mesma conta.
- A mensagem tem registro durável de emissão, com tipo `History`, sessão e
  contagem/disponibilidade; a projeção não é difundida aos outros assinantes nem
  entra no replay de notificações. Falha desse registro impede a entrega.
- Snapshot substitui a lista ao reconectar, sem alertas de bloqueio históricos.
  Replay e eventos ao vivo são deduplicados por EventId; histórico limitado a 500
  linhas e atividade a oito. Falha de leitura é distinta de histórico vazio.

A leitura usa a implementação de fila atual, que ainda percorre os registros
em disco antes de recortar os recentes. Otimização/rotação prolongada continua
na atividade #48. Não se declara custo constante de memória/leitura.

O tipo `History` é novo no registro de emissões. Downgrade para binário antigo
que não conhece esse tipo não foi homologado; upgrade/rollback continuam pendentes.

## Validação da correção

Testes adicionados para fila persistida com leitor recriado, controle de conta e
endpoint, rejeição de identidade ausente/contas ambíguas, contrato NDJSON, limites,
deduplicação, histórico indisponível, emissão privada durável e falha de registro.
Um teste usa servidor e cliente reais de named pipe, com identidade do processo,
verifica status → histórico → evento ao vivo e repete a conexão sem depender
da janela de replay de 60 segundos (evento salvo cinco minutos antes).

Lote local final: **57 aprovados e duas falhas em 59 casos**, tanto Debug quanto
Release. Os nove casos novos passaram nas duas configurações. As duas falhas
existentes são `Reparse_and_hard_link_files_are_refused(hardLink: False)` e
`Reparse_directory_is_refused`: criação de links simbólicos sem privilégio no
host, antes das asserções da proteção. Nenhum controle foi removido ou relaxado.
TRX/logs locais em `artifacts/historico/` e `artifacts/historico-final-*.log`.
Uma tentativa intermediária de Release misturava recuperação saudável e falha
deliberada no mesmo teste; esses cenários foram separados e ambos passaram no
lote final. Os resultados intermediários não são a aprovação final.

CI aprovado: [execução 39778539274](https://github.com/pedro-canafistula/safeupload/actions/runs/39778539274),
fonte limpa `3fa6986b938903f9abbafc0f696f1a043124672d`.

- Suíte C# completa sem filtros: **747 aprovados, zero falhas, quatro ignorados,
  total 751**, em cada configuração Debug e Release. Os nove casos novos e os
  dois testes de links falhos no host constam como Passed nos dois TRX do runner.
- PowerShell 7: 39/39; Windows PowerShell 5.1: 39/39; ambiente: 4/4.
- Validação estática e instalação/reinício/recusa de sobrescrita/remoção reais
  aprovados em Windows Server 2025 descartável. Política e fila preservadas.
- EXE 0.1.5: SHA-256
  `38FB0F7D9665B9E15E90D7F91A1B536D558EF38CD96D34B35071B2E38598BADB`,
  84.039.990 bytes, 724 arquivos de payload, sem assinatura da equipe.
- ZIP do instalador: artifact `12425996640`, SHA-256
  `3b41c38476e3ff1673b364a761adce6068c9e1128734be5ef7b3c28c8c73ab21`.
  ZIP Debug `12426200433`, SHA-256
  `41f4d7fee2c543f3274dd2182b61bed556ad1f80e7bda01b6cec64fdb2fb0835`;
  ZIP Release `12426021318`, SHA-256
  `293cb9b14b4584263054a4a492715589fa9aa625fa677672fa229e74b08f2c2a`.
  Todos baixados e confrontados; EXE conferido com build-result e recibo estático.

Evidências brutas locais do novo CI em `outputs/homologacao-historico-20261022/`.
O candidato exato foi preparado para repetição no clone. O resultado visual
posterior está registrado abaixo. O roteiro local confere identidade do clone,
proveniência do 0.1.4 e hash do novo EXE; coleta o resultado anterior, desinstala
o 0.1.4 preservando hashes da política/fila e instala o 0.1.5 sobre os dados
preservados. Em seguida consulta o pipe e exige o EventId original uma única vez.
Esse roteiro é restrito a este laboratório e requer elevação local; não é uma
implementação nem homologação geral de upgrade. A interface deve ser reaberta
normalmente pelo usuário para concluir o aceite visual.

## Confirmação visual do histórico 0.1.5

A transferência do EXE 0.1.5 passou com hash conferido dentro do convidado.
Uma execução posterior do roteiro foi recusada antes de remover qualquer coisa:
ele esperava 0.1.4, mas a consulta somente de leitura revelou que o 0.1.5 já
estava instalado. `installation.json` e manifesto informam versão 0.1.5,
commit `3fa6986b938903f9abbafc0f696f1a043124672d`, modo FileSystemWatcher,
sem API configurada; serviço Running como LocalSystem. A recusa não é prova de
falha da instalação 0.1.5. O resultado falho dessa repetição também não comprova
os passos anteriores de desinstalação/reinstalação: preservar essa distinção.

O resultado bruto do ensaio 0.1.4 foi coletado e confirma o EventId
`a8c6552d-dca9-41eb-9bff-b1782480d158`, arquivo
`win10-synthetic-028b0d23bd61480ea2833c9f817416ca.txt`, 29 bytes,
`2026-10-22T12:09:36.3064497+00:00`, CPF com trecho mascarado terminado em 25.
Resultado e diagnóstico ficam em `resultado-014-coletado.json` e
`diagnostico-instalacao.json`, no diretório local do laboratório.

Após orientação para abrir normalmente pelo Explorador, o usuário enviou a
captura do Histórico já preenchido. Ela mostra uma linha com o prefixo do mesmo
arquivo sintético, 29 B, 22/10/2026 09:09:36 (São Paulo), categoria CPF e trecho
mascarado terminado em 25. É confirmação visual de recuperação do evento
anterior no novo painel; o EventId completo não é exibido na grade.

Captura local `evidencias-ui/historico-015-evento-anterior.png`, SHA-256
`58EEC0142C8870852925E4B625C887F65973414FA8112325A7DC959CB80CD466`.
Há uma linha visível, mas isso não substitui o ensaio de reconexão/reabertura.
Permanece a distinção entre a classificação de auditoria Blocked e bloqueio
preventivo de uma operação. Não foi necessário alterar ACLs ou o backend.

## Reabertura e novos eventos com o painel aberto

O usuário informou que o histórico continuou igual após sair pela bandeja e
reabrir normalmente. Isso confirma a manutenção da linha anterior nessa
reabertura, por relato manual; a ausência de alerta antigo não foi confirmada
explicitamente. Reconexão por reinício do serviço com UI aberta ainda pendente.

As primeiras capturas seguintes mostraram criação/renomeação de arquivos vazios,
0 B, classificados como permitidos. Isso comprovou atualização do painel, mas
não inspeção de conteúdo sensível. Os registros vazios não precisam ser alterados
retroativamente quando uma gravação posterior produz outra operação auditada.

A captura final mostra novos eventos com 27 B: `.txt` às 11:03:46 e
`cpf-teste.txt.txt` às **11:05:02 de 22/10/2026, horário de São Paulo**, ambos
classificados Blocked, categoria CPF e trecho mascarado terminado em 25. O
arquivo `cpf-teste.txt.txt` também tem registro anterior de 0 B às 11:04:12;
são operações em horários/tamanhos distintos, não prova de duplicação de EventId.
O evento original de 09:09:36 permanece na mesma grade. O usuário enviou também
captura do alerta de CPF. Assim, detecção do novo conteúdo, mascaramento,
notificação e atualização do histórico com o painel aberto têm evidência manual.

Captura `evidencias-ui/historico-cpf-novo-015.png`, SHA-256
`23BFB16837EC2D6D3044F383D10DB98548EA87509084A8E160F95F3C7E14EA0D`;
alerta `evidencias-ui/alerta-cpf-015.png`, SHA-256
`66D59525F81F47FB5E601356CC49EF34BC623DE481DE3BF468BAA7E0317606EB`.
Hashes das capturas intermediárias também preservados no laboratório.

Os textos da atividade/alerta ainda usam termos como "Arquivo enviado" e
"Envio bloqueado" embora o status seja auditoria por watcher. Esta rodada
comprova classificação/alerta, não upload nem impedimento preventivo de gravação;
adequação desses textos ao modo operacional fica registrada como pendência.

## Reinício do Windows: histórico preservado, abertura automática reprovada

Após a orientação para reiniciar apenas a VM, o usuário enviou nova captura do
Histórico com os mesmos sete registros e horários, incluindo os CPFs de 27 B e
o evento original de 29 B. Em seguida esclareceu que precisou abrir o aplicativo
manualmente e que o Status continuava igual. Isso confirma a persistência visual
do histórico após a retomada, mas **reprova a inicialização automática da interface**.
Não considerar esse aceite aprovado pelo simples fato de a chave Run ter sido
conferida no ensaio do instalador.

Investigação em andamento: consulta somente de leitura às entradas Run nas duas
visões do registro, aprovação de startup para máquina/usuário, políticas de
execução dessas entradas, boot, processos e erros do aplicativo. Não foi feita
mudança especulativa no mecanismo de startup nem ampliação de privilégios.
O manifesto da UI pede `asInvoker`. Consulta restrita ao clone e com senha
digitada localmente.

O diagnóstico coletado às 14:15:57 UTC encontrou a entrada Run de máquina na
visão 64 bits, com o caminho esperado entre aspas. Não encontrou entrada
duplicada na visão 32 bits/usuário, aprovação de startup desativada para esse
nome ou as políticas consultadas desabilitando Run. Serviço Running, StartMode
Auto, LocalSystem. O log Application não tinha eventos correspondentes aos
IDs/provedores consultados para a UI; isso não prova ausência de toda falha
possível de inicialização. Boot às 14:10:16 UTC, Explorer às 14:10:23, único
processo da UI às 14:11:38, coerente com a abertura manual relatada.

As DLLs efetivamente instaladas do serviço e da UI foram comparadas com os
hashes do manifesto do artifact 0.1.5 aprovado e coincidem. Não há evidência
nessa consulta de pacote divergente. A causa do autostart permanece em aberto.
Foi preparado monitor somente de leitura, com janela limitada e amostras após
um novo boot sem abrir o painel manualmente. Ele preserva senha apenas em
memória durante o ensaio e não altera registro, serviços ou arquivos na VM.
Não se substituiu a entrada Run por outro mecanismo sem observar o próximo boot.

O usuário posteriormente autorizou o uso direto da credencial do laboratório.
Foi estabelecida sessão autenticada via VirtualBox, com SecureString em memória
e senha passada por stdin, sem arquivo de senha ou senha nos argumentos.
Foi solicitado reinício apenas do clone. Novo boot detectado às
`2026-10-22T14:24:19.5Z`, mas as 17 amostras seguintes não tinham usuário
interativo logado. A VM permaneceu na tela de entrada; tentativas de entrada
visual pelo controle do VirtualBox não concluíram o login.

Portanto, o retorno bruto `completed-no-app-process-observed` desse monitor
**não é reprovação adicional do autostart**: sem login não houve o gatilho Run
do usuário. Interpretação local registrada como
`inconclusive-no-interactive-login` em `monitor-startup-interpretacao.json`.
O monitor foi ajustado para iniciar a janela de observação somente após detectar
login interativo em novo boot. A falha inicial relatada pelo usuário continua
aberta até repetição nessas condições. A sessão de testes usada nesta rodada
foi encerrada e a credencial em memória descartada; não foi feito autologon nem
alteração de configuração de startup. VM original permaneceu desligada.

## Repetição após login: startup aprovado nesta rodada

O usuário concluiu o login após a orientação para não abrir o SafeUpload. A
consulta seguinte encontrou uma única UI, iniciada antes das consultas desta
rodada, com Explorer como processo pai. Nenhum comando de lançamento do agente
foi executado pelo assistente nessa observação:

| Processo | PID | Sessão | Criação UTC |
| --- | ---: | ---: | --- |
| Serviço | 2880 | 0 | 22/10/2026 14:24:25.058 |
| Explorer | 1536 | 1 | 22/10/2026 14:32:51.876 |
| UI | 6012 | 1 | 22/10/2026 14:33:04.464 |

A UI iniciou **12,588 segundos após o Explorer**. O serviço permaneceu Running,
Auto, LocalSystem. O ícone estava na área de ícones ocultos da bandeja; o
assistente abriu esse menu e o painel pelo ícone existente, usando controle
visual do VirtualBox. Status exibiu auditoria e política v1; Histórico mostrou
os mesmos sete registros, sem alerta antigo ao abrir o painel observado.

Uma segunda leitura do pipe, às 14:36:52 UTC, com token **sem elevação** na sessão
1, recebeu status com `policyVersion=1`, cinco categorias, `protectionActive=true`
e `auditOnly=true`; histórico disponível com sete eventos, sete EventIds únicos
e o EventId original exatamente uma vez. A validação do pipe terminou como
`passed`. Os JSON brutos foram preservados no laboratório.

Evidências curadas para revisão:
[recibo com horários e asserções](evidencias/homologacao-win10-20261022/startup-apos-login.json)
e [captura do histórico após autostart](evidencias/homologacao-win10-20261022/historico-apos-autostart-015.jpg).
SHA-256 da captura:
`DFB95BBD5FF24C018183DF6D9593A22500D162B8E397AE03E468EE209CA55395`.

**Resultado:** startup, bandeja, estado e recuperação de histórico aprovados
nesta repetição no Windows 10. A falha inicial relatada não se reproduziu; sua
causa não foi demonstrada e não se presume erro do usuário. Não houve alteração
do mecanismo Run, das ACLs ou do instalador para obter esse resultado. A sessão
com credencial em memória foi encerrada após as consultas.

## Reconexão com painel aberto: aprovada nesta rodada

O instalador 0.1.5 permaneceu no clone isolado, com fonte
`3fa6986b938903f9abbafc0f696f1a043124672d`, FileSystemWatcher e sem driver.
O usuário confirmou a elevação local. O roteiro de laboratório verificou UUID,
versão, origem, caminho do serviço LocalSystem e uma única UI antes de parar o
serviço. Não houve reinstalação nem alteração das ACLs ou do startup.

- Serviço parado às **14:57:28.958 UTC** e Running às **14:58:16.114 UTC**;
  PID mudou de 2880 para 6300. O roteiro aguardou 45 segundos antes de religá-lo.
- O painel mostrou **Serviço indisponível**, política desconhecida e Sem serviço.
  Após o retorno, recuperou automaticamente **Em auditoria**, política v1 e cinco
  categorias, sem fechar nem relançar a UI: PID 6012 e criação preservados.
- Hashes SHA-256 da política e da fila permaneceram idênticos. Leitura do pipe
  após a reconexão, sem elevação, recebeu os mesmos sete EventIds únicos da
  leitura anterior, incluindo o evento original uma única vez.
- Status e Histórico exibiram sete linhas. Nenhum alerta antigo foi observado
  nos pontos de inspeção visual. Não foi medida continuamente a latência da UI.

As duas primeiras invocações não reiniciaram o serviço nem produziram recibo:
a política efetiva de scripts era Restricted e o roteiro inicial não tratava
corretamente a contagem de um único objeto no PowerShell 5.1. O roteiro foi
corrigido com arrays explícitos e suas condições iniciais foram verificadas
antes da nova elevação. A execução final usou RemoteSigned somente no processo
de teste; nenhuma política permanente do Windows foi alterada. Essas tentativas
não contam como aprovação ou falha do agente.

Evidências: [resumo e hashes das capturas](evidencias/homologacao-win10-20261022/reconexao-resumo.json),
[recibo bruto do serviço](evidencias/homologacao-win10-20261022/reconexao-recibo-servico.json),
[roteiro restrito ao clone](evidencias/homologacao-win10-20261022/Testar-Reconexao-015.ps1),
[indisponibilidade](evidencias/homologacao-win10-20261022/reconexao-servico-indisponivel.jpg),
[estado restabelecido](evidencias/homologacao-win10-20261022/reconexao-status-restabelecido.jpg)
e [histórico preservado](evidencias/homologacao-win10-20261022/reconexao-historico-preservado.jpg).
O recibo bruto deixa a observação visual como pendente, pois ela foi feita
separadamente pelo assistente e registrada no resumo. A sessão com a credencial
em memória foi encerrada após as consultas. Esta entrega acrescenta evidências;
os testes C# e de instalador do CI anterior não foram reexecutados.

## Aceite ainda necessário

- [x] Instalação inicial 0.1.4 em Windows 10 sem .NET global; evidência manual.
- [x] Abertura da interface pela sessão comum; status e política recebidos.
- [x] Coletar resultado bruto 0.1.4 e diagnóstico da instalação 0.1.5, sem salvar senha.
- [ ] Coletar logs completos do ensaio de troca entre versões.
- [x] Confirmar 0.1.5 no Windows 10 após CI aprovado e transferência com hash conferido.
- [x] Ver evento já persistido no Histórico após abertura normal orientada ao usuário; evidência manual.
- [x] Reabrir a interface mantendo o histórico sem nova linha, segundo relato do usuário.
- [x] Não observar alerta antigo ao abrir o painel após o login desta rodada.
- [x] Reconectar serviço com UI aberta: sete eventos únicos, dados preservados e nenhum alerta antigo observado nesta rodada.
- [x] Criar novo arquivo sintético com a interface aberta; detecção de CPF, alerta e histórico atualizados.
- [ ] Adequar textos de envio/bloqueio ao modo de auditoria por watcher.
- [x] Histórico preservado na abertura manual após reinício relatado da VM; sete registros visíveis.
- [x] Repetir a investigação de startup: UI iniciada automaticamente nesta rodada; falha anterior não reproduzida.
- [x] Confirmar serviço, bandeja automática e estado após reinício e login real do Windows 10.
- [ ] Desinstalar e conferir preservação de política e fila.
- [ ] Windows 11, assinatura da equipe, upgrade/repair/rollback e integração com API/driver.

PR #49 e PR #42 permanecem em rascunho, sem merge. A reprovação de Functional web
continua separadamente registrada em `DIAGNOSTICO-FUNCTIONAL-WEB-20261021.md`.
