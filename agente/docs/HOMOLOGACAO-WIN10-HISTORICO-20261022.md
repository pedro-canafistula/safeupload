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

O resultado do CI será registrado separadamente.
O runner executará a suíte C# completa sem filtros e instalação/reinício/remoção
do novo candidato, com os mesmos controles de proteção anteriores.

## Aceite ainda necessário

- [x] Instalação inicial 0.1.4 em Windows 10 sem .NET global; evidência manual.
- [x] Abertura da interface pela sessão comum; status e política recebidos.
- [ ] Coletar resultado e logs brutos da VM, sem coletar senha.
- [ ] Repetir no Windows 10 com o EXE 0.1.5 exato, após CI aprovado e hash conferido.
- [ ] Ver evento já persistido no Histórico ao abrir a interface como usuário comum.
- [ ] Reabrir interface/reconectar serviço sem duplicar evento nem alerta antigo.
- [ ] Criar novo arquivo sintético com a interface aberta e verificar atualização.
- [ ] Reiniciar Windows e verificar startup/serviço/estado, distinguindo de Restart-Service.
- [ ] Desinstalar e conferir preservação de política e fila.
- [ ] Windows 11, assinatura da equipe, upgrade/repair/rollback e integração com API/driver.

PR #49 e PR #42 permanecem em rascunho, sem merge. A reprovação de Functional web
continua separadamente registrada em `DIAGNOSTICO-FUNCTIONAL-WEB-20261021.md`.
