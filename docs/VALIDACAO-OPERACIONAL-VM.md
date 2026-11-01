# Validação operacional do SafeUpload na VM

## Estado e autorização

Preparação em 14/10/2026. Nenhuma instalação ou alteração da VM foi realizada por este plano. Testes de integração anteriores aprovados na base 612498f9 com alterações locais; não equivalem à qualificação do driver.

Alvo exclusivo: SafeUpload-Win10-Lab, UUID 05e087d7-f74d-48f6-804e-474da84e0a9c, Windows 10 Pro 22H2 19045.3803. Nunca executar instaladores no host. Não modificar branch, publicar PR ou substituir trabalho dos colegas nesta etapa.

## Gate do responsável pelo driver

Antes de instalar, registrar a resposta do Victor para todos estes itens:

- A build 19045.3803 é aceita ou é necessário outro Windows 19045.2965 em VM separada?
- Qual pacote exato de driver deve ser usado: versão/commit, SYS, INF, CAT, manifesto de hashes e assinatura/certificado esperado?
- Qual versão/commit do agente é compatível? A integração baseada em 612498f9 pode ser aplicada sobre esse par, ou requer adaptação?
- Qual roteiro atual de instalação, política inicial, modo de interceptação e recuperação deve ser seguido?
- Há requisitos de assinatura de teste/boot? Não alterar proteções automaticamente: avaliar separadamente, apenas em VM descartável, com autorização explícita.

Não escolher um pacote pelo nome mais recente. DEPLOY.md contém uma abertura sobre escrita em estágio e seções posteriores sobre fluxo legado; não misturar seus pressupostos de fail-open/fail-closed. O instalador atual do agente exige driver previamente instalado e prepara política de boot como SYSTEM antes de permitir boot-start. A ordem exata deve ser revisada com o pacote recebido; não executar parcialmente nem reiniciar no meio.

## Preparação antes da instalação

1. Preservar ZIPs e hashes de evidências; manter a revisão anterior e as ferramentas portáteis.
2. Confirmar identidade da VM, espaço livre e funcionamento do console. Não usar dados ou credenciais de produção.
3. Desligar normalmente o Windows convidado e criar um snapshot novo, identificado como anterior à instalação operacional. Registrar nome/UUID, data e estado. Não restaurar nem apagar snapshots existentes sem autorização.
4. Manter rede desconectada, clipboard/drag-and-drop e pastas compartilhadas desativados. Não criar bridge nem encaminhamento de portas.
5. Após aprovação do pacote, verificar hashes e assinatura contra a informação recebida por canal confiável, sem executar arquivos apenas para inspecioná-los.
6. Fixar a revisão do código e seu diff junto às evidências. Um commit base sozinho não identifica alterações locais.

Snapshot e verificações acima estão planejados, não realizados por este documento.

## Topologia

Começar em uma VM com backend em loopback e dados sintéticos, se suportado pela configuração aprovada. Não usar o endereço de painel distribuído em appsettings sem revisão. AdminBaseUrl vazio mantém política local; uma URL configurada muda a origem/fallback da política. Definir explicitamente política, escopos e versão antes do teste.

Uma segunda etapa poderá usar duas VMs (agente e gestão) em rede interna isolada, sem bridge, NAT ou portas para o host. Confirmar endereços, autenticação e firewall antes de conectar; não tratar o sucesso em loopback como validação entre máquinas.

A tela de políticas ainda requer integração própria. Não declarar publicação ponta a ponta nem usar valores simulados como evidência de política aplicada.

## Matriz de testes após liberação

| ID | Cenário | Critério e evidência |
| --- | --- | --- |
| OP-01 | Instalação e primeiro boot | Versões/hashes registrados; serviço e filtro no estado esperado pelo roteiro; política de boot e proteção confirmadas após reinício, não apenas processo ativo. |
| OP-02 | Heartbeat e identificação | Endpoint, versão do agente e política coincidem entre agente, API e painel; guardar resposta sem segredos. |
| OP-03 | Arquivo permitido | Operação sintética permitida e evento coerente, com ID correlacionável; sem alteração de conteúdo. |
| OP-04 | Arquivo bloqueado/retido | Resultado corresponde à política e ao modo aprovado; retenção não é confundida com exclusão ou quarentena. |
| OP-05 | Clipboard Audit | Cópia/foco real em sessão comum produz observação, não prova de colagem/bloqueio; nenhum texto copiado na auditoria. |
| OP-06 | Backend indisponível | Gerar conjunto identificado de eventos com backend parado; fila preservada. Ao retornar, mesmos IDs, sem perda ou duplicação. |
| OP-07 | Reinício do agente | Repetir verificação de fila/IDs após reinício permitido pelo roteiro. Não parar serviço no meio de escrita sem cenário aprovado. |
| OP-08 | Uso cotidiano | Salvar, renomear e mover dados sintéticos dentro/fora do escopo; arquivo acima do limite conforme política; registrar tempos e resultado, sem prometer limite não definido. |
| OP-09 | Reinício do Windows | Boot concluído, política persistida, serviço/filtro saudáveis e heartbeat recuperado. |
| OP-10 | Recuperação | Evidências exportadas antes de restauração; recuperação apenas no snapshot correto e após autorização. |

Os quatro testes ignorados de políticas de navegador/filtro de rede/CA são uma etapa separada, com snapshot, revisão do código e aprovação específica. Não ativar SAFEUPLOAD_MACHINE_TESTS globalmente.

## Registro e condições de parada

Cada cenário deve registrar data UTC, revisão e diff, hashes do pacote, build, snapshot, modo/política, pré-condições, ação, resultado esperado/obtido, IDs de eventos e localização dos logs. Usar estados PENDENTE, APROVADO, FALHOU ou BLOQUEADO; não presumir aprovação pela ausência de erro.

Parar diante de assinatura/hash divergente, incompatibilidade de versão, falha de política de boot, tela azul, travamento, perda de dados sintéticos, bloqueio fora do escopo ou exposição de conteúdo copiado. Não repetir instalação nem desabilitar proteção para contornar falha. Preservar logs/dump disponíveis e consultar Victor antes de restaurar ou alterar configuração.

## Liberação pendente

- Confirmação do Victor: PENDENTE.
- Pacote e compatibilidade verificados: PENDENTE.
- Snapshot operacional criado: PENDENTE.
- Instalação e cenários OP-01 a OP-10: NÃO EXECUTADOS.
