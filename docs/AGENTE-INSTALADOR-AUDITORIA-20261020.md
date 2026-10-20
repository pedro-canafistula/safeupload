# Evolução: instalador 0.1.1 e envio de auditoria

Branch local: `feat/agente-instalador-20261020`, baseada em `main` `8ed90220e827596d25009e3c80c273f84aa12180`, conferida no remoto nesta rodada. A branch antiga de recuperação Java não foi incorporada. Driver, Java e Angular permanecem sem mudanças nesta rodada.

## Entregas desta rodada

- Instalador: corrigido o controle de rollback no modo FileSystemWatcher. Uma falha em `New-Service` não reivindica o serviço para limpeza; o controle só é marcado após criação bem-sucedida. Isso não constitui suporte a atualização nem garantia de rollback completo. O candidato passa para 0.1.1.
- Auditoria: DTOs explícitos para eventos e justificativas substituem a serialização direta dos objetos locais. O lote inclui versão de esquema, host remetente e versão informativa real do assembly. O heartbeat usa a mesma versão publicada pelo instalador.
- Metadados: preservados ID, horário original em UTC, endpoint, usuário, nome/extensão/tamanho do arquivo, decisão, categorias, processo, destino, política, duração e canal. O nome é reduzido à última parte do caminho.
- Privacidade: nenhum arquivo ou texto extraído é anexado. Trechos locais são excluídos do envio (`maskedSnippets: []`). Destinos web são reduzidos à origem HTTP(S), removendo caminho, credenciais, query e fragmento. Justificativas e outros metadados continuam sujeitos a controle de acesso e retenção.
- Confirmação: contagens ausentes não se tornam zero implicitamente. Isso evita confirmar um lote somente de justificativas quando `acceptedEvents` está ausente.
- Operação offline: usada a fila durável existente; testes comprovam reabertura, preservação de ID/horário, reenvio, limites de lote e confirmação. Não foi criada uma segunda fila nem colocado HTTP no caminho da decisão.
- CI: o workflow de instalador inclui os testes de auditoria/fila e obtém o caminho do instalador a partir de `build-result.json`, eliminando a versão fixa no smoke.
- Documentação: corrigidas limitações antigas no README que ainda diziam não haver cache offline nem envio de justificativas. Criado o [contrato para Thiago](CONTRATO-AUDITORIA-AGENTE.md), com exemplo sintético e aceite conjunto.

## Validação

| Verificação | Resultado |
| --- | --- |
| Contratos do instalador, PowerShell 7 | 39 aprovados |
| Contratos do instalador, Windows PowerShell 5.1 | 39 aprovados |
| Auditoria, confiabilidade, fila e script instalador, xUnit | 41 aprovados; inclui 10 casos novos |
| Suíte completa do agente | 722 aprovados, 7 falhos, 4 ignorados; total 733 |
| Sintaxe dos scripts de instalação e YAML | Aprovada |
| Release win-x64 com runtime incluído, serviço e UI; Inno Setup | Compilados no candidato 0.1.1; evidência no pacote de saída |
| Instalação/desinstalação como LocalSystem em VM/runner | Não executada nesta máquina |
| API Java atual, MySQL e visualização Angular | Não validados nesta rodada |

As sete falhas completas são em testes existentes de symlinks e hand-back com troca de proprietário, por falta de privilégio no Windows deste ambiente: cinco falham ao criar links simbólicos e duas ao atribuir proprietário. São as mesmas classes de falha registradas anteriormente; não foram escondidas nem desabilitadas. Os testes novos passaram. O conjunto focado e a regressão completa foram repetidos após a última mudança dos DTOs, com os resultados da tabela.

Os testes de HTTP usam transporte simulado e fila real em arquivos temporários: validam formato, política de confirmação e recuperação, mas não comprovam interoperabilidade com a API Java. O smoke de instalação continua restrito a um runner Windows descartável e ainda precisa ser executado remotamente. Não houve instalação do serviço nem carregamento de driver neste computador.

O candidato compilado incorpora o commit `478199e1` (após o ajuste de instalador `421220b5`); este relatório é posterior ao código empacotado. O `build-result.json`, manifesto, checksum e logs acompanham o executável na saída `outputs/agent-audit-20261020` do workspace. O pacote é sem assinatura de distribuição e destinado à validação em VM.

## Dependências e prioridades

1. Executar o smoke de instalação/recusa de atualização/remoção e validar UI com usuário comum; testar uma VM sem .NET instalado. Validar com o responsável pelo driver a sequência de semeadura, reinício e manutenção. A instalação em modo watcher não comprova enforcement no kernel.
2. Thiago: confirmar `/agent/events`, `/agent/heartbeat` e `/agent/policy`, nomes/enums e campos adicionais; implementar persistência transacional, deduplicação e visualização administrativa. Executar o cenário integrado de bloqueio/offline/reenvio com dados sintéticos.
3. Definir autenticação e cadastro seguro do agente com identidade persistente, credencial por instalação e rotação, antes de expor a coleta em rede não controlada. Hoje o endpoint é identificado pelo hostname.
4. Consolidar política por endpoint, versão aplicada e confirmação de aplicação no driver M2 com o responsável pelo driver.
5. Fortalecer a fila: proteção/integridade local, limite de leitura em filas grandes, retenção/compactação e comportamento com disco cheio. Evoluir o reenvio com recuo e métricas depois de estabilizar o contrato.
6. Cenários reais dos canais File/Web/Clipboard e E2E de instalação → bloqueio → auditoria → painel. A presença do enum de canal no envio não comprova todos esses cenários.

## Estado de entrega

Commits e branch locais. O conector GitHub confirmou `pull=true` e `push=false` nesta rodada; portanto não houve push, PR remoto nem execução do workflow remoto. Um usuário com escrita no repositório deverá publicar a branch e abrir o PR usando a proposta fornecida. Não houve merge na main, que continua exigindo nova aprovação do usuário. Nenhuma mensagem foi enviada à equipe.
