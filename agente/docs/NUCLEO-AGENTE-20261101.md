# Núcleo do agente — estado e restante em 01/11/2026

Levantamento dirigido sobre main `c6409002` e a branch do PR #79; não é auditoria exaustiva nem percentual de conclusão. A main já usa unidades SafeUpload/WinFsp e driver gate após #78. Registros de M2/v18 nas issues antigas são históricos: não descrevem automaticamente o par atual.

| Frente | Já disponível | Restante da nossa parte |
|---|---|---|
| Inspeção e decisão | Motor C#, formatos/categorias suportados, limites, falha clássica versus retenção, vínculo de conteúdo da decisão | Aceite do motor dentro do par atual de unidades/gate e aplicativos reais; regressões específicas conforme surgirem |
| Política | Na main: arquivo local e consumidor remoto legado. No PR #79: consumidor ConsoleByIp, destino, revisão, last-known-good, cache por vínculo, identidade validada antes de provisionar e consulta atual sem fallback | Aceite ConsoleByIp no serviço SYSTEM/FileSystemWatcher aprovado no commit 8513d5a7, com cache protegido e reinício offline. Resta o par WinFsp/gate; comparar implementação de Pedro quando publicada. Issue #44 continua aberta |
| Autorizações | No PR #79: justificativa exige política atual e mesma impressão da inspeção, com reconferência após auditoria; liberação automática em modo auditoria exige inspeção concluída e a mesma política atual; sessão/SID/uso único preservados | Aceite do caminho real de pipe/serviço/unidade, inclusive mudança de política durante a solicitação. Leituras remotas não são transação atômica com publicação |
| Auditoria offline | Na main: fila protegida, autoria, metadados minimizados, confirmação em fluxo, recibos completos, histórico, saúde/integridade/manutenção. No PR #79: limite/prazo da resposta e reenvio idêntico após interrupção | Definir retenção/compactação e relações evento/justificativa antes de qualquer exclusão; ensaio prolongado depois de integração/homologação. Não criar outra fila. Issue #48 |
| Validade dos caches | Neste incremento: política e veredito expiram por tempo decorrido; ajuste do relógio civil não estende validade. Consulta atual ignora o cache; cancelamento não publica snapshot | Regressões do conjunto no CI e aceite instalado quando o componente for usado nos canais. Regra de inspeção dos canais não alterada |
| Distribuição | Instalador e serviço/bandeja disponíveis; checks do pacote são independentes da proteção com driver | Pacote atual em Windows 10/11, usuário comum/login, assinatura, upgrade/repair/rollback com preservação de estado. Issue #45 |

## Dependências concretas

Thiago/equipe: contrato de autenticação/provisionamento/renovação/revogação do dispositivo; identidade persistente não é credencial. Confirmar idPolitica como revisão, semântica de versao, seleção por IP quando muda a rede e confirmação de aplicação no painel. Não implementar endpoints ou ACKs não acordados. Issue #47.

Pedro: comparar o consumidor de política com qualquer código ainda não publicado, sem manter duas autoridades conflitantes. Vitor: usar pacote/versão identificados do par WinFsp/gate e combinar o aceite real, sem modificar kernel/infraestrutura unilateralmente. Issue #46 precisa ser lida à luz de #78.

## Fechamento da primeira versão do núcleo

O alvo é um agente pronto para integrar: inspeção/decisão, política válida e last-known-good, fila offline/recibos, autorização vinculada a uma versão, serviço/bandeja e diagnóstico local. Não reconstruir esses componentes nem abrir novas funcionalidades para encerrar essa entrega. O PR #79 reúne o código ainda separado da main; fechamento exige revisar/consolidar esse PR e conferir os checks do SHA final. A regra do repositório também exige aceite na VM para chamar a mudança de concluída; testes isolados não substituem esse aceite.

Diagnóstico próprio entregue neste incremento: `Get-SafeUploadDiagnostics.ps1 -Query policy-status`, no pipe administrativo existente. Distingue última política devolvida em `LoadAsync`, última consulta atual bem-sucedida, revisões remotas validadas/cache gravado/cache lido e último escopo aceito pelo transporte do gate. Falha/cancelamento da consulta atual preserva o último sucesso como histórico, sem torná-lo autoridade. Os marcos são independentes e reiniciam com o processo; não são um inventário atual do disco ou confirmação de proteção. A consulta não faz I/O, não inicia driver e não envia ACK ao backend. Não expõe destinos, URL, identificação do host ou conteúdo de política.

A instrumentação observa os provedores existentes e mantém a consulta atual separada do snapshot clássico. A composição do serviço mantém o comportamento anterior dos consumidores: no modo remoto, o clipboard continua sem um segundo cache periódico; suas regras de inspeção não mudaram.

Retenção automática destrutiva permanece desabilitada na primeira versão, com monitoramento/preview somente leitura já disponíveis. Definir sua regra é evolução operacional da issue #48; não é motivo para criar outra fila ou apagar pendências para declarar conclusão. Autenticação de dispositivo, confirmação no painel e contrato de seleção por IP são integrações conjuntas da issue #47, não APIs a inventar no núcleo.

## Validação e limite do fechamento

101 testes focados aprovados, zero falhas/ignorados: diagnóstico, política central, snapshot/consulta atual, gate, comunicação, caches e pipes. Cliente de suporte: 27/27 em PS7.6.5 e 27/27 em PS5.1.26100.9711. Build Release da interface e dependências: zero erros/avisos. O grupo PolicyDiagnosticsTests passa a ser exigido no workflow de recibos. Não houve instalação local de serviço/driver, montagem WinFsp ou ensaio pesado novo.

Checkpoint remoto anterior: todos os workflows do commit `87c55205` aprovados, incluindo recibos, instalador e contrato/serviço SYSTEM. No commit `3c3f57de`, os cenários de serviço SYSTEM e ConsoleByIp já foram aprovados; conferir os demais checks e o novo HEAD separadamente. Esses cenários usam FileSystemWatcher, após gravação, não qualificam prevenção pelas unidades.

A main remota ainda está em `c6409002` (#78, Vitor/Victor); o fetch de 01/11 não trouxe commit posterior do driver. O aceite do par identificado WinFsp/gate continua sendo o próximo trabalho de integração: decisão versus publicação efetivamente concluída, erros, reconexão, justificativa por versão e Office/USB/SMB. Não tratar o sinal de solicitação/aprovação como prova de cópia final concluída. Acesso ao laboratório preparado e pacote atual são necessários. Windows 10/11, assinatura e upgrade/repair/rollback continuam no aceite de distribuição da issue #45. Não declarar produto inteiro finalizado antes desses aceites.

[PR #79](https://github.com/pedro-canafistula/safeupload/pull/79) continua draft, sem merge para main. [Política e integração](POLITICA-CENTRAL-20261101.md).
