# Núcleo do agente — estado e restante em 01/11/2026

Levantamento dirigido sobre main `c6409002` e a branch do PR #79; não é auditoria exaustiva nem percentual de conclusão. A main já usa unidades SafeUpload/WinFsp e driver gate após #78. Registros de M2/v18 nas issues antigas são históricos: não descrevem automaticamente o par atual.

| Frente | Já disponível | Restante da nossa parte |
|---|---|---|
| Inspeção e decisão | Motor C#, formatos/categorias suportados, limites, falha clássica versus retenção, vínculo de conteúdo da decisão | Aceite do motor dentro do par atual de unidades/gate e aplicativos reais; regressões específicas conforme surgirem |
| Política | Na main: arquivo local e consumidor remoto legado. No PR #79: consumidor ConsoleByIp, destino, revisão, last-known-good, cache por vínculo, identidade validada antes de provisionar e consulta atual sem fallback | Aceite ConsoleByIp no serviço SYSTEM/FileSystemWatcher aprovado no commit 8513d5a7, com cache protegido e reinício offline. Resta o par WinFsp/gate; comparar implementação de Pedro quando publicada. Issue #44 continua aberta |
| Autorizações | No PR #79: justificativa exige política atual e mesma impressão da inspeção, com reconferência após auditoria; sessão/SID/uso único preservados | Aceite do caminho real de pipe/serviço/unidade, inclusive mudança de política durante a solicitação. Leituras remotas não são transação atômica com publicação |
| Auditoria offline | Na main: fila protegida, autoria, metadados minimizados, confirmação em fluxo, recibos completos, histórico, saúde/integridade/manutenção. No PR #79: limite/prazo da resposta e reenvio idêntico após interrupção | Definir retenção/compactação e relações evento/justificativa antes de qualquer exclusão; ensaio prolongado depois de integração/homologação. Não criar outra fila. Issue #48 |
| Validade dos caches | Neste incremento: política e veredito expiram por tempo decorrido; ajuste do relógio civil não estende validade. Consulta atual ignora o cache; cancelamento não publica snapshot | Regressões do conjunto no CI e aceite instalado quando o componente for usado nos canais. Regra de inspeção dos canais não alterada |
| Distribuição | Instalador e serviço/bandeja disponíveis; checks do pacote são independentes da proteção com driver | Pacote atual em Windows 10/11, usuário comum/login, assinatura, upgrade/repair/rollback com preservação de estado. Issue #45 |

## Dependências concretas

Thiago/equipe: contrato de autenticação/provisionamento/renovação/revogação do dispositivo; identidade persistente não é credencial. Confirmar idPolitica como revisão, semântica de versao, seleção por IP quando muda a rede e confirmação de aplicação no painel. Não implementar endpoints ou ACKs não acordados. Issue #47.

Pedro: comparar o consumidor de política com qualquer código ainda não publicado, sem manter duas autoridades conflitantes. Vitor: usar pacote/versão identificados do par WinFsp/gate e combinar o aceite real, sem modificar kernel/infraestrutura unilateralmente. Issue #46 precisa ser lida à luz de #78.

## Próxima entrega prioritária

O ensaio SYSTEM foi ampliado em um cenário separado para selecionar ConsoleByIp e verificar cache protegido/reinício offline e mudança de política no serviço; sua execução remota foi aprovada no commit 8513d5a7. Próximo aceite: conjunto real com WinFsp/gate, dependente de acesso ao laboratório preparado. O cliente do gate agora recusa mensagens que não representem o escopo completo; kernel/protocolo preservados. Separar claramente recebimento da política, persistência do cache e aplicação nas unidades. A fila e os componentes de comunicação já existem; não precisam ser reconstruídos. Retenção destrutiva, autenticação e atualização de instalação exigem suas definições próprias.

## Validação deste incremento

107 testes focados aprovados, zero falhas/ignorados: caches, tempo decorrido, cancelamento, leitura atual, vínculo de política e justificativas. Não somar com recortes anteriores, que se sobrepõem. Testes usam relógio controlado, sem alterar o relógio do Windows. Os grupos de cache passam a ser exigidos no workflow de recibos. Não houve VM ou novo ensaio pesado local.

[PR #79](https://github.com/pedro-canafistula/safeupload/pull/79) continua separado da main; resultados remotos devem ser conferidos no commit exato. [Política e integração](POLITICA-CENTRAL-20261101.md).
