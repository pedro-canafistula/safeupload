# Entrega incremental do agente — 30/10/2026

Esta candidata reúne o PR #64 à main 6e4ec708 e ao recorte de instalador preparado a partir de #42/#49. A autorização de Lucas para organizar os PRs e levar as alterações importantes à main foi dada em 30/10. Integração só deve ser registrada como concluída após merge efetivo e conferência da main.

## Conteúdo selecionado

- Comunicação, identidade persistente, recibos de auditoria e Status do #64, preservando o histórico publicado até 03a64d07.
- Dois fatos descobertos de identidade SYSTEM, um para provisionamento e outro para recuperação em processo distinto, com comprovantes por fase. Origem: incremento local 5ea3b5e5, apenas os dois arquivos do teste/helper; os scripts do driver não entram aqui.
- Instalador: dez arquivos de #42/9f608153, correção de remoção com UI aberta de #50/135369df, verificador estático de pacote de #49/3dd9a573 e adaptações delimitadas da preparação de 25/10. Versão candidata 0.1.15. Checkout do workflow fixa o HEAD e só materializa o agente. Configuração de URL não provisiona identidade nem seleciona o novo protocolo automaticamente.
- Relatório semanal de 26–30/10 para repasse à equipe.

Não foram importados: a projeção HTTP de metadados de #42/#49, histórico/quarentena, alterações da fila/diagnósticos M2, os 857 arquivos de evidências de #49, a candidata de política fac86227 nem a composição com o driver 5ea3b5e5. Permanecem nas fontes originais e no acompanhamento da macro #43. Não remover branches ou evidências ao encerrar os PRs antigos.

O recorte não altera Java, Angular, banco ou driver em relação à main. As atualizações desses componentes no histórico vêm exclusivamente do merge da main existente.

Atualização posterior: Lucas autorizou corrigir testes/CI e, ao constatar lacunas reais, os reparos mínimos de backend/banco. Portanto a afirmação acima descreve apenas o checkpoint 2e4a621a. A rodada seguinte restaura a tabela de auditoria e acrescenta consultas administrativas protegidas; ver REPAROS-INTEGRACAO-BACKEND-20261030.md. Angular de produção, driver, cadastro, heartbeat e publicação de política continuam preservados.

## Verificação deste recorte

Contratos do instalador: 41/41 no PowerShell 7 e 41/41 no Windows PowerShell 5.1; ambiente/helper: 4/4. Nenhum desses testes instala o produto. Recorte C# local: 298 aprovados, duas falhas de preparação de diretórios com links simbólicos por privilégio ausente, zero ignorados em 300. O resultado não foi convertido em aprovação nem repetido por tentativa. O runner descartável precisa validar essa composição e o instalador completo, com manifesto e hashes próprios.

O histórico do #64 já contém aceites isolados de identidade/heartbeat/recuperação com Java/MySQL e tela conectada ao serviço. São da fonte/ambiente registrados, anteriores a esta composição. Não equivalem a homologação do novo pacote nem a proteção pelo driver.

## Impedimentos conhecidos para merge

Functional web executa três contratos incompatíveis com a main atual: a fixture Java não fornece EmpresaRepository exigido pelo controller; a inicialização usa spring.datasource quando o backend exige app.datasource/acesso.datasource; a prontidão e os ensaios antigos dependem de /agent/policy, rota ausente. O contrato atual GET /agent/api/policy não é substituto automático desse contrato legado. Logs do #64 em 03a64d07 confirmam as três falhas. Não desativar checks, aceitar 404 como prontidão ou introduzir fallback de política para obter aprovação.

Lucas havia delimitado o trabalho a C#/.NET e recusado a execução da proposta Java/CI de outras frentes em 26/10. A solicitação atual autoriza integrar os PRs, mas não torna uma falha externa aprovada. A correção compartilhada deve ser alinhada com os responsáveis ou ter seu escopo explicitamente autorizado antes de aplicar mudanças fora do agente. Até resolver isso, registrar a candidata como preparada, sem declarar a main atualizada.

Essa autorização foi concedida explicitamente na continuidade de 30/10, inclusive para backend/banco. Não foi concedida dispensa de checks: a integração permanece condicionada ao resultado revisado. Os roteiros atuais distinguem consulta de política na API de aplicação/cache no agente, que seguem pendentes.
