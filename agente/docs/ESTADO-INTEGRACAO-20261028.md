# Integração do agente: recorte para revisão

Base: main `d6605e4db8043d56e25e0e05adc075f797aa77c9`, incluindo as alterações do backend do Thiago. Este documento é o índice da composição; relatórios anteriores descrevem os commits e ambientes indicados em cada um.

## O que levar neste recorte

- Heartbeat explícito por `id_host` em `/agent/heartbeat`, sem confundir host com usuário do sistema operacional. Origem: PR #64.
- Recibos de auditoria com ambas as contagens obrigatórias, inteiras, únicas e compatíveis com o lote. Resposta ambígua mantém a fila pendente. Origem: PR #63; seus commits originais estão preservados no histórico da composição.
- Diagnóstico de comunicação pelo canal administrativo existente e logs sanitizados, adaptados ao cliente atual. Recorte de #49; não incorpora sua consolidação inteira.
- Ferramentas ApiSmoke e IntegrationSmoke, testes e roteiro de ensaio. O evento Blocked do IntegrationSmoke é sintético: não demonstra bloqueio pelo driver nem inspeção real.
- Workflow exclusivo do agente ampliado para validar os grupos afetados, compilar a interface e exercitar as ferramentas por HTTP sintético. O checkout é limitado ao agente; o workflow funcional do projeto permanece intacto.

Não há alteração de Java, SQL, Angular ou driver contra a base. As implementações locais antigas e incompletas de autenticação/publicação/consultas administrativas não fazem parte deste recorte. A atualização não deve reaplicá-las sobre o backend atual.

## PRs e escopos preservados

| PR | Encaminhamento |
| --- | --- |
| #64 | Centralizar esta composição de comunicação, ferramentas e evidências do agente, mantendo rascunho até revisão e avaliação dos checks |
| #63 | Seu conteúdo e histórico estão incluídos em #64; deixar de disputar integração separada após a publicação conferida |
| #42 | Preservar instalador e homologações; avaliar em recorte próprio |
| #49 | Preservar como inventário congelado de funcionalidades/evidências ainda não extraídas; não integrar em bloco |

Nenhum merge na main, alteração de proteção, reescrita forçada de branch ou exclusão de evidências faz parte desta limpeza.

## Evidências e limites

A revisão local da composição aprovou 152 testes nos oito grupos de cliente, despacho, cache, diagnóstico, logs e tradução C# de política. A primeira execução restrita recusou dois testes do pipe administrativo; a execução com a permissão exigida aprovou todos. A interface WPF compilou em Release, sem erros ou avisos. Isso não qualifica instalação ou driver real.

[Resultado anterior com Java/MySQL](RESULTADO-JAVA-MYSQL-20261028.md) registra persistência, reenvio e falhas controladas no ambiente declarado. [Roteiro da reunião](ROTEIRO-LUCAS-THIAGO-20261028.md) contém os passos do ensaio. Esses resultados têm escopos próprios; não substituem CI da composição publicada nem comprovam exibição no painel.

## Próximos contratos e aceites

1. Política consultável e versionada: a main ainda não disponibiliza a rota que o agente precisa. Aguardar definição conjunta antes de adaptar o consumo.
2. Cadastro repetível com segurança, identidade durável e autenticação individual: ainda pendentes. Não cadastrar automaticamente após timeout.
3. Painel de auditoria e sessão administrativa: ingestão persistida não comprova disponibilidade das consultas ou visualização.
4. Demonstrar interface do agente, inspeção real e ações permitidas/bloqueadas, com evidência do fluxo real. A ferramenta de ensaio não substitui essa demonstração.
5. Validar serviço Windows instalado, driver correspondente e migração de banco existente em aceites separados.
6. Receber os materiais do TC e confirmar o sentido/contrato do heartbeat mencionado na reunião. O heartbeat agente → backend já implementado não resolve automaticamente outro canal.

A tela de políticas permanece dependente da entrega do Luiz; assumir frontend/backend exige confirmar a situação da equipe e tratar o trabalho em recorte separado.
