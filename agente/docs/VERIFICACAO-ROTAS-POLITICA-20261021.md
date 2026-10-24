# Verificação da implementação de políticas — 21/10/2026

## Conclusão

Há implementações relacionadas, mas **o fluxo de publicação seguida de consulta pelo agente não está disponível no código atual da main**. A main usa publicação com tentativa de envio direto ao host. A branch de Luiz tem publicação e consulta, porém a consulta do agente devolve configuração fixa. Uma implementação anterior de publicação e leitura por endpoint existe no histórico, mas foi removida/substituída.

O usuário pediu verificar o repositório antes de perguntar à equipe. Nenhuma pergunta ou mensagem foi enviada. A dependência fica registrada; o agente mantém seu contrato atual, sem abrir um listener para acomodar um contrato presumido.

## Método e referências

As referências remotas foram atualizadas com fetch. Foram pesquisadas 27 referências origin, com busca nos fontes Java dos caminhos de backend e inspeção manual dos controllers, serviços, DTOs e histórico relevantes. Testes, documentação e strings em frontend não foram tratados como prova de rota implementada. Nenhum backend foi executado ou modificado.

| Referência | Commit inspecionado |
|---|---|
| main | `efe93cf75aa668f2870c0951b48b3ef2c6332226` |
| develop-luiz-avanco-telas | `e8afeb4d84df5a5e14f57c9392438e7eec7073a0` |
| api-web-heartbeat | `7766bb3cc262609cb999f77fd3bf1befe0d34ff3` |
| feat/publicacao-politicas | `9b7a29f8e1a09e65e37a08fb6c2fc2042898d3e6` |

O pacote local contém a lista de referências/commits e os resultados brutos da pesquisa. Esses resultados descrevem o código publicado no Git, não o estado de eventual servidor externo.

## Main atual: publicação por envio ao host

`AdminController` implementa `POST /admin/policy/set`. `AdminService.setPolicy` chama `enviarPolitica` **antes** de salvar as regras/política. Esse método monta `http://{destino.ip}:8426/receive/politica` e executa POST com o documento administrativo. Se esse envio lançar erro, o método não prossegue normalmente para as gravações subsequentes.

Fontes: [controller da main](https://github.com/pedro-canafistula/safeupload/blob/efe93cf75aa668f2870c0951b48b3ef2c6332226/web/back/src/main/java/com/safeupload/presentation/controller/AdminController.java), [serviço de publicação](https://github.com/pedro-canafistula/safeupload/blob/efe93cf75aa668f2870c0951b48b3ef2c6332226/web/back/src/main/java/com/safeupload/application/AdminService.java).

O controller do agente na main usa `/agent/api`, com synchronize, heartbeat, empresa/list e tickets. Não contém GET policy. Não foi encontrada implementação de `GET /agent/api/policy` nem de `GET /agent/policy` nos controllers atuais dessa main. O C# continua consultando `policy?endpointId=...` sob BaseUrl `/agent/`; não há listener `8426/receive/politica` em `agente/`.

O DTO administrativo usa `versao`, `nome`, `destino.ip`, `acao` e `regras`; não equivale automaticamente ao documento de inspeção com `version`, `activeCategories`, `monitoredScopes` e `clipboard`. Não mudar somente a URL ou alimentar o cache com esse DTO.

A análise inicial havia identificado a ausência do GET, mas não tinha registrado a tentativa ativa de envio ao host. Este checkpoint complementa e corrige essa lacuna.

## Branch de Luiz: endpoints existem, mas não estão ligados ao consumo

`PoliticaController`, em `develop-luiz-avanco-telas`, implementa POST `/api/politicas` e GET `/api/politicas` ou `/api/politicas/ativa`. O serviço salva uma política ativa no repositório e permite recuperá-la.

Entretanto, `AgentController` expõe `/agent/policy` chamando `AgentService.policy()` sem parâmetro de endpoint. Esse método retorna `new Policy(1, ...)` com configuração fixa. Ele não consulta `PoliticaService` nem a política salva. Portanto, encontrar a rota não comprova que o agente receba o que foi configurado pelo painel. O formato administrativo dessa branch também é próprio, com `categoriasMonitoradas`, `extensoesMonitoradas` etc.

Fontes: [publicação da branch de Luiz](https://github.com/pedro-canafistula/safeupload/blob/e8afeb4d84df5a5e14f57c9392438e7eec7073a0/web/back/src/main/java/com/safeupload/presentation/controller/PoliticaController.java), [resposta fixa ao agente](https://github.com/pedro-canafistula/safeupload/blob/e8afeb4d84df5a5e14f57c9392438e7eec7073a0/web/back/src/main/java/com/safeupload/application/AgentService.java).

## Implementação anterior por endpoint

Em `feat/publicacao-politicas`, `PolicyController` implementa publicação/listagem em `/api/politicas`; `AgentController` implementa `/agent/policy?endpointId=...`; `PolicyService` salva um `PublishedPolicy` por endpoint, incrementa sua versão e recupera o documento correspondente. O heartbeat registra o endpoint antes da publicação. A implementação possui limites próprios: por exemplo, parte dos parâmetros é derivada de defaults e não representa um publicador arbitrário de todo o JSON das imagens.

Fonte: [serviço histórico](https://github.com/pedro-canafistula/safeupload/blob/9b7a29f8e1a09e65e37a08fb6c2fc2042898d3e6/web/back/src/main/java/com/safeupload/application/PolicyService.java).

**Essa branch já integra o histórico da main**, conforme a verificação de ancestralidade. Portanto, não é correto descrevê-la simplesmente como trabalho que nunca foi integrado. O commit `3ca1be4f2fd87806230b6863e05ca0479f8c2ab8` excluiu os controllers/serviço de publicação anteriores; `f2112c6fcb155238c6bab3ce54402bfbf09c46a0` introduziu o fluxo administrativo com envio ao host, e mudanças posteriores compõem o backend atual.

A branch `api-web-heartbeat` possui um commit histórico chamado “Finalização de endpoint de política”, mas seu tip `7766bb3c` remove `web/back`. Nome de commit/branch não comprova a existência atual do endpoint. Não restaurar backend, fazer cherry-pick ou resolver essa divergência fora do escopo do agente.

## Próximos passos do agente

- Manter consulta HTTP de saída e cache/fila existentes; aguardar um contrato consultável em versão da API que a equipe entregue.
- Não implementar automaticamente receptor HTTP na porta 8426, nem traduzir DTO administrativo em política efetiva sem contrato.
- Não enviar a pergunta anterior sobre a existência da rota: o repositório já responde essa parte. Questões de produto/contrato permanecem registradas para quando forem necessárias à implementação.
- Continuar verificações do agente que independem da API. Nesta rodada, foram acrescentados quatro controles de HTTP real para 401, 403, JSON inválido e recibo sem a contagem de justificativas.
- Quando houver uma nova versão do backend para integração, reinspecionar a fonte publicada e executar os controles contra o ambiente correspondente, sem presumir que uma branch histórica seja o ambiente da equipe.

## Entrega e validação C# desta rodada

Os quatro novos casos usam o servidor TCP sintético em loopback já existente. O agente envia evento e justificativa, recebe uma resposta recusada/inválida, reabre a fila, confirma que ID/horário sobreviveram e reenvia o mesmo corpo HTTP. Somente um recibo completo permite confirmar ambos os registros.

| Verificação | Resultado |
|---|---|
| Recorte Debug de HTTP/auditoria/dispatcher/política | 53 aprovados, 0 falhos, 0 ignorados |
| Suíte completa Release | 731 aprovados, 7 falhos, 4 ignorados; total 742 |

Os sete nomes falhos foram comparados com o checkpoint anterior. Persistem os mesmos erros de privilégio de symlink/proprietário no Windows; os quatro testes ignorados seguem existentes, sem novos skips. A suíte completa permanece reprovada neste ambiente. Logs e TRX acompanham o patch. Instalação, SYSTEM, driver, API real e persistência Java/MySQL não foram validados nesta rodada.

Somente testes C# e documentação do agente foram alterados. Scripts e produto não mudaram, portanto os controles PowerShell e instalação não foram repetidos. Não houve publicação no GitHub ou merge. A macro permanece aberta.
