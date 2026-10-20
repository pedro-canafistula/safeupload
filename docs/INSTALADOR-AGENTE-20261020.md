# SafeUpload — instalador do agente, 20/10/2026

**Resultado:** candidato de instalador Windows `.exe`, versão 0.1.0, com serviço, interface de bandeja, runtime próprio, atalhos, inicialização da interface e desinstalador. É uma entrega para validação, sem assinatura da equipe e ainda sem teste completo de instalação em Windows descartável.

Branch local: `feat/agente-instalador-20261020`, criada sobre a main `8ed90220`. Este trabalho não incorpora as correções Java da branch de recuperação anterior. Não altera API web, painel Angular, lógica C# de inspeção, driver ou arquivos de referência em `sources/`. A API permanece sob responsabilidade de Thiago.

## O que foi acrescentado

- Empacotamento reproduzível em `agente/installer`, compilando serviço e UI separadamente para `win-x64`, com .NET incluído e símbolos de depuração excluídos.
- Compilador Inno Setup 6.7.3 oficial, com hash fixado e assinatura Pyrsys verificados, extraído em modo portátil no diretório de ferramentas. Documentação e origem estão no [manual](../agente/installer/README.md).
- Seleção explícita entre minifiltro já instalado/parado e modo de teste sem driver. A sequência original de preparação como SYSTEM e ativação após reboot foi preservada; o pacote não instala ou carrega driver e não altera assinatura de drivers.
- URL opcional de administração, sem credenciais/query/fragmento. Servidor remoto exige HTTPS; loopback permite HTTP para testes. URL vazia força operação local. TLS/proxy/CA permanecem desligados.
- Serviço LocalSystem com SID irrestrito e executável entre aspas; verificação da configuração registrada. A interface inicia na sessão do usuário e a abertura opcional após setup não usa o token elevado.
- Verificação de integridade dos 724 arquivos do payload, validação de caminhos e recusa de links, junções, manifestos adulterados, diretório gravável por usuário comum, instalação anterior ou startup conflitante.
- Remoção apenas do serviço e startup pertencentes a essa instalação. Dados do endpoint, cache, auditoria, escopos e quarentena são preservados. Um driver ativo ou ainda habilitado bloqueia a remoção do agente.
- Workflow separado para compilar e instalar/remover silenciosamente em runner Windows descartável. O smoke possui uma trava que recusa execução fora desse ambiente e recusa qualquer estado SafeUpload preexistente.

## Evidências executadas nesta máquina

| Verificação | Resultado |
| --- | --- |
| Contratos PowerShell 7.6.5 | 39/39 aprovados |
| Contratos Windows PowerShell 5.1 | 39/39 aprovados |
| Testes xUnit existentes `InstallSafeUploadAgentScriptTests` | 6/6 aprovados |
| Publicação Release do serviço, self-contained | Aprovada |
| Publicação Release da UI WPF, self-contained | Aprovada |
| Compilação do instalador Inno Setup | Aprovada |
| Parser dos scripts e do YAML | Aprovados |
| Instalar o agente no computador de trabalho | Não executado |
| Smoke de instalação/desinstalação no GitHub | Preparado, não executado |
| Instalação com driver, reboot e enforcement | Não executados |

Os testes PowerShell usam arquivos temporários reais para integridade e estados simulados para decisões sobre driver/serviço. Eles não comprovam que o SCM e o driver executam o fluxo completo. O teste xUnit é o teste existente do script técnico; a suíte geral do agente não foi repetida por não haver mudança na lógica C#.

O manifesto e `build-result.json` registram o commit efetivamente empacotado, alterações locais, quantidade de arquivos e hash do `.exe`. Acompanhe o checksum `.sha256` entregue junto do executável. Logs, runtimes publicados e binários ficam fora dos commits.

## Limites e próximos critérios de aceite

1. Executar o workflow de instalação inicial, recusa de atualização e remoção com preservação de dados. Validar também uma VM limpa sem SDK/runtime .NET previamente instalado.
2. Validar UI/clipboard e notificações com usuário comum, fechamento da bandeja e remoção com arquivos em uso.
3. Com o responsável pelo driver, testar a sequência de instalação, política de boot, reinício, falha de semeadura e manutenção antes da remoção. O modo sem driver não comprova bloqueio no kernel.
4. Definir upgrade, reparo e rollback de versão existente. Esta primeira versão recusa essas instalações; não faz upgrade silencioso nem promete rollback completo de mudanças do driver. Falhas de configuração podem deixar arquivos de diagnóstico/desinstalador, mas são reportadas como erro e tentam remover o serviço recém-criado.
5. Assinar o pacote com o certificado da equipe antes de distribuição de produção. A assinatura do compilador foi verificada; isso não assina automaticamente o instalador do SafeUpload.
6. Alinhar URL, contratos e autenticação de máquina com Thiago. O instalador configura o agente; não muda ou comprova compatibilidade da API Java.

Não foi feito push, aberto PR remoto, enviado comunicado à equipe ou realizado merge na main. O acesso GitHub disponível na rodada anterior era de leitura; a entrega é local, com branch e bundle para revisão. O merge continua exigindo aprovação do usuário.
