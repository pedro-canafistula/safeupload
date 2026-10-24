# Homologação Windows 10 — agente 0.1.7

Candidato de fonte `39290c98609d154488d368dbf85b92f6744774e6`, Windows 10 Pro 22H2 (19045.3803), PowerShell 5.1. Ensaio em 22/10/2026, aproximadamente 19:40–19:54 (Brasília). Executado exclusivamente no clone `3a9992db-4644-405c-b642-9766edd10650`, sem rede, pastas compartilhadas ou driver. VM original e host não receberam instalação.

Instalador self-contained: `SafeUploadAgent-0.1.7-win-x64-setup.exe`, SHA-256 `663B0FF9AD31A1DF0DF6896A2598E16C00C9C545B8D6F6FEAA1EF1A49347E756`. Os 724 arquivos instalados foram comparados individualmente com o manifesto do artifact do [CI 39864662531](https://github.com/pedro-canafistula/safeupload/actions/runs/39864662531). Pacote sem assinatura digital. A versão 0.1.6 havia sido removida: este ensaio foi instalação sobre dados preservados, não atualização em lugar de uma instalação ativa.

## Aceite e evidências

- [x] Instalação 0.1.7 em FileSystemWatcher; serviço Running/LocalSystem, sem URL de API configurada; política e fila inicial de nove eventos preservadas byte a byte.
- [x] Diagnóstico administrativo real: saudável → degradado → saudável. Bloqueio temporário de compartilhamento da fila gerou falha WriteEvent/HRESULT -2147024864, contador 0 → 1 → 1, registros Windows 3101 e 3102 sem nome/caminho de arquivo, conteúdo ou conta. A liberação ocorreu em finally; a fila manteve o hash original durante a recusa.
- [x] Texto limpo de recuperação: 39 bytes, Approved e décimo evento persistido.
- [x] Novo CPF sintético: 28 bytes, Blocked no contrato, RESTRITO no painel, categoria CPF e trecho mascarado; aviso observado, origem ausente e arquivo correspondente localizado na quarentena. Histórico atualizado automaticamente para onze eventos únicos, preservando os nove anteriores.
- [x] Parada do serviço: painel mostrou “Serviço indisponível”. Reinício mudou PID 4212 → 2516, mantendo a mesma UI PID 1152/data de criação. Reconexão automática e onze eventos pelo pipe de usuário não elevado; hashes da política/fila intactos. Contadores de saúde reiniciaram em zero, como previsto para estado em memória por processo.
- [x] Reinício do Windows e login realizado pelo usuário: serviço LocalSystem PID 2904; UI PID 6476 iniciada por Explorer PID 4460, 14.978 ms após o Explorer. Nenhum lançamento manual do executável nesta etapa. A bandeja foi usada para mostrar o painel, com onze eventos e sem repetição de aviso antigo nas observações realizadas.
- [x] Desinstalação: saída zero, serviço/registro/startup/UI/executáveis ausentes. Política, fila de onze eventos e arquivo em quarentena preservados byte a byte. Registro Inno termina com “Removed all? Yes”; as tentativas iniciais de remover diretórios não vazios (145) foram resolvidas pelo próprio desinstalador.

Os recibos brutos, roteiros usados, logs e quatro capturas estão em [evidencias/homologacao-win10-017-20261022](evidencias/homologacao-win10-017-20261022/). `resumo.json` relaciona SHA-256 de cada evidência; JSON/log preservam os bytes recebidos. `conferencia-ui.json` registra a conferência externa, separada dos campos pending dos roteiros. Estes últimos não foram reescritos para simular uma observação que o processo não fez.

O primeiro roteiro encerrou exclusivamente por tempo de espera da conferência visual, após instalar e conferir os 724 arquivos, antes de injetar falha. A retomada exigiu exatamente esse estado anterior, hashes preservados e serviço ativo; prosseguiu sem reinstalar. A espera seguinte foi ampliada para 30 minutos. Autorizações de elevação e login foram feitas pelo usuário.

## Preservação

| Dado | SHA-256 após os testes e após remover |
| --- | --- |
| Política | `16979B6447FE37E98270729DEEAAFC5BA741AC4509BEF9730B2F11FFB093D90F` |
| Fila com onze eventos | `DFD11C3D42F5D236E7248B267F0383BE4B84ACD90B4C12CD17B15C61143F4AAF` |
| CPF sintético em quarentena | `605A58E33E73F44BEC1E10A8B7C842A4805BB353A2544005FAFC53F2445A2E81` |

A fila inicial tinha SHA-256 `CFCAE771B1ACC370A10850853FF18103C780C3A2D69512253D4832C87C09C9EB`. Mudou apenas pelas duas gravações bem-sucedidas do ensaio: recuperação e CPF posterior. A ocorrência criada enquanto a fila estava ocupada **não foi persistida nem recuperada**; observabilidade não equivale a durabilidade. Não se atribui perda dos nove eventos anteriores a essa falha induzida.

## Limites e dependências

O watcher inspeciona após a escrita e pode mover o arquivo para `C:\SafeUpload\_bloqueados`; não demonstra bloqueio preventivo de upload. Modo da política v1 permanece em auditoria. A saúde da fila é exposta no diagnóstico administrativo/log do Windows; não há aviso de saúde adicionado à interface nesta versão.

Sem validação de API real/publicação de política, autenticação remota ou driver M2 neste clone. As dependências já registradas em #44/#46/#47 permanecem; não se implementou backend. Java, Angular, banco e driver não foram alterados. O workflow functional-web conserva a falha previamente documentada na base; esta homologação não o torna aprovado.

Continuam em #48: corrupção silenciosa, queda de processo/energia, volume realmente cheio, vários dias de operação, retenção/compactação e estratégia de durabilidade para escritas recusadas. A classificação disk_full foi coberta por teste sintético, não por enchimento do disco. Em janela inicial de 960 px observaram-se textos/colunas comprimidos; maximizar permitiu a conferência. Ajuste de layout permanece oportunidade separada, sem correção nesta entrega.

PR #49 permanece em rascunho, sem merge. Os testes de C# e PowerShell do candidato já aprovados no CI não foram repetidos para esta entrega exclusivamente documental.
