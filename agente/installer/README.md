# Instalador do agente Windows — candidato de desenvolvimento

Base do instalador integrada na main pelo #64, com origem nos #42/#49 e correção de remoção com UI aberta da issue #50. Recortes posteriores integraram auditoria/recibos, diagnóstico da fila, histórico e manutenção. O builder usa 0.1.18 por padrão; `-Version` identifica cada candidata posterior. O manifesto e `build-result.json` identificam versão, commit, alterações locais e hashes efetivamente empacotados. Os exemplos abaixo usam a versão padrão, sem selecionar o pacote mais recente. Consulte o resultado do workflow no commit exato antes de executar uma instalação de teste.

Atualização/reversão/recuperação manuais foram entregues no #102, com aceite Windows 10 no modo sem driver. Esse aceite não se transfere a todo build posterior nem qualifica assinatura, Windows11 ou o par driver/WinFsp. Uma URL isolada não provisiona o dispositivo: use a [composição atual](../docs/COMPOSICAO-FINAL-20261105.md#configuração-e-provisionamento), com cadastro único e heartbeat Ed25519; emissão de token e publicação exigem sessão administrativa desde #110.

Instalador `.exe` para Windows 10/11 x64, com serviço `SafeUploadAgent`, interface WPF na bandeja, atalho e desinstalador. Os dois executáveis são publicados com runtime .NET próprio; o computador de destino não precisa do SDK. A compilação usa Inno Setup 6.7.3, obtido de uma release oficial imutável, com SHA-256 e assinatura do editor verificados.

**Estado:** candidato de desenvolvimento sem assinatura da equipe. Compilar o pacote e aprovar testes de contrato não substitui executar instalação, reinício e remoção em uma VM descartável. O driver gate e o WinFsp entram no pacote quando o build recebe `-DriverDirectory` e `-WinFspMsi`. Esta versão não faz atualização automática de instalações existentes.

## Escopo e divisão da equipe

Este trabalho é somente do agente Windows. Não altera o backend Java, seus endpoints ou o painel Angular. A URL escolhida precisa apontar para uma API compatível, definida com Thiago. O pacote não inclui as propostas locais de correção Java da recuperação anterior.

No modo de unidades, o instalador chama `agente/scripts/Install-SafeUploadAgent.ps1 -PrerequisitesOnly` para instalar o WinFsp e o driver gate do pacote.

## Instalação

Execute o instalador como administrador **em VM de teste** e escolha:

| Modo | Requisitos e comportamento |
| --- | --- |
| Unidades SafeUpload (`Drive`, padrão) | Instala o WinFsp e o driver gate quando o pacote os inclui (sem WinFsp instalado nem incluído, a instalação é recusada). Cada pasta protegida, pendrive e compartilhamento da política vira uma unidade inspecionada; o driver gate recusa gravações diretas. Windows em modo de teste (driver assinado com o certificado de teste). Não exige reiniciar. |
| Teste sem driver (`FileSystemWatcher`) | Só é aceito quando não há driver SafeUpload registrado. Observa após a gravação, sem bloqueio preventivo. Não exige reiniciar. |

A URL é opcional. Vazia significa política local e nenhuma sincronização web; para integração, use `https://servidor/agent/`. HTTP é aceito somente em loopback, por exemplo `http://127.0.0.1:8080/agent/`. Credenciais, query, fragmento, espaços e argumentos adicionais são recusados. Configurar uma URL não comprova que o servidor implementa o contrato do agente.

O destino é fixo: `%ProgramFiles%\SafeUpload\Agent`, separado em `service`, `ui` e `setup`. O caminho do serviço é explicitamente entre aspas. A interface entra na inicialização dos usuários após a instalação; a opção de abri-la ao terminar usa o usuário original, sem elevação. A inspeção TLS permanece desligada: este instalador não instala CA nem altera proxy ou regras WFP.

Automação, também em máquina descartável:

```powershell
.\SafeUploadAgent-0.1.18-win-x64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /MODE=FileSystemWatcher
# Unidades SafeUpload (pacote com WinFsp e driver gate):
.\SafeUploadAgent-0.1.18-win-x64-setup.exe /MODE=Drive /ADMINURL=https://servidor/agent/
```

No modo silencioso, ausência de `/MODE` seleciona `Drive`.

## Remoção, falhas e manutenção

- O desinstalador para e remove apenas o serviço cujo executável e conta correspondem a esta instalação; remove sua entrada de inicialização e os binários registrados pelo pacote.
- Política, cache, auditoria, pastas monitoradas, arquivos retidos e quarentena são preservados. Não há exclusão recursiva de `%ProgramData%\SafeUpload` ou `C:\SafeUpload`.
- Com driver registrado, a remoção é bloqueada até o driver estar **desabilitado e parado**, conforme o procedimento de manutenção aprovado pelo responsável do driver. O instalador não desabilita o driver para facilitar a remoção.
- Serviço existente, diretório de instalação ocupado, startup conflitante e caminhos com links/junções são recusados. A versão inicial não faz upgrade nem assume propriedade de uma instalação manual.
- A criação do serviço só ocorre depois da verificação SHA-256 do payload. Falhas nessa etapa são reportadas como erro; há tentativa de remover o serviço criado nesta execução. A instalação pode deixar arquivos/desinstalador para diagnóstico; o driver gate e o WinFsp já instalados permanecem até a desinstalação.
- A remoção encerra a interface pertencente ao caminho exato desta instalação antes de remover o serviço e os binários. Uma interface homônima em outro local é preservada; se não for possível verificar a identidade do executável, a remoção é recusada.

O estado da instalação fica em `setup/installation.json`. O manifesto registra versão, commit, estado de alterações locais e hashes de todos os arquivos empacotados. Dados privados do endpoint não entram no pacote.

Na automação, somente saída zero confirma que a configuração do serviço terminou. Falha na etapa posterior à cópia
dos arquivos retorna código 100 quando o instalador não atribuiu outro erro; consulte o log e não trate binários
copiados como serviço instalado. A falha pode deixar arquivos/desinstalador para diagnóstico, conforme descrito acima.

## Atualização controlada e reversão

O build também gera `SafeUploadAgent-<versão>-win-x64-update.zip` e seu SHA-256. Confira o hash recebido por um canal confiável, extraia em uma pasta separada e execute **Windows PowerShell 5.1 como administrador**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Pacotes\SafeUpload\setup\Update-SafeUploadAgent.ps1" -PackagePath "C:\Pacotes\SafeUpload"
# Para voltar à versão anterior, use o identificador retornado pela atualização:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Pacotes\SafeUpload\setup\Update-SafeUploadAgent.ps1" -Action Rollback -TransactionId <identificador>
```

Aceita somente instalação gerenciada em `%ProgramFiles%\SafeUpload\Agent`, com versão e commit coerentes, pacote de origem limpa e versão posterior. Instalações manuais e candidatas em outros caminhos precisam de migração própria. O pacote precisa manter os mesmos pré-requisitos de driver/WinFsp; este procedimento atualiza apenas serviço, interface e scripts. Configurações persistentes devem ficar em ProgramData ou nos argumentos do serviço: os arquivos empacotados, incluindo `appsettings.json`, são substituídos.

A cópia anterior e o novo pacote são conferidos antes de parar o serviço. O procedimento encerra a interface da instalação, preserva os argumentos e a identidade do serviço e mantém driver, política, identidade do endpoint, fila e arquivos retidos. Confere o serviço e o canal de status após iniciar; no modo Drive exige também gate e unidades prontos. Se a nova versão não inicia ou não fica pronta, tenta restaurar os binários anteriores. A reversão nunca restaura uma fila ou uma política antiga. Reabra a interface na sessão do usuário ao terminar.

As transações ficam em `%ProgramFiles%\SafeUpload\Maintenance\<identificador>`, acessíveis apenas a administradores e SYSTEM, sem limpeza automática. Uma interrupção de energia ou falha na recuperação exige usar `Rollback` com o identificador de `transaction.json` antes de nova atualização. Arquivos não empacotados dentro de `service`, `ui` e `setup` ficam junto à árvore anterior, fora da instalação ativa; o desinstalador original continua no lugar. A remoção considera o manifesto atual para retirar também dependências introduzidas pela atualização.

Esse é um procedimento manual de manutenção da aplicação. Assinatura do editor, atualização de driver, reparo de instalação danificada e atualização automática continuam fora deste recorte. SHA-256 detecta alteração do pacote, mas não autentica seu autor.

## Gerar o instalador

Na máquina de desenvolvimento: Windows x64, .NET 10 SDK, PowerShell 7, Git e acesso às dependências NuGet. O compilador é extraído em modo portátil dentro de `artifacts/installer-tools`, sem instalar o agente.

```powershell
$compiler = ./agente/installer/Initialize-InnoCompiler.ps1
./agente/installer/tests/Test-InstallerContracts.ps1
./agente/installer/Build-AgentInstaller.ps1 -CompilerPath $compiler
./agente/installer/tests/Test-InstallerArtifact.ps1 -BuildResultPath ./artifacts/installer/build-result.json -ResultsPath ./artifacts/installer-tests/artifact-validation.json
```

Saídas em `artifacts/installer/`: instalador `.exe`, pacote de atualização `.zip`, seus arquivos `.sha256`, `build-result.json` e uma pasta de build com payload e logs. O builder cria pastas novas para cada execução e não apaga diretórios existentes. Ele não instala serviços, inicia a UI ou executa o instalador gerado.

## Validação e critérios de aceite

Os contratos PowerShell exercitam URL, argumentos do serviço, recusa de atualização, estado do driver, hashes, adulteração, arquivos ausentes, escape de diretório, duplicidade de caminhos e junções, usando somente arquivos temporários e estados simulados. Rodam em PowerShell 5.1 e 7. Os seis testes xUnit existentes do instalador técnico devem continuar passando.

O workflow `.github/workflows/agent-installer.yml` valida o HEAD exato em PR, push na main e execução manual. Confere identidade/payload do pacote e chama `Test-InstallerSmoke.ps1` somente em runner Windows hospedado e descartável do GitHub. O smoke recusa estado SafeUpload preexistente; verifica instalação silenciosa, LocalSystem/SID, runtime próprio, configuração, startup, inspeção sintética, preservação de evento no reinício, recusa de sobreposição pelo instalador inicial, atualização manual, reversão explícita, recuperação de falha de inicialização e remoção com a UI aberta, preservando política e fila. Inclui o contrato atual de auditoria e o cliente de diagnóstico em setup/Get-SafeUploadDiagnostics.ps1. O smoke valida as consultas administrativas do arquivo instalado em PowerShell 7 e Windows PowerShell 5.1, preservando a fila. A proteção contra execução no computador de trabalho deve permanecer ativa.

O formulário do instalador configura modo e URL; não provisiona a identidade, não seleciona `HeartbeatProtocol=AgentApiEd25519`/`PolicyProtocol=ConsoleByIp` e não cadastra o host automaticamente. A integração atual requer [cadastro/identidade Ed25519](../docs/AUTENTICACAO-ED25519-AGENTE5.md#cadastro-explícito-e-recuperação) e [configuração explícita da composição](../docs/COMPOSICAO-FINAL-20261105.md#configuração-e-provisionamento). A ferramenta ApiSmoke de provisionamento é publicada separadamente do instalador. URL preenchida sozinha mantém o protocolo legado e não representa comunicação qualificada com o backend atual. O [guia de 29/10](../docs/CONFIGURACAO-COMUNICACAO-20261029.md) registra a configuração anterior à autenticação atual.

Antes de liberar: aprovar esse smoke no runner, testar máquina limpa sem .NET instalado, usuário comum/bandeja, Windows 10/11, logs, dados após remoção e os cenários de reinício/falha com o driver assinado da equipe. Validar o driver exige VM própria; o smoke sem driver não comprova enforcement. Acrescentar assinatura Authenticode da equipe e qualificar o procedimento manual de atualização/reversão com o par de driver e os ambientes escolhidos antes de distribuição de produção.

Referências do compilador: [download oficial](https://jrsoftware.org/isdl.php), [release 6.7.3](https://github.com/jrsoftware/issrc/releases/tag/is-6_7_3), [modo portátil](https://jrsoftware.org/ishelp/topic_technotes.htm), [parâmetros de instalação](https://jrsoftware.org/ishelp/topic_setupcmdline.htm) e [eventos de instalação](https://jrsoftware.org/ishelp/topic_scriptevents.htm).
