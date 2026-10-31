# Instalador do agente Windows — candidato de desenvolvimento

Base do instalador integrada na main pelo #64, com origem nos #42/#49 e correção de remoção com UI aberta da issue #50. Recortes posteriores integraram auditoria/recibos, diagnóstico da fila, histórico e manutenção somente leitura. A versão candidata é 0.1.15; o manifesto de cada build identifica commit e hashes próprios. Ela não herda o aceite do pacote Windows 10 0.1.14. Consulte o resultado do workflow no commit exato antes de executar uma instalação de teste.

Instalador `.exe` para Windows 10/11 x64, com serviço `SafeUploadAgent`, interface WPF na bandeja, atalho e desinstalador. Os dois executáveis são publicados com runtime .NET próprio; o computador de destino não precisa do SDK. A compilação usa Inno Setup 6.7.3, obtido de uma release oficial imutável, com SHA-256 e assinatura do editor verificados.

**Estado:** candidato de desenvolvimento sem assinatura da equipe. Compilar o pacote e aprovar testes de contrato não substitui executar instalação, reinício e remoção em uma VM descartável. O driver não acompanha este pacote. Esta versão não faz atualização automática de instalações existentes.

## Escopo e divisão da equipe

Este trabalho é somente do agente Windows. Não altera o backend Java, seus endpoints ou o painel Angular. A URL escolhida precisa apontar para uma API compatível, definida com Thiago. O pacote não inclui as propostas locais de correção Java da recuperação anterior.

O script técnico existente `agente/scripts/Install-SafeUploadAgent.ps1` é reaproveitado no modo minifiltro. A composição do par atual, protocolo e autoridade de política do Vitor mantêm aceite próprio; este pacote de agente não substitui essa validação.

## Instalação

Execute o instalador como administrador **em VM de teste** e escolha:

| Modo | Requisitos e comportamento |
| --- | --- |
| Minifiltro | Driver SafeUpload já instalado e parado. Prepara a política de boot como SYSTEM, configura o serviço com SID irrestrito e escrita em estágio; o filtro não é carregado pelo instalador. Solicita reinicialização. |
| Teste sem driver | Só é aceito quando não há driver SafeUpload registrado. Inicia o serviço com `FileSystemWatcher`, que observa após a gravação e não fornece bloqueio preventivo no kernel. Não exige reiniciar. |

A URL é opcional. Vazia significa política local e nenhuma sincronização web; para integração, use `https://servidor/agent/`. HTTP é aceito somente em loopback, por exemplo `http://127.0.0.1:8080/agent/`. Credenciais, query, fragmento, espaços e argumentos adicionais são recusados. Configurar uma URL não comprova que o servidor implementa o contrato do agente.

O destino é fixo: `%ProgramFiles%\SafeUpload\Agent`, separado em `service`, `ui` e `setup`. O caminho do serviço é explicitamente entre aspas. A interface entra na inicialização dos usuários após a instalação; a opção de abri-la ao terminar usa o usuário original, sem elevação. A inspeção TLS permanece desligada: este instalador não instala CA nem altera proxy ou regras WFP.

Automação, também em máquina descartável:

```powershell
.\SafeUploadAgent-0.1.15-win-x64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /MODE=FileSystemWatcher
# Para o driver já instalado e parado:
.\SafeUploadAgent-0.1.15-win-x64-setup.exe /MODE=Minifilter /ADMINURL=https://servidor/agent/
```

No modo silencioso, ausência de `/MODE` seleciona Minifilter e mantém seus pré-requisitos. `/NORESTART` impede reinício automático, mas não dispensa o reinício necessário ao minifiltro.

## Remoção, falhas e manutenção

- O desinstalador para e remove apenas o serviço cujo executável e conta correspondem a esta instalação; remove sua entrada de inicialização e os binários registrados pelo pacote.
- Política, cache, auditoria, pastas monitoradas, arquivos retidos e quarentena são preservados. Não há exclusão recursiva de `%ProgramData%\SafeUpload` ou `C:\SafeUpload`.
- Com driver registrado, a remoção é bloqueada até o driver estar **desabilitado e parado**, conforme o procedimento de manutenção aprovado pelo responsável do driver. O instalador não desabilita o driver para facilitar a remoção.
- Serviço existente, diretório de instalação ocupado, startup conflitante e caminhos com links/junções são recusados. A versão inicial não faz upgrade nem assume propriedade de uma instalação manual.
- A criação do serviço só ocorre depois da verificação SHA-256 do payload. Falhas nessa etapa são reportadas como erro; há tentativa de remover o serviço criado nesta execução. Se a preparação do minifiltro falhar, seu início fica sob demanda. A instalação pode deixar arquivos/desinstalador para diagnóstico; não há promessa de rollback completo do driver.
- A remoção encerra a interface pertencente ao caminho exato desta instalação antes de remover o serviço e os binários. Uma interface homônima em outro local é preservada; se não for possível verificar a identidade do executável, a remoção é recusada.

O estado da instalação fica em `setup/installation.json`. O manifesto registra versão, commit, estado de alterações locais e hashes de todos os arquivos empacotados. Dados privados do endpoint não entram no pacote.

## Gerar o instalador

Na máquina de desenvolvimento: Windows x64, .NET 10 SDK, PowerShell 7, Git e acesso às dependências NuGet. O compilador é extraído em modo portátil dentro de `artifacts/installer-tools`, sem instalar o agente.

```powershell
$compiler = ./agente/installer/Initialize-InnoCompiler.ps1
./agente/installer/tests/Test-InstallerContracts.ps1
./agente/installer/Build-AgentInstaller.ps1 -CompilerPath $compiler
./agente/installer/tests/Test-InstallerArtifact.ps1 -BuildResultPath ./artifacts/installer/build-result.json -ResultsPath ./artifacts/installer-tests/artifact-validation.json
```

Saídas em `artifacts/installer/`: `SafeUploadAgent-0.1.15-win-x64-setup.exe`, seu `.sha256`, `build-result.json` e uma pasta de build com payload e logs. O builder cria pastas novas para cada execução e não apaga diretórios existentes. Ele não instala serviços, inicia a UI ou executa o instalador gerado.

## Validação e critérios de aceite

Os contratos PowerShell exercitam URL, argumentos do serviço, recusa de atualização, estado do driver, hashes, adulteração, arquivos ausentes, escape de diretório, duplicidade de caminhos e junções, usando somente arquivos temporários e estados simulados. Rodam em PowerShell 5.1 e 7. Os seis testes xUnit existentes do instalador técnico devem continuar passando.

O workflow `.github/workflows/agent-installer.yml` valida o HEAD exato em PR, push na main e execução manual. Confere identidade/payload do pacote e chama `Test-InstallerSmoke.ps1` somente em runner Windows hospedado e descartável do GitHub. O smoke recusa estado SafeUpload preexistente; verifica instalação silenciosa, LocalSystem/SID, runtime próprio, configuração, startup, inspeção sintética, preservação de evento no reinício, recusa de atualização e remoção com a UI aberta, preservando política e fila. Inclui o contrato atual de auditoria e o cliente de diagnóstico em setup/Get-SafeUploadDiagnostics.ps1. O smoke valida as consultas administrativas do arquivo instalado em PowerShell 7 e Windows PowerShell 5.1, preservando a fila. A proteção contra execução no computador de trabalho deve permanecer ativa.

O formulário do instalador configura modo e URL; não provisiona `RegisteredHostId`, não seleciona `HeartbeatProtocol=AgentApi` e não cadastra o host automaticamente. A integração com a API atual requer a configuração explícita descrita em [CONFIGURACAO-COMUNICACAO-20261029.md](../docs/CONFIGURACAO-COMUNICACAO-20261029.md). URL preenchida sozinha mantém o protocolo legado e não representa comunicação qualificada com o backend atual.

Antes de liberar: aprovar esse smoke no runner, testar máquina limpa sem .NET instalado, usuário comum/bandeja, Windows 10/11, logs, dados após remoção e os cenários de reinício/falha com o driver assinado da equipe. Validar o driver exige VM própria; o smoke sem driver não comprova enforcement. Acrescentar assinatura Authenticode da equipe e procedimento de upgrade/rollback antes de distribuição de produção.

Referências do compilador: [download oficial](https://jrsoftware.org/isdl.php), [release 6.7.3](https://github.com/jrsoftware/issrc/releases/tag/is-6_7_3), [modo portátil](https://jrsoftware.org/ishelp/topic_technotes.htm), [parâmetros de instalação](https://jrsoftware.org/ishelp/topic_setupcmdline.htm) e [eventos de instalação](https://jrsoftware.org/ishelp/topic_scriptevents.htm).
