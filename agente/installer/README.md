# Instalador do agente

`SafeUploadAgent-<versão>-win-x64-setup.exe` (Inno Setup) instala o serviço `SafeUploadAgent` e a bandeja em
`%ProgramFiles%\SafeUpload\Agent` (`service`, `ui`, `setup`), com atalho no menu Iniciar e desinstalador. Os
executáveis levam o runtime .NET; a máquina não precisa do SDK. Alvo: Windows 10 x64. É um pacote de
desenvolvimento, sem assinatura da equipe; o driver gate é assinado com o certificado de teste, então use uma VM com
test signing ligado.

## Gerar

Em Windows x64 com .NET 10 SDK, PowerShell 7 e Git, na raiz do repositório:

```powershell
$compiler = ./agente/installer/Initialize-InnoCompiler.ps1      # Inno Setup 6.7.3 portátil em artifacts/installer-tools
./agente/installer/Build-AgentInstaller.ps1 -CompilerPath $compiler `
    -DriverDirectory <pasta com SafeUpload.sys e .inf> -WinFspMsi <winfsp-2.1.x.msi>
```

`-Version` define a versão (padrão no script). Sem `-DriverDirectory`/`-WinFspMsi` o pacote não leva driver nem
WinFsp. Saídas em `artifacts/installer/`: o instalador `.exe`, o pacote de atualização `.zip`, seus `.sha256` e
`build-result.json`. O driver vem de `driver/scripts/build-driver.sh`.

Os testes do instalador (`tests/Test-InstallerContracts.ps1`, `Test-MaintenanceContracts.ps1`,
`Test-InstallerArtifact.ps1`) rodam no workflow `agent.yml`. O `Test-InstallerSmoke.ps1` instala de
verdade e só deve rodar em máquina descartável.

## Instalar

Execute o instalador como administrador e escolha o modo:

| Modo | O que faz |
|---|---|
| Unidades SafeUpload (`Drive`, padrão) | Instala o WinFsp e o driver gate do pacote. Sem WinFsp instalado nem incluído, a instalação é recusada. Não exige reiniciar. |
| Teste sem driver (`FileSystemWatcher`) | Só observa depois da gravação, sem bloqueio preventivo. Recusado se houver driver SafeUpload registrado. |

Sem interação:

```powershell
.\SafeUploadAgent-<versão>-win-x64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /MODE=Drive
```

A bandeja entra na inicialização dos usuários. A inspeção TLS fica desligada: o instalador não cria CA nem mexe em
proxy ou WFP. Saída diferente de zero significa que o serviço não ficou configurado (100 = falha depois da cópia dos
arquivos); veja o log do Inno Setup.

Depois, cadastre a máquina no console com `service\SafeUpload.Agent.Service.exe cadastrar ...` (ver
[README do agente](../README.md#cadastro-no-console)). Passe o endereço do servidor nesse comando. O instalador
recusa o parâmetro antigo `/ADMINURL`. Sem cadastro, o agente protege com o `policy.json` local.

## Atualizar e voltar

O `.zip` de atualização troca serviço, bandeja e scripts de uma instalação feita por este instalador, mantendo
driver, política, identidade, fila e arquivos retidos. Confira o `.sha256`, extraia numa pasta e rode no Windows
PowerShell 5.1 como administrador:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Pacotes\SafeUpload\setup\Update-SafeUploadAgent.ps1 -PackagePath C:\Pacotes\SafeUpload
# voltar à versão anterior, com o identificador impresso pela atualização:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Pacotes\SafeUpload\setup\Update-SafeUploadAgent.ps1 -Action Rollback -TransactionId <identificador>
```

Só aceita versão posterior com os mesmos pré-requisitos de driver/WinFsp; não atualiza o driver. Se a versão nova
não sobe, o script tenta restaurar a anterior. `appsettings.json` é substituído: configuração que deve sobreviver
fica em `%ProgramData%\SafeUpload`. As transações ficam em `%ProgramFiles%\SafeUpload\Maintenance\<identificador>`;
depois de uma queda no meio da atualização, rode `Rollback` com o identificador de `transaction.json` antes de
tentar de novo.

## Remover

Pelo desinstalador (Aplicativos do Windows ou atalho "Desinstalar agente"). Ele fecha a bandeja desta instalação,
remove o serviço, o driver gate e os binários. O WinFsp continua instalado. Política, cache, fila de auditoria,
arquivos retidos e as pastas protegidas são preservados (`%ProgramData%\SafeUpload`, `C:\SafeUpload`).

Diagnóstico (administrador, somente leitura): `setup\Get-SafeUploadDiagnostics.ps1` consulta o serviço sobre
comunicação com o console e saúde da fila de auditoria.
