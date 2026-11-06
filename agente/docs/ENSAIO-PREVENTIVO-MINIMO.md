# Ensaio preventivo mínimo na VM

Executar em VM descartável, com WinFsp 2.1 e o gate atual compilado/assinado, identificados por commit e SHA256.
O gate usa `\SafeUploadGatePort`, protocolo **v1**; o antigo pacote de staging v18 não serve para este ensaio.
O teste exige sessão interativa de administrador, distinta do processo LocalSystem do serviço.

## Preparação

Publicar o serviço da branch a testar e copiar o pacote, `agente/scripts/` e o gate para a VM:

```powershell
dotnet publish agente/SafeUpload.Agent.Service -c Release -r win-x64 --self-contained true -o out/agent
```

Na VM limpa, preparar `C:\ProgramData\SafeUpload\policy.json` com a política abaixo e protegê-la com
`Protect-SafeUploadPolicy.ps1`. Em VM já provisionada, preservar política, fila e stage existentes e usar outra cópia
para este cenário. O script de ensaio nunca substitui a política, instala componentes ou limpa arquivos.

```json
{
  "version": 1,
  "activeCategories": ["Cpf"],
  "monitoredScopes": {
    "extensions": [".txt"],
    "destinationPaths": ["C:\\SafeUpload\\Envios"],
    "removableDrives": false,
    "networkPaths": false
  },
  "overrideAllowed": false,
  "auditOnly": false,
  "excludedProcesses": []
}
```

Instalar com o script existente; `C:\pkg\driver` deve conter o `SafeUpload.sys` atual, confiável na VM.
Seguir o procedimento de assinatura do responsável pelo driver; não desativar validação de assinatura.

```powershell
C:\pkg\scripts\Protect-SafeUploadPolicy.ps1 -PolicyPath C:\ProgramData\SafeUpload\policy.json
C:\pkg\scripts\Install-SafeUploadAgent.ps1 -PackagePath C:\pkg\agent -DriverPath C:\pkg\driver -AdminBaseUrl ''
```

O pacote usa `Interception:Mode=Drive` por padrão. Após aparecer a unidade (normalmente S:), executar:

```powershell
C:\pkg\scripts\Test-PreventiveCore.ps1 -Destination C:\SafeUpload\Envios -DriveRoot S:\ -ResultPath C:\evidencias\preventivo.json
```

## Evidência e continuidade

O JSON deve indicar `passed=true`: arquivo limpo com bytes idênticos no backing; CPF sintético retido com
notificação e evento de bloqueio; escrita direta administrativa recusada com incremento do contador real do gate;
aprovação e bloqueio auditados com a versão aplicada. Registra identidade/hash do binário, política e IDs dos eventos.
Preservar também commit/hash do SYS entregue pelo responsável e versão/build do Windows. Os arquivos têm nomes
únicos e permanecem disponíveis para conferência; não remover o stage nem a fila para repetir o teste.

Este ensaio cobre um destino NTFS local. Não qualifica Office, USB, SMB, entrega ao backend, queda de energia ou
recuperação após encerramento abrupto. Parser aprovado ou testes C# sem unidade montada não constituem seu aceite.
Em 05/11, os três cenários passaram com driver real na VM isolada, serviço `f95f970c`, gate v1 da fonte `07802232`,
Windows 10 `19045.3803`, política local 9101. O [registro do núcleo](NUCLEO-AGENTE.md) identifica IDs e limites.
