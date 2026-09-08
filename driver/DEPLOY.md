# DEPLOY.md — Minifiltro SafeUpload (v1)

Runbook completo para compilar, assinar, instalar, testar, depurar e remover
o minifiltro SafeUpload em uma **VM alvo descartável**.

Este documento assume que quem executa **nunca instalou um driver antes**.
Cada passo traz o comando exato e o que deve aparecer na tela. Nada é
implícito.

---

## Aviso antes de qualquer coisa

Um driver de sistema de arquivos roda em modo kernel. Um erro nele não gera
uma exceção: gera uma tela azul, e potencialmente uma VM que não inicializa
mais.

Regras que não se negociam:

- **Só instale em uma VM descartável**, nunca na máquina de desenvolvimento
  e nunca em máquina com dados reais.
- **Tire um snapshot antes** (passo 1). É o único plano de recuperação que
  funciona sempre.
- A VM alvo precisa ficar com **Secure Boot desligado** e **test signing
  ligado**. Isso reduz a postura de segurança dela — outro motivo para ser
  descartável.

---

## O que este driver faz na v1

- Intercepta `IRP_MJ_CREATE` (abertura de arquivo) e `IRP_MJ_READ` (leitura).
- Ignora paging I/O, abertura de volumes, abertura de diretórios, I/O dos
  processos Idle e System, e o I/O do próprio inspetor.
- Manda para o modo usuário, por uma porta de comunicação do Filter Manager,
  o caminho do arquivo e o PID/imagem do processo requisitante.
- Recebe um veredito e **permite** ou **nega com `STATUS_ACCESS_DENIED`**.

O que ele **não** faz, por decisão de projeto:

- Não tem nenhuma lógica de detecção. As regras RN-001 a RN-004 (CPF, CNPJ,
  Luhn, heurística de senha) vivem inteiramente em modo usuário. O kernel só
  transporta.
- Não bloqueia quando a inspeção falha. Timeout, porta fechada, resposta
  inválida, falta de memória — tudo isso resulta em **permitir**
  (RN-013: "Permitido sem inspeção"). O driver nunca trava o sistema de
  arquivos esperando uma resposta que não vem: o teto é 500 ms por operação.

---

## Caminho rápido: os scripts

O ciclo inteiro está automatizado em `driver/scripts`. As partes A e B abaixo
continuam sendo a referência — elas explicam **por que** cada passo existe, e
é para elas que você volta quando algo falha. Os scripts são o que você roda
no dia a dia.

**Nesta VM**, compila, assina, gera e assina o catálogo, escreve um manifesto
com os hashes e serve o pacote:

```powershell
.\driver\scripts\Publish-SafeUpload.ps1 -Serve
```

Aceita `-Configuration Release` e `-Analyze` (Code Analysis com as regras de
driver). Ao servir, ele imprime o comando exato para o outro lado, já com o
IP desta máquina.

**Na VM alvo**, em um PowerShell **elevado**, um comando só:

```powershell
iex (irm http://192.168.122.132:8000/bootstrap.ps1)
```

O `bootstrap.ps1` é gerado a cada publicação com a URL embutida. Ele baixa a
**versão atual** do script de teste, libera a política de execução no escopo
do processo e entrega o controle. Não há cópia de script para manter
atualizada na VM alvo: o que roda é sempre o que acabou de ser publicado.

A partir daí o script faz a verificação prévia, baixa o pacote, confere os
hashes contra o manifesto, troca o binário, carrega o filtro e roda o teste
de fumaça inteiro, terminando com um resumo do tipo `6/6 verificações
passaram` e código de saída diferente de zero se alguma falhar.

Para passar opções, rode o script já baixado:

```powershell
& $env:TEMP\Invoke-SafeUploadTest.ps1 -SkipDownload -SkipSmokeTest
```

> O `bootstrap.ps1` entrega o controle ao script **como arquivo**, e não por
> `Invoke-Expression`. É deliberado: `#Requires -RunAsAdministrator` é
> ignorado quando um script é interpretado a partir de uma string, e a
> verificação de elevação se perderia justamente onde ela importa.

> **Sobre hashes: use sempre o manifesto.** Assinar altera o arquivo, e cada
> `Rebuild` produz um binário diferente do anterior mesmo sem mudança de
> código. Por isso o `Publish` grava `manifest.json` com o hash do artefato
> **assinado** e o `Invoke` confere contra ele. Nenhum hash anotado à mão
> sobrevive a dois ciclos.

Os scripts não substituem os pré-requisitos da Parte B que só se fazem uma
vez — snapshot, Secure Boot desligado, `bcdedit /set testsigning on` e a
importação do certificado. O `Invoke` **verifica** todos eles e para com
instrução clara se algum faltar, mas não os executa: ligar modo de teste e
mexer em firmware são decisões do operador, não de um script.

---

## Parte A — Na VM de desenvolvimento (esta máquina)

### A.1. Ambiente verificado

| Item | Versão nesta VM |
|---|---|
| Visual Studio | Community **2026** (18.9.2) — *não* 2022 |
| SDK/WDK | 10.0.28000.0 (SDK e WDK pareados) |
| Toolset do driver | `WindowsKernelModeDriver10.0` |
| Toolset do inspetor | `v145` |

> Se alguém do time usar Visual Studio 2022, os `.vcxproj` precisarão de
> `PlatformToolset` compatível. O código em si não depende da versão.

### A.2. Compilar

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" "C:\Users\vika\Documents\safeupload\driver\SafeUpload.Driver.sln" /t:Rebuild /p:Configuration=Debug /p:Platform=x64
```

Saída esperada: `0 Warning(s)` e `0 Error(s)`.

Artefatos gerados:

| Arquivo | Caminho |
|---|---|
| `SafeUpload.sys` | `driver\x64\Debug\SafeUpload.sys` |
| `SafeUpload.Inspector.exe` | `driver\x64\Debug\SafeUpload.Inspector.exe` |
| `SafeUpload.inf` | `driver\SafeUpload.Minifilter\SafeUpload.inf` (não é gerado, é fonte) |

Para rodar a análise estática com as regras de driver:

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" "C:\Users\vika\Documents\safeupload\driver\SafeUpload.Minifilter\SafeUpload.Minifilter.vcxproj" /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /p:RunCodeAnalysis=true /p:EnablePREfast=true /p:CodeAnalysisRuleSet="C:\Program Files (x86)\Windows Kits\10\CodeAnalysis\DriverRecommendedRules.ruleset"
```

### A.3. Montar a pasta de pacote

Junte tudo em um diretório só. Todos os comandos de assinatura abaixo
assumem `C:\safeupload-pkg`.

```powershell
New-Item -ItemType Directory -Force C:\safeupload-pkg | Out-Null
Copy-Item C:\Users\vika\Documents\safeupload\driver\x64\Debug\SafeUpload.sys C:\safeupload-pkg\
Copy-Item C:\Users\vika\Documents\safeupload\driver\x64\Debug\SafeUpload.Inspector.exe C:\safeupload-pkg\
Copy-Item C:\Users\vika\Documents\safeupload\driver\SafeUpload.Minifilter\SafeUpload.inf C:\safeupload-pkg\
```

### A.4. Gerar o certificado de teste

Feito **uma vez**. O `.pfx` (com chave privada) fica só nesta VM; para a VM
alvo vai apenas o `.cer` (só a parte pública).

```powershell
New-Item -ItemType Directory -Force C:\safeupload-cert | Out-Null

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=SafeUpload Test Signing" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears(3) `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")

$cert.Thumbprint
```

Exportar. O `.cer` é a parte pública e vai para a VM alvo. O `.pfx` é a cópia
portátil da chave privada e serve para assinar de **outra** máquina — nesta
aqui a assinatura sai direto do repositório de certificados (passo A.5), sem
senha. Se a senha do `.pfx` se perder, basta reexportar: a chave foi criada
com `-KeyExportPolicy Exportable`.

```powershell
$pfxPassword = Read-Host -AsSecureString "Senha para o PFX"
Export-PfxCertificate -Cert $cert -FilePath C:\safeupload-cert\SafeUploadTest.pfx -Password $pfxPassword
Export-Certificate  -Cert $cert -FilePath C:\safeupload-cert\SafeUploadTest.cer
```

> O `.pfx` contém a chave privada. Ele **não vai para o repositório** (o
> `.gitignore` já bloqueia `*.pfx`, `*.cer`, `*.pvk`) e **não vai para a VM
> alvo**.

### A.5. Assinar — a ordem importa

O catálogo (`.cat`) guarda o hash dos arquivos listados no INF. Se você
assinar o `.sys` **depois** de gerar o `.cat`, o hash muda e o catálogo passa
a estar errado. A ordem correta é:

Os comandos abaixo assinam **direto do repositório de certificados**, por
impressão digital. Não há senha envolvida. O `.pfx` é apenas uma cópia
portátil da chave, útil para assinar de outra máquina — um servidor de build,
por exemplo — e desnecessário aqui. Perder a senha dele não impede assinar,
desde que o certificado continue no repositório.

Para descobrir a impressão digital:

```powershell
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*SafeUpload*" } | Select-Object Thumbprint, Subject, NotAfter, HasPrivateKey
```

> **Assinar muda o arquivo.** A assinatura é embutida no `.sys`, o que altera
> o tamanho e o hash. Qualquer conferência de integridade tem que usar o hash
> do artefato **assinado**, em `C:\safeupload-pkg`, e nunca o da saída de
> build em `driver\x64\Debug`. Confundir os dois faz uma cópia perfeitamente
> boa parecer corrompida.

**1) Assinar o driver (assinatura embutida — é o que o kernel valida na
carga):**

```powershell
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe" sign /v /fd sha256 /sha1 IMPRESSAO_DIGITAL_DO_CERTIFICADO C:\safeupload-pkg\SafeUpload.sys
```

**2) Gerar o catálogo:**

```powershell
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x86\Inf2Cat.exe" /driver:C:\safeupload-pkg /os:10_x64 /verbose
```

Esperado: `Errors: None`, `Warnings: None`, e o arquivo
`C:\safeupload-pkg\safeupload.cat` (o Inf2Cat grava o nome em minúsculas;
o Windows não diferencia maiúsculas em nome de arquivo, então está correto).

**3) Assinar o catálogo (é o que o instalador do INF valida):**

```powershell
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe" sign /v /fd sha256 /sha1 IMPRESSAO_DIGITAL_DO_CERTIFICADO C:\safeupload-pkg\safeupload.cat
```

**4) Conferir as duas assinaturas:**

```powershell
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe" verify /v /pa C:\safeupload-pkg\SafeUpload.sys
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe" verify /v /pa /c C:\safeupload-pkg\safeupload.cat C:\safeupload-pkg\SafeUpload.sys
```

O `verify` vai reclamar que a cadeia não termina em uma raiz confiável
(`A certificate chain processed, but terminated in a root certificate which
is not trusted by the trust provider`). Isso é **esperado nesta VM**: a raiz
de teste só será confiável na VM alvo, depois do passo 2 da Parte B.

Se quiser carimbo de tempo (opcional, exige internet), acrescente
`/tr http://timestamp.digicert.com /td sha256` aos comandos de `sign`.

Ao fim, `C:\safeupload-pkg` contém os quatro arquivos que vão para a VM
alvo:

```
SafeUpload.sys
SafeUpload.inf
safeupload.cat
SafeUpload.Inspector.exe
```

E `C:\safeupload-cert\SafeUploadTest.cer` (só a parte pública) vai junto.

---

## Parte B — Na VM alvo

Todos os comandos abaixo são executados em um **Prompt de Comando ou
PowerShell como Administrador**.

### 1. Snapshot da VM alvo

**Antes de qualquer outro passo.** No hipervisor (Hyper-V, VMware,
VirtualBox), com a VM desligada ou em estado estável:

- Hyper-V: `Checkpoint-VM -Name "<nome-da-vm>" -SnapshotName "pre-safeupload"`
- VMware / VirtualBox: use o menu de snapshots da interface.

Anote o nome do snapshot. O passo 10 depende dele.

### 2. Preparar a VM para aceitar assinatura de teste

Sem isto, o Windows recusa carregar o driver com
`STATUS_INVALID_IMAGE_HASH` e o `fltmc load` do passo 5 falha.

**2a. Desligar o Secure Boot** no firmware da VM (configuração do
hipervisor). Confirme dentro do Windows:

```powershell
Confirm-SecureBootUEFI
```

Deve responder `False` ou dar erro dizendo que a máquina não é UEFI. Se
responder `True`, o Secure Boot ainda está ligado e o passo 2b não terá
efeito.

**2b. Ligar o modo de assinatura de teste:**

```
bcdedit /set testsigning on
```

**Reinicie a VM.** Após o boot, o canto inferior direito da área de trabalho
mostra "Modo de Teste". Confirme:

```
bcdedit /enum {current}
```

Procure `testsigning  Yes`.

**2c. Importar o certificado de teste** nos dois armazenamentos. `Root` faz
o Windows confiar na raiz; `TrustedPublisher` evita o diálogo de "deseja
instalar este software?" durante a instalação do INF.

Copie `SafeUploadTest.cer` para `C:\safeupload\` na VM alvo e:

```
certutil -addstore -f Root C:\safeupload\SafeUploadTest.cer
certutil -addstore -f TrustedPublisher C:\safeupload\SafeUploadTest.cer
```

Esperado em ambos: `Certificado "SafeUpload Test Signing" adicionado ao
repositório.` seguido de `CertUtil: -addstore comando concluído com êxito.`

Conferir:

```
certutil -store Root "SafeUpload Test Signing"
certutil -store TrustedPublisher "SafeUpload Test Signing"
```

### 3. Copiar os arquivos

Copie da VM de desenvolvimento para `C:\safeupload\` na VM alvo:

```
C:\safeupload\SafeUpload.sys
C:\safeupload\SafeUpload.inf
C:\safeupload\safeupload.cat
C:\safeupload\SafeUpload.Inspector.exe
```

Os quatro precisam estar **na mesma pasta** — o instalador procura o `.sys`
e o `.cat` ao lado do `.inf`.

Confira que a assinatura agora é reconhecida:

```
certutil -verify -urlfetch C:\safeupload\SafeUpload.sys
```

### 4. Instalar o INF

```
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 C:\safeupload\SafeUpload.inf
```

Esse comando **não imprime nada**, nem em caso de erro. É normal. Verifique
o resultado de duas formas:

**Serviço criado:**

```
sc query SafeUpload
```

Esperado: `TYPE : 2 FILE_SYSTEM_DRIVER` e `STATE : 1 STOPPED` (parado
porque é demand start — ele só sobe no passo 5).

**Arquivo copiado:**

```
dir C:\Windows\System32\drivers\SafeUpload.sys
```

Se algo falhou, o log do instalador diz o quê:

```
notepad C:\Windows\INF\setupapi.dev.log
```

Procure pelas últimas entradas contendo `SafeUpload`.

### 5. Carregar o filtro

```
fltmc load SafeUpload
```

Sem saída = sucesso. Erros comuns:

| Mensagem | Causa |
|---|---|
| `0x80070424` (serviço não existe) | O passo 4 falhou; reveja o `setupapi.dev.log`. |
| `0xc0000428` (`STATUS_INVALID_IMAGE_HASH`) | Assinatura não aceita: passo 2 incompleto (test signing desligado, Secure Boot ligado, ou certificado não importado). |
| `0xC01C0011` (`STATUS_FLT_INSTANCE_ALTITUDE_COLLISION`) | Conflito de altitude: outro filtro já ocupa 321410. Veja "Limitações conhecidas". |
| `0x80070002` (`ERROR_FILE_NOT_FOUND`) mas o serviço existe e o `.sys` está em `system32\drivers` | Mensagem enganosa do `fltmc`. Veja abaixo — quase sempre é o registro de instância no lugar errado. |

> **Atenção à mensagem do `fltmc`.** Ele reporta `0x80070002` ("não foi
> possível encontrar o arquivo especificado") para falhas que não têm nada a
> ver com arquivo ausente. Quando o serviço existe e o `.sys` está no lugar,
> **não confie nessa mensagem**: vá direto ao log de eventos, que traz o
> `NTSTATUS` real do `FltRegisterFilter`:
>
> ```
> Get-WinEvent -LogName System -MaxEvents 40 | Where-Object { $_.Message -like "*SafeUpload*" } | Select-Object TimeCreated, Id, ProviderName, Message | Format-List
> ```
>
> Um evento **ID 5** do `Microsoft-Windows-FilterManager` com status
> `0xC0000034` (`STATUS_OBJECT_NAME_NOT_FOUND`) significa que o driver
> carregou e rodou o `DriverEntry`, mas o FltMgr não achou a configuração de
> instância no registro. Confira onde ela está:
>
> ```
> Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload" -Recurse | Select-Object Name
> ```
>
> Com o instalador legado que este INF usa, ela tem que estar em
> `Services\SafeUpload\Instances`. Se estiver em
> `Services\SafeUpload\Parameters\Instances`, o INF aplicado é de uma versão
> anterior à correção desse layout — reinstale com o INF atual (passo 8d
> para remover, depois passo 4).

Conferir que o filtro está registrado:

```
fltmc filters
```

Esperado — uma linha com o nome, número de instâncias e a altitude:

```
Filter Name       Num Instances    Altitude    Frame
----------------  -------------  ------------  -----
SafeUpload                    3       321410     0
```

Conferir a quais volumes ele se anexou:

```
fltmc instances -f SafeUpload
```

Esperado — uma instância por volume local (`C:`, `D:`, etc.). Volumes de
rede são recusados de propósito pelo `InstanceSetup` do driver.

### 6. Ligar o Driver Verifier apenas neste driver

O Verifier é o que transforma um bug silencioso (uso de memória liberada,
IRQL errado, vazamento de pool) em uma tela azul imediata e diagnosticável.
Ligue-o **só** para o `SafeUpload.sys`, nunca para todos os drivers — a VM
ficaria inutilizavelmente lenta.

```
verifier /standard /driver SafeUpload.sys
```

Resposta esperada: aviso de que é preciso reiniciar.

```
shutdown /r /t 0
```

Depois do boot, confirme:

```
verifier /querysettings
```

Deve listar `SafeUpload.sys` com as opções padrão (que incluem **Special
Pool** — é ele que detecta uso de memória liberada, e é a razão principal de
ligar o Verifier aqui).

> O driver é *demand start*: ele **não** sobe sozinho no boot. Depois de
> reiniciar, carregue de novo:
>
> ```
> fltmc load SafeUpload
> ```

### 7. Teste de fumaça

O inspetor é o "log" desta versão: ele imprime no console cada operação que
o kernel manda.

**7a. Preparar o arquivo de bloqueio ANTES de tudo.**

Isto tem que ser feito com o inspetor **desligado**. Enquanto ele estiver
rodando, qualquer tentativa de *criar* um arquivo com `BLOQUEAR_TESTE` no
caminho também é negada — a regra vale para o `IRP_MJ_CREATE`, e criar é um
create.

```
mkdir C:\safeupload-teste
echo conteudo de teste > C:\safeupload-teste\BLOQUEAR_TESTE.txt
echo arquivo normal > C:\safeupload-teste\normal.txt
```

**7b. Iniciar o inspetor** em um Prompt de Comando **como Administrador**
(a porta é acessível apenas a SYSTEM e Administradores):

```
C:\safeupload\SafeUpload.Inspector.exe
```

Esperado:

```
SafeUpload.Inspector - cliente de teste da porta \SafeUploadPort
Regra de teste: bloqueia caminhos contendo "BLOQUEAR_TESTE"

Conectado. Aguardando requisicoes (Ctrl+C para sair).
```

Se aparecer `ERRO: nao foi possivel conectar na porta`, o filtro não está
carregado (volte ao passo 5) ou o prompt não está elevado.

Se **não aparecer nada** e o prompt voltar na hora, o processo morreu no
carregador antes de chegar ao `main`. Confirme:

```
$LASTEXITCODE
```

`-1073741515` é `0xC0000135` (`STATUS_DLL_NOT_FOUND`): falta uma DLL. O
projeto do inspetor liga o CRT estaticamente justamente para isso não
acontecer numa VM sem Visual Studio — se você vir esse erro, o `.exe`
copiado é anterior a essa correção. Confira as dependências dele na VM de
desenvolvimento:

```
dumpbin /dependents C:\safeupload-pkg\SafeUpload.Inspector.exe
```

Só podem aparecer `KERNEL32.dll` e `FLTLIB.DLL`. Se aparecerem
`VCRUNTIME140D.dll` ou `ucrtbased.dll`, recompile e recopie.

**7c. Caso permitido.** Em *outra* janela:

```
notepad C:\safeupload-teste\normal.txt
```

O Notepad abre o arquivo normalmente. Na janela do inspetor aparecem linhas
como:

```
[41] CREATE pid=7312   notepad.exe      \Device\HarddiskVolume3\safeupload-teste\normal.txt
[42] READ   pid=7312   notepad.exe      \Device\HarddiskVolume3\safeupload-teste\normal.txt
```

O caminho vem em forma NT (`\Device\HarddiskVolumeN\...`), não em forma DOS
(`C:\...`). Isso é o caminho normalizado que o Filter Manager entrega.

**7d. Caso bloqueado:**

```
notepad C:\safeupload-teste\BLOQUEAR_TESTE.txt
```

O Notepad mostra um erro de acesso negado. Na linha de comando o efeito é
mais explícito:

```
type C:\safeupload-teste\BLOQUEAR_TESTE.txt
```

Esperado: `Acesso negado.` / `Access is denied.`

E no inspetor:

```
[57] CREATE pid=9120   cmd.exe          \Device\HarddiskVolume3\safeupload-teste\BLOQUEAR_TESTE.txt  => BLOQUEADO
```

**7e. Caso de falha de inspeção (RN-013).** Feche o inspetor com `Ctrl+C` e
repita o passo 7d. O arquivo agora **abre normalmente**: sem inspetor
conectado, o driver permite tudo. Esse é o comportamento correto e
proposital — falha de inspeção nunca vira bloqueio.

**7f. Rastros do kernel (opcional).** As mensagens `DbgPrintEx` do driver
saem em `DPFLTR_INFO_LEVEL`, que o kernel filtra por padrão. Para vê-las é
preciso um depurador de kernel anexado (ou o DebugView do Sysinternals com
"Capture Kernel" ligado) **e** subir a máscara:

- No WinDbg: `ed nt!Kd_IHVDRIVER_Mask 0xF`
- Persistente (exige reboot):

  ```
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v IHVDRIVER /t REG_DWORD /d 0xF /f
  ```

### 8. Descarregar e desinstalar

**8a. Pare o inspetor primeiro** (`Ctrl+C` na janela dele).

Isso é obrigatório: o driver **recusa** um descarregamento voluntário
enquanto houver inspetor conectado. Se você tentar `fltmc unload` com ele
rodando, o comando falha com `STATUS_FLT_DO_NOT_DETACH` (`0xC01C0010`).
É proposital — descarregar sob um cliente vivo deixa a ordem dos eventos
imprevisível.

**8b. Descarregar o filtro:**

```
fltmc unload SafeUpload
```

Confirme que sumiu:

```
fltmc filters
```

`SafeUpload` não deve mais aparecer na lista.

**8c. Desligar o Driver Verifier:**

```
verifier /reset
shutdown /r /t 0
```

**8d. Desinstalar o INF (remove o serviço e o arquivo):**

```
rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 128 C:\safeupload\SafeUpload.inf
```

Se por algum motivo o serviço sobreviver, remova na mão:

```
sc delete SafeUpload
del C:\Windows\System32\drivers\SafeUpload.sys
```

Confirme:

```
sc query SafeUpload
```

Esperado: `O serviço especificado não existe como um serviço instalado.`

**8e. (Opcional) Reverter o modo de teste:**

```
bcdedit /set testsigning off
certutil -delstore Root "SafeUpload Test Signing"
certutil -delstore TrustedPublisher "SafeUpload Test Signing"
shutdown /r /t 0
```

### 9. Em caso de tela azul (BSOD)

**9a. Garanta que a VM alvo está configurada para gerar dump.** Faça isto
*antes* de precisar:

- `sysdm.cpl` → Avançado → Inicialização e Recuperação → Configurações →
  "Gravar informações de depuração" = **Despejo de memória do kernel** (ou
  completo).
- O arquivo padrão é `C:\Windows\MEMORY.DMP`.

Equivalente por linha de comando (1 = completo, 2 = kernel):

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 2 /f
```

**9b. Depois do BSOD**, copie o dump da VM alvo para esta VM de
desenvolvimento:

```
C:\Windows\MEMORY.DMP  ->  C:\safeupload-dumps\MEMORY.DMP
```

**9c. Abrir no WinDbg** (nesta VM):

```
& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -z C:\safeupload-dumps\MEMORY.DMP
```

**9d. Dentro do WinDbg**, na ordem:

```
.symfix
.sympath+ C:\Users\vika\Documents\safeupload\driver\x64\Debug
.reload /f
!analyze -v
```

`.sympath+` aponta para o `SafeUpload.pdb` gerado junto com o `.sys` — sem
ele a pilha aparece como endereços sem nome. **O `.pdb` tem que ser o da
mesma compilação que gerou o `.sys` instalado**; se você recompilou, o
símbolo não casa.

O `!analyze -v` mostra o bugcheck, o módulo culpado (`MODULE_NAME`) e a
pilha. Se `MODULE_NAME` for `SafeUpload`, a falha é nossa.

**9e. Estado do Filter Manager** no momento do crash:

```
.load fltkd
!fltkd.filters
```

Lista os filtros registrados, suas instâncias e volumes. Comandos úteis em
seguida:

```
!fltkd.filter <endereço-do-filtro>
!fltkd.volumes
```

**9e-bis. Nem toda tela azul é do driver — confira antes de investigar.**

A primeira pergunta, sempre:

```
lm m SafeUpload
```

Se não listar nada, o driver **não estava carregado** e nada do que se seguir
tem a ver com ele. Se listar, olhe a pilha: sem um quadro `SafeUpload!` nela,
a probabilidade de ser nosso cai muito.

Esta VM já produziu dois bugchecks assim, ambos no caminho do **console** e
nenhum com o driver envolvido:

| Bugcheck | Pilha | Driver carregado? |
|---|---|---|
| `0x3B` | `condrv!CdCompleteIo`, em `conhost.exe` | não |
| `0xA` | `nt!KiDeliverApc` vindo de `NtDeviceIoControlFile` do console, em `powershell.exe` | não |

O regime que os produz parece ser console sob carga com um depurador de
kernel anexado. Custaram duas rodadas de investigação antes de alguém rodar
`lm m SafeUpload`. Rode primeiro.

Uma ressalva honesta: corrupção de memória causada por um driver pode
aparecer na estrutura de outro, bem depois. Ausência do nosso nome na pilha é
evidência forte, não prova. Se houver motivo para desconfiar, `verifier
/standard /all` instrumenta todos os drivers e encontra quem corrompe — ao
custo de deixar a VM bem mais lenta.

**9f. Bugchecks típicos com Driver Verifier ligado:**

| Bugcheck | Significado provável |
|---|---|
| `0xC4 DRIVER_VERIFIER_DETECTED_VIOLATION` | Violação genérica; o subcódigo diz qual. |
| `0xC1 SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION` | Escrita fora do bloco ou uso depois do `ExFreePoolWithTag`. |
| `0xC9 DRIVER_IRQL_NOT_LESS_OR_EQUAL` | Chamada bloqueante acima de `PASSIVE_LEVEL`. |
| `0xD0/0x0A` | Ponteiro inválido em IRQL elevado. |

Para inspecionar o pool deste driver especificamente (tag `SUfl`):

```
!poolused 2 SUfl
!poolfind SUfl
```

Um valor que só cresce em `!poolused` entre operações indica vazamento.

### 10. Recuperação: a VM alvo não inicializa

Ordem do mais barato para o mais caro:

**10a.** Se ela chega ao menu de boot: F8 → **Modo de Segurança**. O driver
é *demand start*, então não sobe em modo de segurança. De dentro dele:

```
verifier /reset
sc config SafeUpload start= disabled
```

Reinicie normalmente.

**10b.** Se nem isso funciona: **reverta o snapshot** do passo 1.

- Hyper-V: `Restore-VMSnapshot -VMName "<nome-da-vm>" -Name "pre-safeupload" -Confirm:$false`
- VMware / VirtualBox: pelo gerenciador de snapshots.

Reverter o snapshot é a saída garantida. É por isso que o passo 1 vem antes
de tudo.

---

## Contrato de mensagens (Protocol.h)

Esta seção existe para o **agente em C#** que substitui o
`SafeUpload.Inspector`. A fonte da verdade é
`driver/SafeUpload.Minifilter/Protocol.h`; o que está abaixo é a mesma
coisa descrita para quem marshala do outro lado.

Já existe uma implementação de referência em `service/`, e ela é o ponto de
partida recomendado em vez de reescrever o marshalling do zero:

| Arquivo | O que é |
|---|---|
| `service/SafeUpload.Protocol/Protocol.cs` | As cinco estruturas, com `Contract.Verify()` |
| `service/SafeUpload.Protocol/FilterPort.cs` | Conexão, laço de mensagens, resposta, canal de controle |
| `service/SafeUpload.Protocol/PolicyBuilder.cs` | Montagem da política e a conversão DOS → NT |
| `service/SafeUpload.Agent/Program.cs` | Cliente mínimo funcional, equivalente ao Inspector |

Para conferir o contrato sem driver nenhum:

```
dotnet run --project service\SafeUpload.Agent -- --verify
```

### Regras do contrato

1. Toda mensagem é uma **estrutura de tamanho fixo**. Sem ponteiros, sem
   cauda de tamanho variável, sem posse de memória cruzando a fronteira.
2. Todo campo tem **largura explícita** (`UINT32`, `UINT64`, `WCHAR`). Nada
   de `enum`, `BOOL` ou `ULONG_PTR` — nada cujo tamanho dependa do
   compilador ou do bitness do processo.
3. Os campos estão ordenados para **não haver padding implícito**. O
   `Protocol.h` tem `C_ASSERT` de tamanho e de offset de cada campo: se
   alguém mudar o layout sem manter a propriedade, o build do driver quebra.
4. Toda estrutura carrega `Version` e `StructSize`. Um par kernel/usuário
   incompatível é **detectado**, não mal interpretado.
5. Qualquer mensagem que o receptor não entenda vale **permitir**, nunca
   bloquear.

### Versão

`SAFEUPLOAD_PROTOCOL_VERSION` é **6**. Ela sobe sempre que o layout muda,
inclusive quando a mudança é só um contador novo: o receptor lê a estrutura
inteira de uma vez, então um campo acrescentado no meio desloca tudo o que
vem depois. Um cliente antigo contra um driver novo não leria um número
ligeiramente errado — leria os campos seguintes trocados entre si, e
números trocados são piores que números ausentes, porque parecem
plausíveis.

### Nome da porta

```
\SafeUploadPort
```

ACL: apenas SYSTEM e Administradores (descritor padrão do Filter Manager).
**Uma conexão simultânea, no máximo.**

Isso decide a arquitetura do lado usuário: quem segura a porta é o
**serviço Windows**, rodando como LocalSystem. O aplicativo WPF não se
conecta ao driver — ele conversa com o serviço. Não é preferência de
desenho, é o que a ACL e o limite de uma conexão permitem.

### As cinco mensagens

| Estrutura | Sentido | Tamanho |
|---|---|---:|
| `SAFEUPLOAD_REQUEST` | kernel → usuário | 1192 |
| `SAFEUPLOAD_RESPONSE` | usuário → kernel | 24 |
| `SAFEUPLOAD_CONTROL` | usuário → kernel | 16 |
| `SAFEUPLOAD_POLICY_MESSAGE` | usuário → kernel | 19752 |
| `SAFEUPLOAD_COUNTERS` | kernel → usuário (resposta) | 144 |

As duas primeiras trafegam pelo par `FilterGetMessage` /
`FilterReplyMessage`. As três últimas pelo `FilterSendMessage`, que é o
canal de controle e vai no sentido oposto.

### `SAFEUPLOAD_REQUEST` — kernel → usuário (1192 bytes)

| Offset | Tamanho | Campo | Descrição |
|---:|---:|---|---|
| 0 | 4 | `Version` | `6`. |
| 4 | 4 | `StructSize` | `1192`. |
| 8 | 8 | `RequestId` | Identificador monotônico. A resposta **tem que** repeti-lo. |
| 16 | 4 | `Operation` | `1` = CREATE. O `2` = READ existe no contrato mas não ocorre: `IRP_MJ_READ` não é registrado. |
| 20 | 4 | `RequestorProcessId` | PID de quem pediu a operação. |
| 24 | 4 | `Flags` | Ver abaixo. |
| 28 | 4 | `PathLength` | **Bytes**, sem o terminador. |
| 32 | 4 | `ImageNameLength` | **Bytes**, sem o terminador. |
| 36 | 4 | `Reserved` | Zero. |
| 40 | 1024 | `Path[512]` | Caminho em forma de dispositivo. |
| 1064 | 128 | `ImageName[64]` | Nome da imagem, sem caminho. |

Flags:

| Valor | Nome | Significado |
|---:|---|---|
| 0x01 | `PATH_TRUNCATED` | O caminho não coube em 512 caracteres. |
| 0x02 | `IMAGE_NAME_TRUNCATED` | O nome da imagem não coube em 64. |
| 0x04 | `PATH_NOT_NORMALIZED` | A normalização falhou; o caminho é o de abertura. |
| 0x08 | `SCOPE_DESTINATION` | A operação vai para um destino monitorado. |
| 0x10 | `SCOPE_SOURCE` | A operação lê de uma origem monitorada. |

Os dois últimos são a informação que o serviço usa para decidir o que a
resposta significa. Uma negação em escopo de **origem** marca o processo;
uma negação em escopo de **destino** cancela a abertura.

`PathLength` vem do kernel e é o tamanho em bytes, não em caracteres.
Divida por dois antes de indexar, e **limite ao tamanho do campo** antes de
usar: indexar um buffer fixo com um valor não conferido é a diferença entre
um cliente correto e um que lê fora da estrutura.

### `SAFEUPLOAD_RESPONSE` — usuário → kernel (24 bytes)

| Offset | Tamanho | Campo | Descrição |
|---:|---:|---|---|
| 0 | 4 | `Version` | `6`. |
| 4 | 4 | `StructSize` | `24`. |
| 8 | 8 | `RequestId` | O mesmo que chegou. |
| 16 | 4 | `Verdict` | `0` = permitir, `1` = negar. |
| 20 | 4 | `Reserved` | Zero. |

### `SAFEUPLOAD_CONTROL` — usuário → kernel (16 bytes)

Cabeçalho de todo comando pelo `FilterSendMessage`.

| Offset | Tamanho | Campo | Descrição |
|---:|---:|---|---|
| 0 | 4 | `Version` | `6`. |
| 4 | 4 | `StructSize` | Tamanho da mensagem **inteira**, não do cabeçalho. |
| 8 | 4 | `Command` | `1` = SET_POLICY, `2` = GET_COUNTERS. |
| 12 | 4 | `Reserved` | Zero. |

### `SAFEUPLOAD_POLICY_MESSAGE` — usuário → kernel (19752 bytes)

**Sem esta mensagem o driver não inspeciona nada.** Ele sobe sem política e
libera tudo; não há padrão embutido. Empurrar a política é o passo que liga
o filtro, não configuração opcional.

| Offset | Tamanho | Campo | Descrição |
|---:|---:|---|---|
| 0 | 16 | `Control` | Com `Command` = 1. |
| 16 | 4 | `ExtensionCount` | Máximo 32. |
| 20 | 4 | `PrefixCount` | Destinos, máximo 16. |
| 24 | 4 | `ImageCount` | Imagens excluídas, máximo 16. |
| 28 | 4 | `SourcePrefixCount` | Origens, máximo 16. |
| 32 | 4 | `Flags` | `0x01` = todo volume removível, `0x02` = toda rede. |
| 36 | 4 | `Reserved` | Zero. |
| 40 | 1024 | `Extensions[32][16]` | Com o ponto: `.docx`. |
| 1064 | 8320 | `Prefixes[16][260]` | Destinos monitorados. |
| 9384 | 8320 | `SourcePrefixes[16][260]` | Origens sensíveis. |
| 17704 | 2048 | `Images[16][64]` | Processos ignorados, só o nome. |

Cada entrada ocupa um slot de tamanho fixo e **tem que terminar em nulo**:
o kernel mede a string, então uma entrada escrita até o último caractere do
slot invade o próximo.

#### A armadilha dos caminhos

Os prefixos têm de estar em **forma de dispositivo**:

```
\Device\HarddiskVolume3\safeupload-teste
```

e **não**

```
C:\safeupload-teste
```

O kernel compara com os nomes que o Filter Manager entrega, e esses são
sempre em forma de dispositivo. Um prefixo em forma DOS não casa com nada.
O sintoma é cruel: o driver carrega, anexa, responde, e simplesmente não
inspeciona — porque permitir é o padrão seguro. Nenhum erro aparece em
lugar nenhum; o único sinal é `ScopeEvaluations` parado em zero.

A conversão é `QueryDosDeviceW` sobre a letra da unidade, concatenada com o
resto do caminho. Está pronta em `PolicyBuilder.ToNtPath`.

Caminhos UNC não têm dispositivo DOS a resolver. Destinos de rede são
cobertos pelo flag `0x02`, não por prefixo.

### `SAFEUPLOAD_COUNTERS` — resposta de GET_COUNTERS (144 bytes)

Enviar um `SAFEUPLOAD_CONTROL` com `Command` = 2 e um buffer de saída de
144 bytes. `Version` e `StructSize` nos offsets 0 e 4; a partir do 8, e nesta
ordem, dezessete `UINT64`:

```
CreatesSeen  CreatesPastCheapGates  ScopeEvaluations  UserModeRoundTrips
CacheHits  DeniedPreCreate  DeniedPostCreate  DeniedRename
AllowedWithoutInspection  TaintsRecorded  TaintLookups  TaintHits
SetInformationSeen  RenamesSeen  RenamesFromTainted
ClassesSeenLow  ClassesSeenHigh
```

`AllowedWithoutInspection` é o que o serviço precisa vigiar: ele conta
operações que passaram **sem inspeção** porque a resposta não chegou a
tempo. Crescendo, o usuário está trabalhando sem proteção e nada mais no
sistema vai avisar.

### Como o Filter Manager embrulha as mensagens

Cada requisição chega precedida de um cabeçalho de 16 bytes, e cada resposta
tem de ser precedida de outro:

```c
typedef struct _FILTER_MESSAGE_HEADER {
    ULONG     ReplyLength;
    ULONGLONG MessageId;
} FILTER_MESSAGE_HEADER;   //  16 bytes: o ULONGLONG alinha em 8

typedef struct _FILTER_REPLY_HEADER {
    NTSTATUS  Status;
    ULONGLONG MessageId;
} FILTER_REPLY_HEADER;     //  16 bytes, mesma razão
```

Então o buffer de leitura tem 16 + 1192 = **1208** bytes e o de resposta
16 + 24 = **40**. O `MessageId` da resposta é o que chegou; `Status` é um
NTSTATUS do transporte e **não** é o veredito — o veredito viaja no corpo.

### O orçamento de 500 ms

O driver espera pelo veredito com timeout, e pela RN-013 um timeout vale
**permitir**. Isso tem uma consequência que precisa estar clara antes de
qualquer linha do serviço ser escrita:

> Tudo que o serviço fizer entre receber a requisição e responder é tempo
> em que a abertura do arquivo está parada. Se passar do orçamento, o
> driver desiste e libera — e o arquivo passa **sem inspeção**, sem erro,
> sem log do lado do kernel além de um contador.

Hash, consulta a disco, chamada de rede, lock que outra thread pode segurar:
nada disso pode estar no caminho síncrono. O que não couber no orçamento
tem de ficar atrás de um cache que a função de decisão apenas lê.

`FilterGetMessage` também bloqueia. Numa thread só, toda abertura
monitorada da máquina enfileira atrás do veredito mais lento — a
implementação de referência é single-thread de propósito, para ser legível,
e um serviço real precisa de um pool.

## Limitações conhecidas da v1

Coisas que são verdade hoje e que a v2 precisa resolver. Nenhuma delas é
bug; todas são escopo que ficou de fora conscientemente.

**1. Altitude provisória.** 321410 está na faixa correta (FSFilter
Anti-Virus, 320000–329999) mas **não foi alocada para este produto**. Em
qualquer máquina que já rode um antivírus real há risco de colisão, e dois
filtros na mesma altitude não coexistem. A altitude definitiva precisa ser
solicitada à Microsoft antes de qualquer instalação fora de VM descartável.
O TODO está no `SafeUpload.inf`.

**2. ~~Custo de interceptar `IRP_MJ_READ`.~~ Resolvido.** Na v1 toda leitura
não-paginada virava uma ida ao modo usuário, e a VM ficava perceptivelmente
mais lenta sob carga de I/O. O gancho de `READ` foi **removido** e o veredito
passou a ser guardado em contexto de fluxo: uma consulta por versão de
arquivo, não por leitura. Medido, com o alvo do desenho atingido — 0,9% dos
creates passam das portas baratas, contra o `< 1%` projetado. Ver
`ARQUITETURA.md` para o raciocínio e para as evidências sob as quais um
gancho de leitura voltaria.

**3. Cliente de thread única.** O laço de mensagens atende uma requisição por
vez, de forma síncrona, e vale tanto para a sonda quanto para o
`MinifilterInterceptor` do serviço: `FilterGetMessage` bloqueia a thread que
o chama. Todas as outras operações monitoradas da máquina ficam na fila atrás
da mais lenta. A saída é I/O sobreposto com um pool sobre a mesma porta, como
faz o sample `scanner` do WDK.

**4. Espera circular limitada pelo timeout.** Se o inspetor bloquear em uma
operação de arquivo que passa por este mesmo filtro (por exemplo escrevendo
um log através de um processo intermediário), forma-se uma espera circular.
Ela **não** trava a máquina: o timeout de 500 ms a rompe e a operação é
permitida. Mas cada ocorrência custa 500 ms. O agente C# deve evitar I/O de
arquivo no caminho de resposta.

**5. Caminhos em forma NT.** O driver entrega
`\Device\HarddiskVolume3\...`, não `C:\...`. A conversão para forma DOS é
responsabilidade do modo usuário (`QueryDosDevice` / tabela de volumes).

**6. Sem versionamento de recurso no binário.** O `.sys` não tem bloco
`VERSIONINFO`. Antes de qualquer assinatura de produção, adicionar um `.rc`
com `VERSIONINFO` ao projeto do driver.

**7. Sem parâmetros de registro.** O timeout de 500 ms é constante de
compilação (`SAFEUPLOAD_VERDICT_TIMEOUT_MS`, em `Filter.h`). O `RegistryPath`
recebido no `DriverEntry` é deliberadamente ignorado nesta versão.

**8. Comportamento do buffer de resposta no timeout — verificado
empiricamente.** O driver aloca requisição e resposta em um único bloco de
pool e o libera assim que `FltSendMessage` retorna, inclusive quando ela
retorna `STATUS_TIMEOUT`. Isso assume que o Filter Manager não escreve mais
no buffer depois de retornar.

Essa suposição foi exercitada na VM alvo com o Driver Verifier
(`/standard`, Special Pool ativo), congelando o inspetor pelo modo de
seleção do console — o que o prende dentro do `wprintf`, antes do
`FilterReplyMessage`, com a porta ainda aberta — e gerando I/O em paralelo.
Resultado:

```
MODULE: SafeUpload.sys (load: 1 / unload: 0)
    Current Pool Allocations:  (      0 /      0 )
    Current Pool Bytes:        (      0 /      0 )
    Peak Pool Allocations:     (     33 /      0 )
    Peak Pool Bytes:           (  40128 /      0 )
```

Leitura desses números: 40128 ÷ 33 = 1216 bytes, exatamente
`sizeof(SAFEUPLOAD_EXCHANGE)`, então toda alocação rastreada é o bloco de
exchange e não há nenhuma outra. `Peak 33` são 33 threads simultaneamente
paradas no `FltSendMessage`, ou seja, o caminho de timeout foi de fato
percorrido em volume. `Current 0` confirma que tudo foi liberado — sem
vazamento. `Paged 0` confirma que só há pool não-paginado.

Nenhum bugcheck ocorreu. Como o Special Pool coloca cada alocação em página
própria e marca a página liberada como inacessível, uma escrita tardia do
Filter Manager teria causado `0xC1` imediato. Evidência forte, embora
empírica: se um dia esse caminho passar a dar `0xC1`
(`SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION`), a correção é não liberar o
bloco no retorno de `STATUS_TIMEOUT` — mantê-lo até o unload, ou trocar por
um buffer por-thread reaproveitado.

**Repita este teste sempre que o caminho de veredito mudar.** O
procedimento está no passo 6 e a forma de forçar o timeout é a descrita
acima.
