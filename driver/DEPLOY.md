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

Esta seção existe para o **agente WPF em C#** que vai substituir o
`SafeUpload.Inspector`. A fonte da verdade é
`driver/SafeUpload.Minifilter/Protocol.h`; o que está abaixo é a mesma coisa
descrita para quem vai marshalar do outro lado.

### Regras do contrato

1. Toda mensagem é uma **estrutura de tamanho fixo**. Sem ponteiros, sem
   cauda de tamanho variável, sem posse de memória cruzando a fronteira.
2. Todo campo tem **largura explícita** (`UINT32`, `UINT64`, `WCHAR`). Nada
   de `enum`, `BOOL` ou `ULONG_PTR` — nada cujo tamanho dependa do
   compilador ou do bitness do processo.
3. Os campos estão ordenados para **não haver padding implícito**. O
   `Protocol.h` tem `C_ASSERT` de tamanho e de offset de cada campo: se
   alguém mudar o layout sem manter a propriedade, o build do driver quebra.
4. As duas estruturas carregam `Version` e `StructSize`. Um par
   kernel/usuário incompatível é **detectado**, não mal interpretado.
5. Qualquer mensagem que o receptor não entenda vale **permitir**, nunca
   bloquear.

### Nome da porta

```
\SafeUploadPort
```

ACL: apenas SYSTEM e Administradores (descritor padrão do Filter Manager).
Uma conexão simultânea, no máximo.

### `SAFEUPLOAD_REQUEST` — kernel → usuário (1192 bytes)

| Offset | Tamanho | Campo | Descrição |
|---:|---:|---|---|
| 0 | 4 | `Version` | `1` nesta versão. |
| 4 | 4 | `StructSize` | `1192`. |
| 8 | 8 | `RequestId` | Identificador monotônico. A resposta **tem que** repeti-lo. |
| 16 | 4 | `Operation` | `1` = CREATE, `2` = READ. |
| 20 | 4 | `RequestorProcessId` | PID de quem pediu a operação. |
| 24 | 4 | `Flags` | Ver tabela abaixo. |
| 28 | 4 | `PathLength` | Bytes úteis em `Path`, sem o terminador. |
| 32 | 4 | `ImageNameLength` | Bytes úteis em `ImageName`, sem o terminador. |
| 36 | 4 | `Reserved` | Sempre 0. |
| 40 | 1024 | `Path[512]` | Caminho NT do arquivo, terminado em NUL. |
| 1064 | 128 | `ImageName[64]` | Último componente da imagem do processo, terminado em NUL. |

`Flags`:

| Valor | Nome | Significado |
|---:|---|---|
| `0x01` | `PATH_TRUNCATED` | O caminho não coube em 511 caracteres e foi cortado. |
| `0x02` | `IMAGE_NAME_TRUNCATED` | O nome da imagem foi cortado. |
| `0x04` | `PATH_NOT_NORMALIZED` | Não foi possível obter o nome normalizado; `Path` traz o nome aberto (pode ser relativo, nome curto, ou por outro ponto de montagem). Usável, mas **não** confiável para comparação byte a byte contra lista de política. |

### `SAFEUPLOAD_RESPONSE` — usuário → kernel (24 bytes)

| Offset | Tamanho | Campo | Descrição |
|---:|---:|---|---|
| 0 | 4 | `Version` | `1`. |
| 4 | 4 | `StructSize` | `24`. |
| 8 | 8 | `RequestId` | Cópia do `RequestId` da requisição. |
| 16 | 4 | `Verdict` | `0` = permitir, `1` = bloquear. Qualquer outro valor é tratado como permitir. |
| 20 | 4 | `Reserved` | Sempre 0. |

O driver descarta a resposta — e permite a operação — se `Version`,
`StructSize` ou `RequestId` não casarem. O eco do `RequestId` é o que impede
que uma resposta atrasada, de uma requisição que já estourou o timeout, seja
tomada como a resposta da requisição atual.

### Como o Filter Manager embrulha as mensagens

O driver envia só o `SAFEUPLOAD_REQUEST`. O Filter Manager prefixa um
`FILTER_MESSAGE_HEADER` (16 bytes: `UINT32 ReplyLength` + padding +
`UINT64 MessageId`) antes de o modo usuário ver. A resposta vai prefixada
por um `FILTER_REPLY_HEADER` (16 bytes: `NTSTATUS Status` + padding +
`UINT64 MessageId`), e o `MessageId` da resposta **tem que ser** o mesmo da
mensagem recebida.

Ou seja: buffer de recepção = 16 + 1192 = **1208 bytes**; buffer de resposta
= 16 + 24 = **40 bytes**.

### Esqueleto de marshalling em C#

```csharp
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct FilterMessageHeader
{
    public uint  ReplyLength;
    public ulong MessageId;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct FilterReplyHeader
{
    public int   Status;      // NTSTATUS
    public ulong MessageId;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct SafeUploadRequest
{
    public uint  Version;
    public uint  StructSize;
    public ulong RequestId;
    public uint  Operation;
    public uint  RequestorProcessId;
    public uint  Flags;
    public uint  PathLength;
    public uint  ImageNameLength;
    public uint  Reserved;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Path;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ImageName;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadResponse
{
    public uint  Version;
    public uint  StructSize;
    public ulong RequestId;
    public uint  Verdict;
    public uint  Reserved;
}
```

Valide na inicialização do agente, para não descobrir o desalinhamento em
produção:

```csharp
Debug.Assert(Marshal.SizeOf<SafeUploadRequest>()  == 1192);
Debug.Assert(Marshal.SizeOf<SafeUploadResponse>() == 24);
```

As três funções necessárias vêm de `fltlib.dll`:
`FilterConnectCommunicationPort`, `FilterGetMessage`, `FilterReplyMessage`.
O processo do agente precisa rodar como SYSTEM ou como Administrador para
abrir a porta.

Ao trocar o inspetor pelo agente C#, o **serviço** `SafeUpload.Agent.Service`
é o candidato natural a dono da porta (já roda como serviço e já fala com o
app WPF por named pipe). O app WPF não deve abrir a porta diretamente: ele
roda na sessão do usuário, sem privilégio, e uma sessão desconectada
deixaria o driver sem inspetor.

---

## Limitações conhecidas da v1

Coisas que são verdade hoje e que a v2 precisa resolver. Nenhuma delas é
bug; todas são escopo que ficou de fora conscientemente.

**1. Altitude provisória.** 321410 está na faixa correta (FSFilter
Anti-Virus, 320000–329999) mas **não foi alocada para este produto**. Em
qualquer máquina que já rode um antivírus real há risco de colisão, e dois
filtros na mesma altitude não coexistem. A altitude definitiva precisa ser
solicitada à Microsoft antes de qualquer instalação fora de VM descartável.
O TODO está no `SafeUpload.inf`.

**2. Custo de interceptar `IRP_MJ_READ`.** Com o inspetor conectado, **toda**
leitura não-paginada de todo processo (fora Idle/System/inspetor) vira uma
ida e volta ao modo usuário. Isso é caro. O teto por operação é o timeout de
500 ms, então o sistema não trava, mas a VM fica perceptivelmente mais lenta
sob carga de I/O. A v2 deve guardar o veredito por *stream handle context* e
consultar o modo usuário uma vez por handle, não uma vez por leitura.

**3. Inspetor de thread única.** O `SafeUpload.Inspector` atende uma
requisição por vez, de forma síncrona. Todas as outras operações do sistema
ficam na fila atrás dela. O agente C# deve usar I/O sobreposto com um pool
de threads, como faz o sample `scanner` do WDK.

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
