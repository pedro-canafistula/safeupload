#ifndef PayloadRoot
  #error PayloadRoot is required; use Build-AgentInstaller.ps1
#endif
#ifndef ArtifactOutput
  #error ArtifactOutput is required
#endif
#ifndef AgentVersion
  #define AgentVersion "0.1.2"
#endif

#if FileExists(AddBackslash(PayloadRoot) + "prereq\winfsp.msi")
  #define WinFspBundled "true"
#else
  #define WinFspBundled "false"
#endif

[Setup]
AppId={{772C11DF-43ED-48B1-9303-D4339A210D89}
AppName=SafeUpload Agent
AppVersion={#AgentVersion}
AppPublisher=Equipe SafeUpload
DefaultDirName={autopf}\SafeUpload\Agent
DisableDirPage=yes
DefaultGroupName=SafeUpload Agent
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
OutputDir={#ArtifactOutput}
OutputBaseFilename=SafeUploadAgent-{#AgentVersion}-win-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\ui\SafeUpload.Agent.App.exe
SetupLogging=yes
CloseApplications=no
RestartApplications=no
DisableWelcomePage=no
LicenseFile=..\..\LICENSE
InfoBeforeFile=INSTALLATION-NOTICE.txt

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Files]
Source: "{#PayloadRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "support\Invoke-AgentSetup.ps1"; Flags: dontcopy
Source: "support\SafeUpload.Setup.psm1"; Flags: dontcopy
Source: "support\SafeUpload.Maintenance.psm1"; Flags: dontcopy

[Icons]
Name: "{commonprograms}\SafeUpload Agent\Abrir agente"; Filename: "{app}\ui\SafeUpload.Agent.App.exe"
Name: "{commonprograms}\SafeUpload Agent\Desinstalar agente"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\ui\SafeUpload.Agent.App.exe"; Description: "Abrir a interface do agente"; Flags: postinstall nowait skipifsilent runasoriginaluser unchecked

[UninstallDelete]
Type: files; Name: "{app}\setup\installation.json"

[Code]
var
  ModePage: TInputOptionWizardPage;
  ServerPage: TInputQueryWizardPage;
  InstallationSucceeded: Boolean;

function SelectedMode: String;
begin
  if ModePage.Values[1] then Result := 'FileSystemWatcher'
  else Result := 'Drive';
end;

function JsonEscape(const Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '\', '\\', True);
  StringChangeEx(Result, '"', '\"', True);
  StringChangeEx(Result, #13, '\r', True);
  StringChangeEx(Result, #10, '\n', True);
  StringChangeEx(Result, #9, '\t', True);
end;

function RunSetupAction(const ScriptPath, ActionName: String; IncludeAnswers: Boolean): String;
var
  Parameters, ResultFile: String;
  Detail: AnsiString;
  ExitCode: Integer;
begin
  Result := '';
  ResultFile := ExpandConstant('{tmp}\safeupload-result.txt');
  DeleteFile(ResultFile);
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptPath +
    '" -Action ' + ActionName + ' -InstallRoot "' + ExpandConstant('{app}') + '" -ResultPath "' + ResultFile + '"';
  if IncludeAnswers then
    Parameters := Parameters + ' -AnswersPath "' + ExpandConstant('{tmp}\safeupload-answers.json') + '"';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Parameters, '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    Result := 'Não foi possível executar a configuração do serviço.'
  else if ExitCode <> 0 then begin
    Result := 'A configuração foi interrompida. Consulte o log de instalação.';
    if LoadStringFromFile(ResultFile, Detail) then Result := Result + #13#10 + UTF8Decode(Detail);
  end;
  if Result <> '' then Log(Result);
end;

procedure InitializeWizard;
var
  ModeParameter: String;
begin
  ModePage := CreateInputOptionPage(wpSelectDir, 'Modo de instalação', 'Escolha como o agente será utilizado.',
    'O modo sem driver é destinado a testes e observa arquivos após a gravação. Ele não oferece o bloqueio preventivo das unidades SafeUpload.', True, False);
  ModePage.Add('Unidades SafeUpload: pastas protegidas, pendrives e compartilhamentos inspecionados antes do envio (WinFsp e driver gate)');
  ModePage.Add('Teste sem driver: serviço com observação de arquivos');
  ModeParameter := ExpandConstant('{param:MODE|Drive}');
  if (CompareText(ModeParameter, 'Drive') <> 0) and (CompareText(ModeParameter, 'FileSystemWatcher') <> 0) then
    RaiseException('MODE deve ser Drive ou FileSystemWatcher.');
  ModePage.Values[0] := CompareText(ModeParameter, 'Drive') = 0;
  ModePage.Values[1] := not ModePage.Values[0];
  ServerPage := CreateInputQueryPage(ModePage.ID, 'Servidor de administração', 'Informe o endereço combinado com a equipe.',
    'Use HTTPS em servidores remotos e termine o endereço com /agent/. Deixe vazio para usar a política local, sem sincronização web.');
  ServerPage.Add('URL da API do agente:', False);
  ServerPage.Values[0] := ExpandConstant('{param:ADMINURL|}');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Answers: String;
begin
  ExtractTemporaryFile('Invoke-AgentSetup.ps1');
  ExtractTemporaryFile('SafeUpload.Setup.psm1');
  ExtractTemporaryFile('SafeUpload.Maintenance.psm1');
  Answers := '{"mode":"' + SelectedMode + '","adminBaseUrl":"' + JsonEscape(ServerPage.Values[0]) +
    '","winFspBundled":{#WinFspBundled}}';
  if not SaveStringToFile(ExpandConstant('{tmp}\safeupload-answers.json'), UTF8Encode(Answers), False) then begin
    Result := 'Não foi possível preparar a configuração.';
    Exit;
  end;
  Result := RunSetupAction(ExpandConstant('{tmp}\Invoke-AgentSetup.ps1'), 'Preflight', True);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Failure: String;
begin
  if CurStep = ssPostInstall then begin
    Failure := RunSetupAction(ExpandConstant('{app}\setup\Invoke-AgentSetup.ps1'), 'Install', True);
    if Failure <> '' then RaiseException(Failure);
    InstallationSucceeded := True;
  end;
end;

function NeedRestart: Boolean;
begin
  Result := False;
end;

function InitializeUninstall: Boolean;
var
  Failure: String;
begin
  Failure := RunSetupAction(ExpandConstant('{app}\setup\Invoke-AgentSetup.ps1'), 'CheckUninstall', False);
  Result := Failure = '';
  if not Result then MsgBox(Failure, mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Failure: String;
begin
  if CurUninstallStep = usUninstall then begin
    Failure := RunSetupAction(ExpandConstant('{app}\setup\Invoke-AgentSetup.ps1'), 'Uninstall', False);
    if Failure <> '' then RaiseException(Failure);
  end;
end;
