#requires -Version 5.1
# Returns the private per-instance oobeSystem answer (XML text) built from the shared Sysprep template. No side effects.
# Windows 10 client ignores HideLocalAccountScreen (Server only). Naming the existing account, as the install answer
# does, skips account creation; one autologon then starts the SYSTEM cleanup task (Complete-Oobe.ps1).
param([Parameter(Mandatory)][string] $TemplatePath, [Parameter(Mandatory)][string] $Password)
$ErrorActionPreference = 'Stop'
[xml]$template = Get-Content -LiteralPath $TemplatePath -Raw
$ns = New-Object Xml.XmlNamespaceManager($template.NameTable)
$ns.AddNamespace('u','urn:schemas-microsoft-com:unattend')
$oobe = $template.SelectSingleNode('/u:unattend/u:settings[@pass="oobeSystem"]',$ns)
if ($null -eq $oobe -or $oobe.SelectNodes('.//u:UserAccounts|.//u:AutoLogon|.//u:Password',$ns).Count) {
    throw 'The shared template must have an oobeSystem pass without accounts or passwords.'
}
$answer = New-Object Xml.XmlDocument
[void]$answer.AppendChild($answer.CreateXmlDeclaration('1.0','utf-8',$null))
[void]$answer.AppendChild($answer.CreateElement('unattend','urn:schemas-microsoft-com:unattend'))
[void]$answer.DocumentElement.AppendChild($answer.ImportNode($oobe,$true))
$shell = $answer.SelectSingleNode('//*[local-name()="component" and @name="Microsoft-Windows-Shell-Setup"]')
$uri = $shell.NamespaceURI
$secret = $answer.CreateElement('Password',$uri)
foreach ($pair in @(@('Value',$Password),@('PlainText','true'))) {
    $node = $answer.CreateElement($pair[0],$uri); $node.InnerText = $pair[1]; [void]$secret.AppendChild($node)
}
$account = $answer.CreateElement('LocalAccount',$uri)
$action = $answer.CreateAttribute('wcm','action','http://schemas.microsoft.com/WMIConfig/2002/State'); $action.Value = 'add'
[void]$account.Attributes.Append($action)
foreach ($pair in @(@('Name','vika'),@('Group','Administrators'))) {
    $node = $answer.CreateElement($pair[0],$uri); $node.InnerText = $pair[1]; [void]$account.AppendChild($node)
}
[void]$account.AppendChild($secret.CloneNode($true))
$locals = $answer.CreateElement('LocalAccounts',$uri); [void]$locals.AppendChild($account)
$users = $answer.CreateElement('UserAccounts',$uri); [void]$users.AppendChild($locals); [void]$shell.AppendChild($users)
$auto = $answer.CreateElement('AutoLogon',$uri)
foreach ($pair in @(@('Enabled','true'),@('LogonCount','1'),@('Username','vika'))) {
    $node = $answer.CreateElement($pair[0],$uri); $node.InnerText = $pair[1]; [void]$auto.AppendChild($node)
}
[void]$auto.AppendChild($secret); [void]$shell.AppendChild($auto)
$answer.OuterXml
