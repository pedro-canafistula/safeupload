#requires -Version 5.1
$ErrorActionPreference='Stop'
$out='C:\T5\m2dev1019a-word\result.json'
$row=[ordered]@{User=[Security.Principal.WindowsIdentity]::GetCurrent().Name;Pid=$PID;Session=[Diagnostics.Process]::GetCurrentProcess().SessionId;Path='C:\Protected\m2dev1019a-word-clean.docx';Text='Quarterly meeting notes without personal data.';Passed=$false}
$word=$null;$document=$null
try {
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $row.Session -ne 1 -or $row.User -notmatch '\\t5actor$'){throw 'Interactive standard t5actor required'}
    if(Test-Path -LiteralPath $row.Path){throw 'Fresh destination required'}
    $word=New-Object -ComObject Word.Application
    $word.Visible=$true;$word.DisplayAlerts=0
    $document=$word.Documents.Add()
    $document.Content.Text=$row.Text
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $document.SaveAs2($row.Path)
    $row.SaveElapsedMilliseconds=$timer.ElapsedMilliseconds
    $row.AppSaved=[bool]$document.Saved
    $row.AppReadOnly=[bool]$document.ReadOnly
    $document.Close(0);[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($document);$document=$null
    $row.Passed=$row.AppSaved -and -not $row.AppReadOnly
} catch { $row.Error=($_|Out-String);$row.Stack=$_.ScriptStackTrace }
finally {
    if($document){$document.Close(0);[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($document)}
    if($word){$word.Quit();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($word)}
    $row|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $out -Encoding UTF8
}
if(-not $row.Passed){exit 1}
