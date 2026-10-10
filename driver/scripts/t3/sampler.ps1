# Samples the driver counters every 3 seconds into C:\T3\samples.jsonl (registry high-water mark, reclaim passes, Unknown reasons).
$d = 'C:\Users\vika\Documents'
while ($true) {
    try { $c = & "$d\Get-SafeUploadDiagnostics.ps1" -Query counters; ($c | ConvertTo-Json -Depth 6 -Compress) | Add-Content -LiteralPath C:\T3\samples.jsonl }
    catch { ('ERR ' + $_.Exception.Message) | Add-Content -LiteralPath C:\T3\samples.jsonl }
    Start-Sleep -Seconds 3
}
