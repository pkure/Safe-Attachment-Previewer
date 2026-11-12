# hal-id: #HAL-20261107-0018-PK-R2
# Azure Automation runbook (PowerShell 7.4, system-assigned managed identity).
#   -Mode Watch  : every 30 s, take messages from secops-triage Inbox/Sandbox, ship their file attachments to
#                  vm-sandbox (blob cases/<caseId>), run analyze.ps1 there, write a verdict mail to Sandbox/Done,
#                  move the original to Sandbox/Done. Stops after -MaxMinutes.
#   -Mode Inject : create one test email per blob in the 'samples' container (TEST SAMPLES ONLY).
# Mailbox access comes from Exchange RBAC for Applications (scoped to CustomAttribute1 = sandbox-poc), not Entra roles.
# Email content (subject, sender, filenames) is untrusted: it is HTML-encoded in reports and never executed.
param(
    [ValidateSet('Watch', 'Inject', 'Once')][string]$Mode = 'Watch',
    [ValidateRange(1, 170)][int]$MaxMinutes = 90
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

Connect-AzAccount -Identity | Out-Null
$Mbx = Get-AutomationVariable -Name TriageMailbox
$Account = Get-AutomationVariable -Name StorageAccount
$VmName = Get-AutomationVariable -Name SandboxVmName
$Rg = Get-AutomationVariable -Name ResourceGroup
$PeIp = Get-AutomationVariable -Name PrivateEndpointIp
Set-AzContext -Subscription (Get-AutomationVariable -Name SubscriptionId) | Out-Null
$Graph = "https://graph.microsoft.com/v1.0/users/$Mbx"
$Blob = "https://$Account.blob.core.windows.net"
$MaxAttachmentBytes = 25MB

function Get-Token([string]$Resource) {
    $t = (Get-AzAccessToken -ResourceUrl $Resource -WarningAction SilentlyContinue).Token
    if ($t -is [securestring]) { $t = [Net.NetworkCredential]::new('', $t).Password }
    $t
}

function Invoke-Graph([string]$Method, [string]$Uri, $Body) {
    $p = @{ Method = $Method; Uri = $Uri; Headers = @{ Authorization = "Bearer $(Get-Token 'https://graph.microsoft.com')" } }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 8); $p.ContentType = 'application/json' }
    Invoke-RestMethod @p
}

function Get-StorageHeaders {
    @{ Authorization = "Bearer $(Get-Token 'https://storage.azure.com')"; 'x-ms-version' = '2023-11-03' }
}

function Get-OrCreateFolder([string]$ParentUri, [string]$Name) {
    $f = (Invoke-Graph GET "$ParentUri/childFolders?`$filter=displayName eq '$Name'").value | Select-Object -First 1
    if (-not $f) { $f = Invoke-Graph POST "$ParentUri/childFolders" @{ displayName = $Name } }
    $f
}

# A message created through Graph is a draft unless PR_MESSAGE_FLAGS (0x0E07) is set at creation; 1 = read, not draft.
$NotDraft = @(@{ id = 'Integer 0x0E07'; value = '1' })

function Enc([string]$s) { [Net.WebUtility]::HtmlEncode($s) }

function Format-Report($rep, $msg) {
    $color = switch ($rep.verdict) { 'MALICIOUS' { '#b00020' } 'SUSPICIOUS' { '#b26a00' } default { '#1b6e20' } }
    $rows = foreach ($f in $rep.files) {
        $detail = @()
        if ($f.defender) { $detail += "Defender: $($f.defender)" }
        if ($f.flags) { $detail += $f.flags }
        if ($f.note) { $detail += $f.note }
        if ($f.olevba -and $f.olevba.findings) { $detail += $f.olevba.findings }
        "<tr><td>$(Enc $f.name)</td><td>$($f.size)</td><td style='font-family:monospace;font-size:11px'>$(Enc $f.sha256)</td><td>$(Enc (($detail | Select-Object -Unique) -join '; '))</td></tr>"
    }
    @"
<div style='font-family:Segoe UI,Arial,sans-serif'>
<h2 style='color:$color;margin:0'>Sandbox verdict: $(Enc $rep.verdict)</h2>
<p>Case <b>$(Enc $rep.caseId)</b> &middot; analyzed $(Enc $rep.analyzedUtc) UTC on $(Enc $rep.sandbox)<br>
Original: <b>$(Enc $msg.subject)</b> from $(Enc $msg.from.emailAddress.address)<br>
Sandbox internet reachable during analysis: <b>$($rep.internetReached)</b> &middot; public DNS resolvable: <b>$($rep.dnsResolved)</b> &middot;
Defender signatures $(Enc $rep.defender.signatureVersion) ($(Enc $rep.defender.signatureDate))</p>
<table border='1' cellpadding='4' style='border-collapse:collapse;font-size:12px'>
<tr><th>File</th><th>Bytes</th><th>SHA-256</th><th>Findings</th></tr>
$($rows -join "`n")
</table>
<p style='font-size:11px;color:#666'>"No detections" is not proof a file is safe. Files stay in C:\cases\$(Enc $rep.caseId) on the sandbox until it is destroyed.
Open them only inside the sandbox (Bastion). TEST POC - not a production control.</p></div>
"@
}

function Invoke-Case($msg, $sandboxFolder, $doneFolder) {
    $caseId = '{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 4))
    Write-Output "case $caseId <- message $($msg.id.Substring(0,12))..."
    $h = Get-StorageHeaders
    $h['x-ms-blob-type'] = 'BlockBlob'
    $atts = (Invoke-Graph GET "$Graph/messages/$($msg.id)/attachments").value
    $n = 0
    foreach ($a in $atts) {
        if ($a.'@odata.type' -ne '#microsoft.graph.fileAttachment' -or $a.size -gt $MaxAttachmentBytes) { continue }
        $safe = ($a.name -replace '[^A-Za-z0-9._-]', '_')
        if ($safe.Length -gt 100) { $safe = $safe.Substring($safe.Length - 100) }
        $n++
        $bytes = [Convert]::FromBase64String($a.contentBytes)
        Invoke-WebRequest -Method Put -Headers $h -Body $bytes -ContentType 'application/octet-stream' `
            -Uri "$Blob/cases/$caseId/$n-$safe" | Out-Null
    }
    $boot = @"
`$ErrorActionPreference='Stop'; `$ProgressPreference='SilentlyContinue'
`$hosts="`$env:SystemRoot\System32\drivers\etc\hosts"; `$line='$PeIp $Account.blob.core.windows.net'
if (-not (Select-String -LiteralPath `$hosts -SimpleMatch `$line -Quiet)) { Add-Content -LiteralPath `$hosts -Value `$line }
`$t=(Invoke-RestMethod -Headers @{Metadata='true'} -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/').access_token
`$h=@{Authorization="Bearer `$t";'x-ms-version'='2023-11-03'}
if (-not (Test-Path 'C:\sbx\tools\ready')) {
  New-Item -ItemType Directory -Force C:\sbx | Out-Null
  Invoke-WebRequest -UseBasicParsing -Headers `$h -Uri '$Blob/tools/tools.zip' -OutFile C:\sbx\tools.zip
  Expand-Archive C:\sbx\tools.zip C:\sbx\tools -Force; Set-Content C:\sbx\tools\ready 1
}
& C:\sbx\tools\analyze.ps1 -CaseId '$caseId' -Account '$Account'
"@
    $rc = Invoke-AzVMRunCommand -ResourceGroupName $Rg -VMName $VmName -CommandId RunPowerShellScript -ScriptString $boot
    $out = ($rc.Value | ForEach-Object Message) -join ' '
    Write-Output "  sandbox: $out"
    try {
        $rep = Invoke-RestMethod -Headers (Get-StorageHeaders) -Uri "$Blob/reports/$caseId/report.json"
        $subject = "[Sandbox: $($rep.verdict)] $($msg.subject)"
        $html = Format-Report $rep $msg
    } catch {
        $subject = "[Sandbox: ERROR] $($msg.subject)"
        $html = "<p>Analysis failed for case $(Enc $caseId). Sandbox output:</p><pre>$(Enc $out)</pre>"
    }
    Invoke-Graph POST "$Graph/mailFolders/$($doneFolder.id)/messages" @{
        subject                       = $subject
        body                          = @{ contentType = 'HTML'; content = $html }
        from                          = @{ emailAddress = @{ name = 'Attachment Sandbox'; address = $Mbx } }
        toRecipients                  = @(@{ emailAddress = @{ address = $Mbx } })
        singleValueExtendedProperties = $NotDraft
    } | Out-Null
    Invoke-Graph POST "$Graph/messages/$($msg.id)/move" @{ destinationId = $doneFolder.id } | Out-Null
    Write-Output "  -> $subject"
}

if ($Mode -eq 'Inject') {
    [xml]$list = (Invoke-WebRequest -Headers (Get-StorageHeaders) -Uri "$Blob/samples?restype=container&comp=list").Content.TrimStart([char]0xFEFF)
    foreach ($b in $list.EnumerationResults.Blobs.Blob) {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
        Invoke-WebRequest -Headers (Get-StorageHeaders) -Uri "$Blob/samples/$($b.Name)" -OutFile $tmp
        $bytes = [IO.File]::ReadAllBytes($tmp); Remove-Item $tmp
        Invoke-Graph POST "$Graph/mailFolders/inbox/messages" @{
            subject                       = "[TEST SAMPLE] Payment documents - $($b.Name)"
            body                          = @{ contentType = 'Text'; content = "TEST SAMPLE for the attachment sandbox POC. Benign test file: $($b.Name)." }
            from                          = @{ emailAddress = @{ name = 'Test Sender'; address = 'billing@example.com' } }
            toRecipients                  = @(@{ emailAddress = @{ address = $Mbx } })
            attachments                   = @(@{ '@odata.type' = '#microsoft.graph.fileAttachment'; name = $b.Name; contentBytes = [Convert]::ToBase64String($bytes) })
            singleValueExtendedProperties = $NotDraft
        } | Out-Null
        Write-Output "injected $($b.Name)"
    }
    return
}

$sandboxFolder = Get-OrCreateFolder "$Graph/mailFolders/inbox" 'Sandbox'
$doneFolder = Get-OrCreateFolder "$Graph/mailFolders/$($sandboxFolder.id)" 'Done'
$until = (Get-Date).AddMinutes($MaxMinutes)
do {
    $msgs = (Invoke-Graph GET "$Graph/mailFolders/$($sandboxFolder.id)/messages?`$top=10&`$select=id,subject,from,hasAttachments").value
    foreach ($m in $msgs) {
        try { Invoke-Case $m $sandboxFolder $doneFolder }
        catch {
            Write-Output "  case failed: $($_.Exception.Message)"
            # Move it out of Sandbox anyway so one bad message can't loop the sandbox every 30 s.
            try { Invoke-Graph POST "$Graph/messages/$($m.id)/move" @{ destinationId = $doneFolder.id } | Out-Null } catch { }
        }
    }
    if ($Mode -eq 'Once') { break }
    Start-Sleep -Seconds 30
} while ((Get-Date) -lt $until)
Write-Output 'watch window ended'
