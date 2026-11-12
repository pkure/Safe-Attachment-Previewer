# hal-id: #HAL-20261107-0017-PK-A1
# Runs INSIDE vm-sandbox (Windows PowerShell 5.1, as SYSTEM via Run Command). The VM has no internet.
# 1. pulls cases/<CaseId>/* through the storage private endpoint using the VM's managed identity
# 2. hashes, Defender custom scan, oletools olevba (Office macros), pdfid (PDF keywords), risky-extension check
# 3. writes reports/<CaseId>/report.json
# Never executes or opens the samples itself.
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$')][string]$CaseId,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9]{3,24}$')][string]$Account
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$started = Get-Date
$toolsDir = 'C:\sbx\tools'
$py = Join-Path $toolsDir 'python\python.exe'
$caseDir = Join-Path 'C:\cases' $CaseId
$blobBase = "https://$Account.blob.core.windows.net"
$riskyExt = @('.exe', '.dll', '.scr', '.js', '.jse', '.vbs', '.vbe', '.wsf', '.hta', '.lnk', '.iso', '.img',
    '.ps1', '.bat', '.cmd', '.msi', '.one', '.html', '.htm', '.svg', '.xll', '.jar')

function Get-StorageHeaders {
    $uri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/'
    $tok = Invoke-RestMethod -Headers @{ Metadata = 'true' } -Uri $uri
    @{ Authorization = "Bearer $($tok.access_token)"; 'x-ms-version' = '2023-11-03' }
}

function Test-Internet {
    # Expect FALSE: proves the sandbox is offline at analysis time.
    $c = New-Object Net.Sockets.TcpClient
    try { $c.ConnectAsync('1.1.1.1', 443).Wait(3000) } catch { $false } finally { $c.Dispose() }
}

function Test-PublicDns {
    # Expect FALSE: public names must not resolve (DNS-tunneling exfil path closed by the NSG).
    try { [void][Net.Dns]::GetHostAddresses('www.microsoft.com'); $true } catch { $false }
}

$h = Get-StorageHeaders
New-Item -ItemType Directory -Force -Path $caseDir | Out-Null

# --- pull the case -----------------------------------------------------------------------------------
$listUri = "$blobBase/cases?restype=container&comp=list&prefix=$CaseId/"
# Decode bytes as UTF-8 ourselves: Windows PowerShell reads the body as Latin-1, so the BOM arrives as "ï»¿".
$listTxt = [Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing -Headers $h -Uri $listUri).RawContentStream.ToArray())
[xml]$list = $listTxt.Substring($listTxt.IndexOf('<'))
$files = @()
foreach ($b in $list.EnumerationResults.Blobs.Blob) {
    $name = Split-Path -Leaf $b.Name
    if ($name -eq 'manifest.json') { continue }
    $dest = Join-Path $caseDir $name
    $writeError = $null
    try { Invoke-WebRequest -UseBasicParsing -Headers $h -Uri "$blobBase/cases/$($b.Name)" -OutFile $dest }
    catch { $writeError = $_.Exception.Message }  # Defender can block the write itself
    $files += [pscustomobject]@{ Name = $name; Path = $dest; Size = [int64]$b.Properties.'Content-Length'; WriteError = $writeError }
}

# Unpack archives one level deep (Defender scans what comes out).
foreach ($f in @($files)) {
    if ($f.Name -match '\.zip$' -and (Test-Path $f.Path)) {
        $out = "$($f.Path)_unzipped"
        try {
            Expand-Archive -Path $f.Path -DestinationPath $out -Force
            Get-ChildItem -File -Recurse $out | ForEach-Object {
                $files += [pscustomobject]@{ Name = "$($f.Name) > $($_.Name)"; Path = $_.FullName; Size = $_.Length; WriteError = $null }
            }
        } catch {
            $files += [pscustomobject]@{ Name = "$($f.Name) > (extract failed)"; Path = $out; Size = 0; WriteError = $_.Exception.Message }
        }
    }
}

# --- Defender ----------------------------------------------------------------------------------------
$mp = Get-MpComputerStatus
try { Start-MpScan -ScanType CustomScan -ScanPath $caseDir } catch { }  # scan errors still leave detections
Start-Sleep -Seconds 3
$threats = @{}
foreach ($d in @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $started.AddMinutes(-1) })) {
    $name = (Get-MpThreat -ThreatID $d.ThreatID).ThreatName
    # Only this case's folder: Defender's history is machine-wide, so a detection from the previous case
    # (seconds earlier on the same VM) must not leak into this verdict.
    foreach ($r in $d.Resources) {
        $p = $r -replace '^[a-z]+:_', ''
        if ($p.StartsWith($caseDir, [StringComparison]::OrdinalIgnoreCase)) { $threats[$p] = $name }
    }
}

# --- per-file analysis -------------------------------------------------------------------------------
function Invoke-Py([string[]]$PyArgs) {
    if (-not (Test-Path $py)) { return $null }
    # Windows PowerShell 5.1 turns any native stderr line into an error under 'Stop'; library warnings must not kill the case.
    $ErrorActionPreference = 'Continue'
    $out = & $py -W ignore @PyArgs 2>$null
    ($out -join "`n")
}

$results = foreach ($f in $files) {
    $present = Test-Path -LiteralPath $f.Path -PathType Leaf
    $r = [ordered]@{
        name     = $f.Name
        size     = $f.Size
        sha256   = $null
        defender = $null
        olevba   = $null
        pdfid    = $null
        flags    = @()
        note     = $f.WriteError
    }
    foreach ($k in $threats.Keys) { if ($k -like "*$([IO.Path]::GetFileName($f.Path))") { $r.defender = $threats[$k] } }
    if (-not $present -and -not $r.defender -and -not $f.WriteError) { $r.note = 'file removed during analysis (likely Defender quarantine)' }
    if ($present) {
      try {
        $r.sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $f.Path).Hash.ToLower()
        $ext = [IO.Path]::GetExtension($f.Path).ToLower()
        if ($riskyExt -contains $ext) { $r.flags += "risky file type $ext" }
        $head = [IO.File]::ReadAllBytes($f.Path) | Select-Object -First 8
        $isOle = ($head.Count -ge 4 -and $head[0] -eq 0xD0 -and $head[1] -eq 0xCF -and $head[2] -eq 0x11 -and $head[3] -eq 0xE0)
        $isZip = ($head.Count -ge 2 -and $head[0] -eq 0x50 -and $head[1] -eq 0x4B)
        $isPdf = ($head.Count -ge 4 -and [Text.Encoding]::ASCII.GetString($head, 0, 4) -eq '%PDF')
        if ($isOle -or ($isZip -and $ext -match '^\.(doc|xls|ppt)[mx]?$|^\.xlsb$')) {
            $json = Invoke-Py @('-m', 'oletools.olevba', '-j', '--relaxed', $f.Path)
            try {
                $entry = ($json | ConvertFrom-Json) | Where-Object { $_.file } | Select-Object -First 1
                $macros = @($entry.macros).Count
                $analysis = @($entry.analysis | Where-Object { $_.type -in 'AutoExec', 'Suspicious', 'IOC' } |
                        ForEach-Object { "$($_.type): $($_.keyword)" })
                $r.olevba = [ordered]@{ macros = $macros; findings = $analysis }
                if ($macros -gt 0) { $r.flags += "contains $macros VBA macro module(s)" }
                if ($analysis | Where-Object { $_ -match '^(AutoExec|Suspicious)' }) { $r.flags += 'auto-run or suspicious macro keywords' }
            } catch { $r.olevba = 'olevba failed' }
        }
        if ($isPdf) {
            $txt = Invoke-Py @('-m', 'pdfid.pdfid', $f.Path)
            $counts = [ordered]@{}
            foreach ($kw in '/JS', '/JavaScript', '/OpenAction', '/AA', '/Launch', '/EmbeddedFile', '/XFA', '/RichMedia') {
                $m = [regex]::Match([string]$txt, "(?m)^\s*$([regex]::Escape($kw))\s+(\d+)")
                if ($m.Success) { $counts[$kw] = [int]$m.Groups[1].Value }
            }
            $r.pdfid = $counts
            $hot = @($counts.Keys | Where-Object { $_ -in '/JS', '/JavaScript', '/Launch', '/EmbeddedFile' -and $counts[$_] -gt 0 })
            if ($hot.Count) { $r.flags += "PDF has active content: $($hot -join ', ')" }
            if (-not $txt) { $r.pdfid = 'pdfid unavailable' }
        }
      } catch {
        # Real-time protection refuses to open infected files. That refusal IS a detection, not a crash.
        $msg = $_.Exception.Message
        if ($msg -match 'virus|potentially unwanted') { $r.defender = 'blocked by Defender real-time protection'; $r.note = 'file blocked on read (Defender real-time)' }
        else { $r.note = "analysis error: $msg" }
      }
    }
    [pscustomobject]$r
}

# --- verdict -----------------------------------------------------------------------------------------
$verdict = 'NO DETECTIONS'
if ($results | Where-Object { $_.flags.Count }) { $verdict = 'SUSPICIOUS' }
if ($threats.Count -or ($results | Where-Object { $_.defender -or $_.note -match 'quarantine|virus|blocked' })) { $verdict = 'MALICIOUS' }
if (-not $files.Count) { $verdict = 'NO FILE ATTACHMENTS' }

$report = [ordered]@{
    caseId          = $CaseId
    verdict         = $verdict
    analyzedUtc     = (Get-Date).ToUniversalTime().ToString('o')
    sandbox         = $env:COMPUTERNAME
    detections      = @($threats.GetEnumerator() | ForEach-Object { "$($_.Value) in $($_.Key)" })
    internetReached = (Test-Internet)
    dnsResolved     = (Test-PublicDns)
    defender        = [ordered]@{
        realTime         = $mp.RealTimeProtectionEnabled
        signatureVersion = $mp.AntivirusSignatureVersion
        signatureDate    = $mp.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')
    }
    files           = @($results)
}
$body = [Text.Encoding]::UTF8.GetBytes(($report | ConvertTo-Json -Depth 6))
$put = Get-StorageHeaders
$put['x-ms-blob-type'] = 'BlockBlob'
Invoke-WebRequest -UseBasicParsing -Method Put -Headers $put -ContentType 'application/json' -Body $body `
    -Uri "$blobBase/reports/$CaseId/report.json" | Out-Null
"OK $CaseId $verdict files=$($files.Count) internet=$($report.internetReached) dns=$($report.dnsResolved)"
