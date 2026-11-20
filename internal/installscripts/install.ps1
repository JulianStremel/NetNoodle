# netnoodle installer for Windows PowerShell 5.1. Agent and scanner only.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Read-SetupCode([string]$Value) {
    if ($Value.Length -gt 16384 -or $Value -notmatch '^nnsetup1:([A-Za-z0-9_-]+)$') { throw 'Invalid setup code.' }
    $encoded = $Matches[1].Replace('-', '+').Replace('_', '/')
    if ($encoded.Length % 4 -eq 1) { throw 'Invalid base64url.' }
    $encoded = $encoded.PadRight($encoded.Length + ((4 - $encoded.Length % 4) % 4), '=')
    $decoded = (New-Object Text.UTF8Encoding($false, $true)).GetString([Convert]::FromBase64String($encoded))
    $fields = @{}
    $knownKeys = @('server','fingerprint','spki','session','secret','token','name','kind','version','expires')
    foreach ($line in $decoded.TrimEnd("`n").Split("`n")) {
        $pair = $line.Split(@('='), 2)
        if ($pair.Count -ne 2 -or $pair[1] -match '[\x00\r]') { throw 'Invalid setup line.' }
        if ($knownKeys -cnotcontains $pair[0]) { continue }
        if ($fields.ContainsKey($pair[0])) { throw 'Duplicate setup key.' }
        $fields[$pair[0]] = $pair[1]
    }
    foreach ($key in @('server','fingerprint','spki','session','secret','token','name','kind','version','expires')) {
        if (-not $fields.ContainsKey($key) -or -not $fields[$key]) { throw "Missing setup key: $key" }
    }
    if ($fields.name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$' -or
        $fields.kind -cnotmatch '^(agent|scan)$' -or
        $fields.session -cnotmatch '^[A-Za-z0-9-]{16,80}$' -or
        $fields.secret -cnotmatch '^[A-Za-z0-9_-]{43}$' -or
        $fields.token -cnotmatch '^[A-Za-z0-9_-]{1,128}$' -or
        $fields.fingerprint -cnotmatch '^[a-fA-F0-9]{64}$' -or
        $fields.spki -cnotmatch '^[A-Za-z0-9+/]{43}=$' -or
        $fields.expires -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' -or
        $fields.version -cnotmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$') { throw 'Invalid setup fields.' }
    $origin = [Uri]$fields.server
    if ($origin.Scheme -ne 'https' -or $origin.UserInfo -or $origin.AbsolutePath -ne '/' -or $origin.Query -or $origin.Fragment) { throw 'Invalid server URL.' }
    if ([DateTimeOffset]::Parse($fields.expires) -le [DateTimeOffset]::UtcNow) { throw 'The setup code has expired.' }
    return $fields
}

function Private-Path([string]$Path, [bool]$Directory) {
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = if ($Directory) {
            New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        } else { New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow') }
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Protect-InstallRoot {
    if ((Get-Item -LiteralPath $script:InstallRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Install root must not be a link.' }
    Private-Path $script:InstallRoot $true
    $acl = Get-Acl -LiteralPath $script:InstallRoot
    $localService = New-Object Security.Principal.SecurityIdentifier('S-1-5-19')
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($localService,'ReadAndExecute','Allow')))
    Set-Acl -LiteralPath $script:InstallRoot -AclObject $acl
    if ((Test-Path -LiteralPath $script:Journal) -and ((Get-Item -LiteralPath $script:Journal).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Journal must not be a link.' }
}
function Record-Resource([string]$Type, [string]$Target) {
    [IO.File]::AppendAllText($script:Journal, "$Type|$Target`n", (New-Object Text.UTF8Encoding($false)))
}
function New-InstallFile([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw "File already exists: $Path" }
    Record-Resource 'file' $Path
}
function Remove-Install {
    if (-not (Test-Path -LiteralPath $script:Journal)) { return }
    $entries = [IO.File]::ReadAllLines($script:Journal)
    [Array]::Reverse($entries)
    $bad = $false
    foreach ($entry in $entries) {
        try {
            $pair = $entry.Split(@('|'), 2)
            if ($pair.Count -ne 2) { throw 'Invalid journal.' }
            if ($pair[0] -eq 'task') {
                if ($pair[1] -cnotmatch '^nn-[A-Za-z0-9][A-Za-z0-9._-]{0,62}$') { throw 'Invalid task name.' }
                if (Get-ScheduledTask -TaskName $pair[1] -ErrorAction SilentlyContinue) {
                    Stop-ScheduledTask -TaskName $pair[1]
                    Unregister-ScheduledTask -TaskName $pair[1] -Confirm:$false
                }
            } elseif ($pair[0] -eq 'file' -or $pair[0] -eq 'dir') {
                $resolved = [IO.Path]::GetFullPath($pair[1])
                $prefix = [IO.Path]::GetFullPath($script:InstallRoot).TrimEnd('\') + '\'
                if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Journal path leaves the install root.' }
                if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
            } else { throw 'Unknown journal entry.' }
        } catch { $bad = $true; Write-Warning "Rollback failed for a journal entry: $($_.Exception.Message)" }
    }
    if ($bad) { throw 'Rollback had errors. Keep the journal and check the files and task.' }
    Remove-Item -LiteralPath $script:Journal -Force
    Write-Host 'Removed the task and files made by this install.'
}
function Server-Request([string]$Method, [string]$Path, $Body = $null, [int]$TimeoutMS = 30000) {
    $request = [Net.HttpWebRequest]::Create($script:Setup.server + $Path)
    $request.AllowAutoRedirect = $false
    $request.Timeout = $TimeoutMS
    $request.ReadWriteTimeout = $TimeoutMS
    $request.Method = $Method
    $request.Headers['X-NN-Onboard-Secret'] = $script:Setup.secret
    if ($null -ne $Body) {
        $request.ContentType = 'application/json'
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress))
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    }
    $response = $request.GetResponse()
    try {
        $reader = New-Object IO.StreamReader($response.GetResponseStream())
        try {
            $buffer = New-Object char[] 1048577
            $count = $reader.ReadBlock($buffer, 0, $buffer.Length)
            if ($count -gt 1048576) { throw 'Server response too large.' }
            $bodyText = New-Object string($buffer, 0, $count)
            return @{ Data = ($bodyText | ConvertFrom-Json); Date = $response.Headers['Date'] }
        } finally { $reader.Dispose() }
    } finally { $response.Dispose() }
}
function Report-Step([string]$Name) {
    $null = Server-Request 'POST' "/v1/onboard/$($script:Setup.session)/step" @{ name=$Name; ok=$true; message='' }
}
function Run-Program([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Peer command failed.' }
}
function Ask-Input([string]$Prompt) {
    if ($script:Yes) { throw "Input is required: $Prompt. Run without --yes." }
    $answer = Read-Host $Prompt
    if (-not $answer -or $answer.Length -gt 16384) { throw 'Input is empty or too large.' }
    return $answer
}
function Quote-Argument([string]$Value) {
    # Windows doubles backslashes before a quote, and before the closing quote.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

$Code = ''; $script:Yes = $false; $Uninstall = ''
for ($i=0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
        { $_ -in @('--code','-Code') } { $i++; if ($i -ge $args.Count) { throw '--code needs a value' }; $Code = $args[$i] }
        { $_ -in @('--yes','-Yes') } { $script:Yes = $true }
        { $_ -in @('--uninstall','-Uninstall') } { $i++; if ($i -ge $args.Count) { throw '--uninstall needs a name' }; $Uninstall = $args[$i] }
        default { throw 'Unknown installer option.' }
    }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Quote each argument for the Windows command line. Codes contain no quotes.
    $forward = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath) + $args
    $quoted = @($forward | ForEach-Object { Quote-Argument $_ })
    # The elevated installer needs a visible console for setup-code prompts.
    $child = Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Normal -ArgumentList $quoted -Wait -PassThru
    exit $child.ExitCode
}
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'This installer needs Windows.' }
$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$platform = switch ($arch) { 'AMD64' { 'windows-x86_64' } 'ARM64' { 'windows-arm64' } default { throw 'Supported architectures: x86_64 and arm64.' } }
$script:InstallRoot = Join-Path $env:ProgramData 'netnoodle\install'
if ($Uninstall) {
    if ($Uninstall -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$') { throw 'Invalid name.' }
    $script:Journal = Join-Path $script:InstallRoot "$Uninstall.journal"
    if (Test-Path -LiteralPath $script:InstallRoot) { Protect-InstallRoot; Remove-Install }
    exit
}
if (-not $Code) { $Code = Ask-Input 'Paste the setup code' }
$script:Setup = Read-SetupCode $Code
$Code = $null

# Use a CLR callback so TLS validation does not depend on a PowerShell runspace
# on a networking thread. It compares the full SHA-256 certificate fingerprint.
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
public static class NNInstallPin {
    public static string Expected;
    public static bool Check(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        if (cert == null) return false;
        using (SHA256 hash = SHA256.Create()) {
            return String.Equals(BitConverter.ToString(hash.ComputeHash(cert.GetRawCertData())).Replace("-", ""), Expected, StringComparison.OrdinalIgnoreCase);
        }
    }
}
'@
$oldCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
$oldProtocol = [Net.ServicePointManager]::SecurityProtocol
$pinCallback = [Net.Security.RemoteCertificateValidationCallback][NNInstallPin]::Check
[NNInstallPin]::Expected = $script:Setup.fingerprint
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = $pinCallback
$armed = $false; $success = $false; $journalActive = $false; $stage = 'preflight'
$work = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work
Private-Path $work $true
try {
    $health = Server-Request 'GET' '/v1/health'
    if ([Math]::Abs(([DateTimeOffset]::UtcNow - [DateTimeOffset]::Parse($health.Date)).TotalSeconds) -ge 300) { throw 'Set the clock. The server time differs by more than 5 minutes.' }
    $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($script:InstallRoot))
    if ($drive.AvailableFreeSpace -lt 268435456) { throw 'At least 256 MiB of free disk is required.' }
    Report-Step 'preflight'
    $armed = $true
    $stage = 'download'
    $manifest = (Server-Request 'GET' "/v1/install/manifest?version=$($script:Setup.version)&platform=$platform&kind=$($script:Setup.kind)").Data
    if ($manifest.version -ne $script:Setup.version -or $manifest.artifacts.Count -ne 1) { throw 'Invalid release manifest.' }
    $artifact = $manifest.artifacts[0]
    if ($artifact.kind -ne 'zip' -or $artifact.sha256 -cnotmatch '^[a-f0-9]{64}$' -or ([Uri]$artifact.url).Scheme -ne 'https') { throw 'Invalid artifact.' }
    # Release downloads use normal PKI. Restore the server pin after download.
    [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    $archive = Join-Path $work 'release.zip'
    try {
        $request = [Net.HttpWebRequest]::Create($artifact.url)
        $request.AllowAutoRedirect = $false
        # GitHub release assets redirect to HTTPS asset storage.
        for ($redirect=0; $redirect -lt 6; $redirect++) {
            $request.Timeout = 300000
            $response = $request.GetResponse()
            if ([int]$response.StatusCode -ge 300 -and [int]$response.StatusCode -lt 400) {
                $next = New-Object Uri($request.RequestUri, $response.Headers['Location'])
                $response.Dispose()
                if ($next.Scheme -ne 'https') { throw 'Unsafe release redirect.' }
                $request = [Net.HttpWebRequest]::Create($next); $request.AllowAutoRedirect = $false
                continue
            }
            try {
                $inputStream = $response.GetResponseStream(); $outputStream = [IO.File]::Create($archive)
                try {
                    $buffer = New-Object byte[] 65536; $total = 0
                    while (($count = $inputStream.Read($buffer,0,$buffer.Length)) -gt 0) {
                        $total += $count
                        if ($total -gt 268435456) { throw 'Release file too large.' }
                        $outputStream.Write($buffer,0,$count)
                    }
                } finally { $outputStream.Dispose(); $inputStream.Dispose() }
            } finally { $response.Dispose() }
            break
        }
    } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $pinCallback }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $artifact.sha256) { throw 'SHA-256 check failed.' }
    Report-Step 'download'
    $stage = 'install'
    $script:Journal = Join-Path $script:InstallRoot "$($script:Setup.name).journal"
    if (-not (Test-Path -LiteralPath $script:InstallRoot)) {
        $null = New-Item -ItemType Directory -Path $script:InstallRoot
    }
    Protect-InstallRoot
    if (Test-Path -LiteralPath $script:Journal) {
        if ((Ask-Input 'An install exists. Type repair to remove it and install again, or abort') -cne 'repair') { throw 'Install cancelled.' }
        Remove-Install
    }
    $null = New-Item -ItemType File -Path $script:Journal
    Private-Path $script:Journal $false
    $journalActive = $true
    $homePath = Join-Path $script:InstallRoot $script:Setup.name
    if (Test-Path -LiteralPath $homePath) { throw 'Install directory exists without a journal.' }
    Record-Resource 'dir' $homePath
    $null = New-Item -ItemType Directory -Path $homePath
    $binaryName = if ($script:Setup.kind -eq 'agent') { 'nn-agent.exe' } else { 'nn-scan.exe' }
    $binary = Join-Path $homePath $binaryName
    New-InstallFile $binary
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $entries = @($zip.Entries | Where-Object { $_.Name -ceq $binaryName })
        if ($entries.Count -ne 1 -or $entries[0].Length -gt 268435456) { throw 'Invalid archive members.' }
        # Extract a single known file to a fixed path. No archive path is used.
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $binary)
    } finally { $zip.Dispose() }
    $creds = Join-Path $homePath 'credentials.json'; $config = Join-Path $homePath 'config.json'
    New-InstallFile $creds; New-InstallFile $config
    $settings = @{ credentials=$creds; interval='1h' }
    if ($script:Setup.kind -eq 'scan') {
        $cidr = Ask-Input 'Scan CIDR (for example 192.168.1.0/24)'
        if ($cidr -cnotmatch '^[0-9a-fA-F.:]+/[0-9]+$') { throw 'Invalid CIDR.' }
        $settings.cidrs = @($cidr); $settings.interval = '15m'
    }
    [IO.File]::WriteAllText($config, ($settings | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
    Report-Step 'install'
    $stage = 'enroll'
    $env:NN_JOIN_TOKEN = $script:Setup.token
    try {
        if ($script:Setup.kind -eq 'agent') { Run-Program $binary @('--config',$config,'--creds',$creds,'enroll','--server',$script:Setup.server,'--fingerprint',$script:Setup.fingerprint,'--name',$script:Setup.name) }
        else { Run-Program $binary @('enroll','-server',$script:Setup.server,'-fingerprint',$script:Setup.fingerprint,'-name',$script:Setup.name,'-creds',$creds) }
    } finally { Remove-Item Env:NN_JOIN_TOKEN -ErrorAction SilentlyContinue; $script:Setup.token = '' }
    Report-Step 'enrolled'
    $stage = 'service'
    $taskName = 'nn-' + $script:Setup.name
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Task already exists.' }
    $commandArgs = if ($script:Setup.kind -eq 'agent') { '--config "' + $config + '" run' } else { 'run -config "' + $config + '"' }
    $action = New-ScheduledTaskAction -Execute $binary -Argument $commandArgs -WorkingDirectory $homePath
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    # LOCAL SERVICE has no admin rights. Permit it to read credentials and write
    # only this installation's runtime state, with no permissions for Users.
    $localService = New-Object Security.Principal.SecurityIdentifier('S-1-5-19')
    $acl = Get-Acl -LiteralPath $homePath
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($localService,'Modify','ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl -LiteralPath $homePath -AclObject $acl
    Record-Resource 'task' $taskName
    $null = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $taskSettings -User 'NT AUTHORITY\LOCAL SERVICE' -RunLevel Limited
    Start-ScheduledTask -TaskName $taskName
    Run-Program $binary @('--version')
    Report-Step 'service'
    $stage = 'communication'
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    $startupDeadline = [DateTime]::UtcNow.AddSeconds(10)
    $peerSeen = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running' -and [DateTime]::UtcNow -ge $startupDeadline) { throw 'The peer task stopped.' }
        $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        $status = (Server-Request 'GET' "/v1/onboard/$($script:Setup.session)" $null $remaining).Data
        if ($status.state -in @('aborted','expired')) { throw 'Session ended.' }
        if ($status.peer_seen) { $peerSeen = $true; break }
        $remaining = [int][Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if ($remaining -gt 0) { Start-Sleep -Milliseconds ([Math]::Min(2000, $remaining)) }
    }
    if (-not $peerSeen) { throw 'No communication from the peer within 120 seconds.' }
    Report-Step 'communication'; Report-Step 'done'
    $success = $true
    Write-Host "Installed $($script:Setup.name)`nServer: $($script:Setup.server)`nTask: $taskName`nUninstall: powershell -File install.ps1 --uninstall $($script:Setup.name)"
} catch {
    # Do not print request bodies, codes, credentials, or arbitrary peer errors.
    Write-Warning "Install failed at: $stage. Rolling back."
} finally {
    if ($armed -and -not $success) {
        try { $null = Server-Request 'POST' "/v1/onboard/$($script:Setup.session)/step" @{name=$stage;ok=$false;message='installer failed; local rollback attempted'} }
        catch { Write-Warning 'Could not report the failed step.' }
        if ($journalActive) { try { Remove-Install } catch { Write-Warning $_.Exception.Message } }
        try { $null = Server-Request 'POST' "/v1/onboard/$($script:Setup.session)/abort" @{reason='installer failed; local rollback attempted'} }
        catch { Write-Warning 'Server abort failed. Cancel the session on the Peers page.' }
    }
    [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCallback
    [Net.ServicePointManager]::SecurityProtocol = $oldProtocol
    if (Test-Path -LiteralPath $work) {
        $resolvedWork = [IO.Path]::GetFullPath($work)
        $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if ($resolvedWork.StartsWith($tempPrefix,[StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $resolvedWork -Recurse -Force }
    }
}
if (-not $success) { exit 1 }
