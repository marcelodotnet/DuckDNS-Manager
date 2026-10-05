<#
DuckDNS Manager for Windows. Windows PowerShell 5.1; ASCII source.
#>
[CmdletBinding()]
param(
    [switch]$Scheduled,
    [ValidateSet('Startup', 'Network', 'Periodic')]
    [string]$Reason = 'Periodic'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ScriptVersion = '1.3.0'
$Root = Join-Path $env:ProgramData 'DuckDNS'
$InstalledScript = Join-Path $Root 'DuckDNS-Manager.ps1'
$ConfigPath = Join-Path $Root 'config.json'
$PreviousConfigPath = Join-Path $Root 'config.previous.json'
$script:RunLockHeld = $false
$script:RunClock = $null
$script:OpeningAddressCheck = $null
$InternalLimitSeconds = 240
$ManualFallbacks = @('1.1.1.1', '8.8.8.8')
$TokenPath = Join-Path $Root 'token.dat'
$CredentialReceiptPath = Join-Path $Root 'credentials.dat'
$StatusPath = Join-Path $Root 'status.json'
$LockPath = Join-Path $Root 'run.lock'
$LogDirectory = Join-Path $Root 'logs'
$TaskFolderName = '\DuckDNS Manager'
$Providers = @('https://api.ipify.org', 'https://ipv4.icanhazip.com', 'https://checkip.amazonaws.com')
$TaskNames = @('Startup', 'Network', 'Periodic')
$ExitCodes = @{ Success = 0; Config = 10; Token = 11; PublicIp = 12; Dns = 13; Api = 14; State = 15; Timeout = 16; Internal = 99 }

function New-DefaultConfig {
    return [pscustomobject]@{
        SchemaVersion = 3
        Hostname = ''
        NetworkInterface = [pscustomobject]@{ Mode = 'Automatic'; InterfaceGuid = $null }
        CompareIpBeforeUpdate = $true
        PostUpdateValidation = $true
        Dns = [pscustomobject]@{ Mode = 'System'; ManualServer = $null }
        Retry = [pscustomobject]@{ Attempts = 6; DelaySeconds = 5 }
        ForcedUpdate = [pscustomobject]@{ Enabled = $false; IntervalHours = 24 }
        Scheduling = [pscustomobject]@{
            Startup = [pscustomobject]@{ Enabled = $true; DelaySeconds = 20 }
            NetworkReconnect = [pscustomobject]@{ Enabled = $true }
            Periodic = [pscustomobject]@{ Enabled = $true; IntervalMinutes = 30 }
        }
        Logging = [pscustomobject]@{ Enabled = $false }
    }
}

function New-EmptyState {
    return [pscustomobject]@{
        Domain = $null
        CredentialStatus = 'Pending'
        CredentialHostname = $null
        CredentialVerificationId = $null
        LastCredentialVerificationUtc = $null
        LastCheckUtc = $null
        LastSuccessfulCheckUtc = $null
        ConsecutiveFailures = 0
        ApplicationVersion = $ScriptVersion
        LastStateRecoveryUtc = $null
        LastStateRecoveryReason = $null
        LastSuccessfulUpdateUtc = $null
        LastReason = $null
        LastResult = $null
        LastDetectedPublicIPv4 = $null
        DuckDnsIPv4 = $null
        SynchronizationState = 'Unknown'
        LastExitCode = 0
    }
}

function Test-IPv4([string]$Value, [bool]$RequirePublic = $false) {
    if ($Value -notmatch '^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$') { return $false }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$address)) { return $false }
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    if ($address.ToString() -ne $Value) { return $false }
    if (-not $RequirePublic) { return $true }
    $n = @($address.GetAddressBytes() | ForEach-Object { [int]$_ })
    if ($n[0] -eq 0 -or $n[0] -eq 10 -or $n[0] -eq 127 -or $n[0] -ge 224) { return $false }
    if ($n[0] -eq 169 -and $n[1] -eq 254) { return $false }
    if ($n[0] -eq 172 -and $n[1] -ge 16 -and $n[1] -le 31) { return $false }
    if ($n[0] -eq 192 -and $n[1] -eq 168) { return $false }
    if ($n[0] -eq 100 -and $n[1] -ge 64 -and $n[1] -le 127) { return $false }
    if ($n[0] -eq 192 -and $n[1] -eq 0 -and $n[2] -eq 0) { return $false }
    if ($n[0] -eq 192 -and $n[1] -eq 0 -and $n[2] -eq 2) { return $false }
    if ($n[0] -eq 198 -and ($n[1] -eq 18 -or $n[1] -eq 19)) { return $false }
    if ($n[0] -eq 198 -and $n[1] -eq 51 -and $n[2] -eq 100) { return $false }
    if ($n[0] -eq 203 -and $n[1] -eq 0 -and $n[2] -eq 113) { return $false }
    return $true
}

function Normalize-Hostname([string]$Value) {
    $name = $Value.Trim().ToLowerInvariant()
    if ($name.EndsWith('.duckdns.org')) { $name = $name.Substring(0, $name.Length - 12) }
    if ($name -notmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$') { throw 'Invalid DuckDNS hostname.' }
    return $name
}

function Get-DuckDnsDomain($Config) { return ([string]$Config.Hostname + '.duckdns.org') }

# Legacy config/state validation only. Canonical configuration stores Hostname.
function Normalize-Domain([string]$Value) { return ((Normalize-Hostname $Value) + '.duckdns.org') }

function Assert-Range($Value, [int]$Minimum, [int]$Maximum, [string]$Name) {
    if ($Value -is [bool] -or $Value -isnot [int] -and $Value -isnot [long]) { throw "Invalid $Name." }
    if ([long]$Value -lt $Minimum -or [long]$Value -gt $Maximum) { throw "Invalid $Name." }
}

function Assert-Config($Config) {
    if ($null -eq $Config -or ($Config.SchemaVersion -isnot [int] -and $Config.SchemaVersion -isnot [long]) -or
        $Config.SchemaVersion -notin @(1, 2, 3)) { throw 'Unsupported configuration schema.' }
    if ($Config.SchemaVersion -eq 3) {
        if ($Config.Hostname -isnot [string] -or (Normalize-Hostname ([string]$Config.Hostname)) -cne [string]$Config.Hostname -or
            $Config.PSObject.Properties['Domain']) { throw 'Invalid hostname configuration.' }
        if ($Config.NetworkInterface -isnot [pscustomobject] -or $Config.NetworkInterface.Mode -cnotin @('Automatic','Specific')) { throw 'Invalid interface mode.' }
        if ($Config.NetworkInterface.Mode -eq 'Automatic') {
            if ($null -ne $Config.NetworkInterface.InterfaceGuid) { throw 'Invalid automatic interface.' }
        } else {
            $id = [guid]::Empty
            if ($Config.NetworkInterface.InterfaceGuid -isnot [string] -or
                -not [guid]::TryParse([string]$Config.NetworkInterface.InterfaceGuid, [ref]$id) -or
                $id -eq [guid]::Empty) { throw 'Invalid interface identity.' }
        }
    } elseif ((Normalize-Domain ([string]$Config.Domain)) -cne [string]$Config.Domain) { throw 'Invalid domain.' }
    if ($Config.SchemaVersion -eq 1) {
        if (-not (Test-IPv4 ([string]$Config.ValidationDns))) { throw 'Invalid validation DNS.' }
    } else {
        if ($Config.Dns.Mode -cnotin @('System', 'Manual')) { throw 'Invalid DNS mode.' }
        if ($Config.Dns.Mode -eq 'Manual' -and -not (Test-IPv4 ([string]$Config.Dns.ManualServer))) { throw 'Invalid manual DNS.' }
    }
    foreach ($item in @($Config.CompareIpBeforeUpdate, $Config.PostUpdateValidation, $Config.ForcedUpdate.Enabled,
            $Config.Scheduling.Startup.Enabled, $Config.Scheduling.NetworkReconnect.Enabled,
            $Config.Scheduling.Periodic.Enabled, $Config.Logging.Enabled)) {
        if ($item -isnot [bool]) { throw 'Invalid configuration flag.' }
    }
    Assert-Range $Config.Retry.Attempts 1 12 'retry attempts'
    Assert-Range $Config.Retry.DelaySeconds 1 60 'retry delay'
    Assert-Range $Config.ForcedUpdate.IntervalHours 1 168 'force interval'
    Assert-Range $Config.Scheduling.Startup.DelaySeconds 1 300 'startup delay'
    Assert-Range $Config.Scheduling.Periodic.IntervalMinutes 5 1440 'periodic interval'
}

function Convert-ConfigV3($Value) {
    Assert-Config $Value
    if ($Value.SchemaVersion -eq 1) {
        $mode = 'System'; $manual = $null
        if ($Value.ValidationDns -ne '1.1.1.1') { $mode = 'Manual'; $manual = $Value.ValidationDns }
        $Value.PSObject.Properties.Remove('ValidationDns')
        $Value | Add-Member -NotePropertyName Dns -NotePropertyValue ([pscustomobject]@{ Mode = $mode; ManualServer = $manual })
    }
    if ($Value.SchemaVersion -lt 3) {
        $hostname = Normalize-Hostname $Value.Domain
        $Value.PSObject.Properties.Remove('Domain')
        $Value | Add-Member -NotePropertyName Hostname -NotePropertyValue $hostname
        $Value | Add-Member -NotePropertyName NetworkInterface -NotePropertyValue ([pscustomobject]@{
            Mode = 'Automatic'; InterfaceGuid = $null })
        $Value.SchemaVersion = 3
    }
    Assert-Config $Value
    return $Value
}

function Read-Config {
    $value = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    return (Convert-ConfigV3 $value)
}

function Save-Config($Value) {
    if (-not $script:RunLockHeld) { throw 'Configuration write requires lock.' }
    Assert-Config $Value
    if ([IO.File]::Exists($ConfigPath)) {
        $old = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-Config $old
        Write-AtomicJson $PreviousConfigPath $old
        Set-SecureAcl $PreviousConfigPath $false
    }
    Write-AtomicJson $ConfigPath $Value
    Set-SecureAcl $ConfigPath $false
}

function Migrate-Config {
    if (-not $script:RunLockHeld) { throw 'Migration requires lock.' }
    $old = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Config $old
    if ($old.SchemaVersion -lt 3) { Save-Config (Convert-ConfigV3 $old) }
}

function Assert-State($Value) {
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw 'Invalid state.' }
    foreach ($name in @('Domain','LastCheckUtc','LastSuccessfulUpdateUtc','LastReason','LastResult',
            'LastDetectedPublicIPv4','DuckDnsIPv4','SynchronizationState','LastExitCode')) {
        if ($null -eq $Value.PSObject.Properties[$name]) { throw 'Invalid state structure.' }
    }
    foreach ($name in @('Domain','LastReason','LastResult','DuckDnsIPv4','ApplicationVersion','LastStateRecoveryReason','CredentialHostname','CredentialVerificationId')) {
        if ($null -ne $Value.$name -and $Value.$name -isnot [string]) { throw 'Invalid state text.' }
    }
    if ($Value.Domain -and (Normalize-Domain ([string]$Value.Domain)) -cne $Value.Domain) { throw 'Invalid state domain.' }
    if ($Value.PSObject.Properties['CredentialStatus'] -and $Value.CredentialStatus -cnotin @('Pending','Verified','Rejected')) {
        throw 'Invalid credential status.'
    }
    if ($Value.CredentialHostname -and (Normalize-Hostname $Value.CredentialHostname) -cne $Value.CredentialHostname) {
        throw 'Invalid credential hostname.'
    }
    if ($Value.CredentialVerificationId) {
        $id = [guid]::Empty
        if (-not [guid]::TryParse($Value.CredentialVerificationId, [ref]$id) -or $id -eq [guid]::Empty) {
            throw 'Invalid credential verification identity.'
        }
    }
    if ($Value.SynchronizationState -cnotin @('Unknown','Synchronized','Pending','Accepted','Failed')) { throw 'Invalid state status.' }
    foreach ($name in @('LastCheckUtc','LastSuccessfulUpdateUtc','LastSuccessfulCheckUtc','LastStateRecoveryUtc','LastCredentialVerificationUtc')) {
        $v = $Value.$name
        if ($v) {
            if ($v -is [DateTime]) { continue }
            $parsed = [DateTime]::MinValue
            if ($v -isnot [string] -or -not [DateTime]::TryParse($v, [ref]$parsed)) { throw 'Invalid state date.' }
        }
    }
    if ($Value.LastDetectedPublicIPv4 -and -not (Test-IPv4 ([string]$Value.LastDetectedPublicIPv4) $true)) { throw 'Invalid public IPv4 state.' }
    if ($Value.LastExitCode -isnot [int] -and $Value.LastExitCode -isnot [long]) { throw 'Invalid exit state.' }
    if ($null -ne $Value.ConsecutiveFailures) { Assert-Range $Value.ConsecutiveFailures 0 2147483647 'failure count' }
}

function New-StateReadResult([string]$Kind, [bool]$CanPersist, [bool]$HistoryKnown) {
    $state = New-EmptyState
    $state | Add-Member -NotePropertyName ReadKind -NotePropertyValue $Kind
    $state | Add-Member -NotePropertyName CanPersist -NotePropertyValue $CanPersist
    $state | Add-Member -NotePropertyName HistoryKnown -NotePropertyValue $HistoryKnown
    return $state
}

function Read-State([switch]$Recover) {
    $state = New-StateReadResult 'Missing' $true $true
    try { $text = [IO.File]::ReadAllText($StatusPath, [Text.Encoding]::UTF8) }
    catch [IO.FileNotFoundException] { return $state }
    catch [IO.DirectoryNotFoundException] { return $state }
    catch { return (New-StateReadResult 'ReadError' $false $false) }
    try {
        $saved = ConvertFrom-Json -InputObject $text
        Assert-State $saved
        foreach ($name in @((New-EmptyState).PSObject.Properties.Name)) {
            if ($null -ne $saved.PSObject.Properties[$name]) {
                $state.$name = $saved.$name
                if ($state.$name -is [DateTime]) { $state.$name = $state.$name.ToUniversalTime().ToString('o') }
            }
        }
        $state.ReadKind = 'Valid'
        return $state
    } catch {
        $state.ReadKind = 'InvalidJson'; $state.CanPersist = $false; $state.HistoryKnown = $false
        if (-not $Recover) { return $state }
        if (-not $script:RunLockHeld) { throw 'State recovery requires lock.' }
        try {
            $stamp = [DateTime]::UtcNow
            do {
                $backup = Join-Path $Root ('status.corrupt-' + $stamp.ToString('yyyyMMddTHHmmssZ') + '.json')
                $stamp = $stamp.AddSeconds(1)
            } while ([IO.File]::Exists($backup))
            [IO.File]::Move($StatusPath, $backup)
            Set-SecureAcl $backup $false
            $state.CanPersist = $true; $state.HistoryKnown = $true
            $state.LastStateRecoveryUtc = [DateTime]::UtcNow.ToString('o')
            $state.LastStateRecoveryReason = 'InvalidJson'
        } catch { $state.ReadKind = 'ReadError'; $state.CanPersist = $false }
        return $state
    }
}

function Save-State($State) {
    if (-not $script:RunLockHeld) { throw 'State write requires lock.' }
    if ($State.PSObject.Properties['CanPersist'] -and -not $State.CanPersist) { throw 'State access failure.' }
    $clean = New-EmptyState
    foreach ($name in @($clean.PSObject.Properties.Name)) { $clean.$name = $State.$name }
    $clean.ApplicationVersion = $ScriptVersion
    Assert-State $clean
    Write-AtomicJson $StatusPath $clean
    Set-SecureAcl $StatusPath $false
}

function Get-CorruptStateFiles {
    return @(Get-ChildItem -LiteralPath $Root -Filter 'status.corrupt-*.json' -File -ErrorAction Stop)
}

function Remove-CorruptStateFiles {
    foreach ($file in @(Get-CorruptStateFiles)) { Remove-Item -LiteralPath $file.FullName -Force }
}

function Write-AtomicBytes([string]$Destination, [byte[]]$Bytes, [bool]$Json = $false) {
    $temp = Join-Path (Split-Path -Parent $Destination) ('.duckdns-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllBytes($temp, $Bytes)
        if ($Json) {
            $verified = [IO.File]::ReadAllText($temp, [Text.Encoding]::UTF8) | ConvertFrom-Json
            if ($null -eq $verified) { throw 'JSON validation failed.' }
        }
        Set-SecureAcl $temp $false
        if ([IO.File]::Exists($Destination)) { [IO.File]::Replace($temp, $Destination, [System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temp, $Destination) }
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}

function Write-AtomicJson([string]$Destination, $Value) {
    $json = ConvertTo-Json -InputObject $Value -Depth 10
    $check = ConvertFrom-Json -InputObject $json
    if ($null -eq $check) { throw 'JSON validation failed.' }
    $encoder = [Text.UTF8Encoding]::new($false)
    $bytes = $encoder.GetBytes($json + "`r`n")
    Write-AtomicBytes $Destination $bytes $true
}

function Set-SecureAcl([string]$Path, [bool]$IsDirectory) {
    $sidSystem = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $sidAdmins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    if ($IsDirectory) { $acl = [IO.Directory]::GetAccessControl($Path) }
    else { $acl = [IO.File]::GetAccessControl($Path) }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }
    $rights = [Security.AccessControl.FileSystemRights]::FullControl
    $type = [Security.AccessControl.AccessControlType]::Allow
    $flags = [Security.AccessControl.InheritanceFlags]::None
    if ($IsDirectory) { $flags = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit }
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sidSystem, $rights, $flags, $propagation, $type))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sidAdmins, $rights, $flags, $propagation, $type))
    if ($IsDirectory) { [IO.Directory]::SetAccessControl($Path, $acl) }
    else { [IO.File]::SetAccessControl($Path, $acl) }
}

function Protect-Runtime {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { [void][IO.Directory]::CreateDirectory($Root) }
    Set-SecureAcl $Root $true
    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) { [void][IO.Directory]::CreateDirectory($LogDirectory) }
    Set-SecureAcl $LogDirectory $true
    foreach ($path in @($InstalledScript, $ConfigPath, $PreviousConfigPath, $TokenPath, $CredentialReceiptPath, $StatusPath, $LockPath)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { Set-SecureAcl $path $false }
    }
    foreach ($file in @(Get-CorruptStateFiles)) { Set-SecureAcl $file.FullName $false }
    foreach ($name in @('DuckDNS-Manager.log', 'DuckDNS-Manager.1.log')) {
        $path = Join-Path $LogDirectory $name
        if (Test-Path -LiteralPath $path -PathType Leaf) { Set-SecureAcl $path $false }
    }
}

function ConvertTo-TokenBytes([Security.SecureString]$Secure) {
    $handle = [IntPtr]::Zero
    try {
        $handle = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($handle)
        if ($plain.Length -lt 8 -or $plain.Length -gt 256 -or $plain -notmatch '^[A-Za-z0-9-]+$') { throw 'Invalid token format.' }
        $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
        try {
            return [Security.Cryptography.ProtectedData]::Protect($bytes, $null,
                [Security.Cryptography.DataProtectionScope]::LocalMachine)
        } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
    } finally {
        if ($handle -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($handle) }
        $plain = $null
    }
}

function Read-Token {
    if (-not [IO.File]::Exists($TokenPath)) { throw 'Token unavailable.' }
    $cipher = [IO.File]::ReadAllBytes($TokenPath)
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($cipher, $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine)
    try {
        $token = [Text.Encoding]::UTF8.GetString($bytes)
        if ($token.Length -lt 8 -or $token.Length -gt 256 -or $token -notmatch '^[A-Za-z0-9-]+$') { throw 'Invalid token data.' }
        return $token
    }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Test-TokenLocal {
    try { $token = Read-Token; return (-not [string]::IsNullOrWhiteSpace($token)) }
    catch { return $false }
    finally { $token = $null }
}

function Get-TokenFileIdentity {
    $cipher = [IO.File]::ReadAllBytes($TokenPath)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($hash.ComputeHash($cipher)) }
    finally { $hash.Dispose(); [Array]::Clear($cipher, 0, $cipher.Length) }
}

function Write-CredentialReceipt($Value) {
    if (-not $script:RunLockHeld) { throw 'Credential receipt write requires lock.' }
    $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $Value -Compress))
    try {
        $cipher = [Security.Cryptography.ProtectedData]::Protect($bytes, $null,
            [Security.Cryptography.DataProtectionScope]::LocalMachine)
        try { Write-AtomicBytes $CredentialReceiptPath $cipher }
        finally { [Array]::Clear($cipher, 0, $cipher.Length) }
    } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Read-CredentialReceipt {
    $cipher = [IO.File]::ReadAllBytes($CredentialReceiptPath)
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($cipher, $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine)
    try { return (ConvertFrom-Json ([Text.Encoding]::UTF8.GetString($bytes))) }
    finally { [Array]::Clear($bytes, 0, $bytes.Length); [Array]::Clear($cipher, 0, $cipher.Length) }
}

function Reset-CredentialVerification($State) {
    $State.CredentialStatus = 'Pending'; $State.CredentialHostname = $null
    $State.CredentialVerificationId = $null; $State.LastCredentialVerificationUtc = $null
}

function Get-CredentialsStatus($Config, $State) {
    if (-not (Test-TokenLocal)) { return '[FAIL] Unavailable' }
    try {
        $receipt = Read-CredentialReceipt
        if (-not $State.CredentialVerificationId -or $State.CredentialHostname -cne $Config.Hostname -or
            $receipt.Id -cne $State.CredentialVerificationId -or $receipt.Hostname -cne $Config.Hostname -or
            $receipt.TokenIdentity -cne (Get-TokenFileIdentity) -or $receipt.Status -cne $State.CredentialStatus) {
            return '[WARN] Protected; verification pending'
        }
        if ($State.CredentialStatus -eq 'Verified' -and $State.LastCredentialVerificationUtc) {
            return '[OK] Protected and verified'
        }
        if ($State.CredentialStatus -eq 'Rejected') { return '[FAIL] Rejected' }
    } catch { }
    return '[WARN] Protected; verification pending'
}

function Set-CredentialOutcome($Config, $State, $Api) {
    if ($Api.Kind -notin @('Success','Rejected')) { return }
    # The opaque receipt ID is public state; the ciphertext identity stays DPAPI-protected.
    # A changed hostname/token, unreadable receipt or partial write always becomes pending.
    Reset-CredentialVerification $State
    try {
        $identity = Get-TokenFileIdentity
        if ($identity -cne $Api.TokenIdentity) { return }
        $id = [guid]::NewGuid().ToString('D')
        $status = 'Rejected'; $verified = $null
        if ($Api.Kind -eq 'Success') { $status = 'Verified'; $verified = [DateTime]::UtcNow.ToString('o') }
        Write-CredentialReceipt ([pscustomobject]@{ Id = $id; Hostname = $Config.Hostname;
            TokenIdentity = $identity; Status = $status })
        $State.CredentialStatus = $status; $State.CredentialHostname = $Config.Hostname
        $State.CredentialVerificationId = $id; $State.LastCredentialVerificationUtc = $verified
    } catch { Reset-CredentialVerification $State }
}

function Enter-RunLock {
    try {
        $handle = [IO.FileStream]::new($LockPath, [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $script:RunLockHeld = $true
        return $handle
    } catch [IO.IOException] { return $null }
}

function Exit-RunLock($Handle) {
    try { if ($null -ne $Handle) { $Handle.Dispose() } }
    finally { $script:RunLockHeld = $false; $script:RunClock = $null }
}

function Start-Deadline { $script:RunClock = [Diagnostics.Stopwatch]::StartNew() }

function Assert-Deadline([int]$ReserveSeconds = 0) {
    if ($null -ne $script:RunClock -and
        $script:RunClock.Elapsed.TotalSeconds + $ReserveSeconds -ge $InternalLimitSeconds) {
        throw [TimeoutException]::new('Execution timeout')
    }
}

function Wait-Retry([int]$Seconds) {
    Assert-Deadline $Seconds
    Start-Sleep -Seconds $Seconds
    Assert-Deadline
}

function New-Line([string]$Label, [string]$Value) {
    return [pscustomobject]@{ Label = $Label; Value = $Value }
}

function Write-Rows($Rows) {
    $width = 26
    foreach ($row in $Rows) { $width = [Math]::Max($width, $row.Label.Length + 4) }
    foreach ($row in $Rows) {
        if ($row.PSObject.Properties['Section']) { Show-Section $row.Section; continue }
        $dots = '.' * ($width - $row.Label.Length - 1)
        Write-Host (' ' + $row.Label + ' ' + $dots + ' ' + $row.Value)
    }
}

function Show-Header([string]$Title) {
    Clear-Host
    Write-Host ('=' * 70)
    Write-Host (' DUCKDNS MANAGER' + $(if ($Title) { ' > ' + $Title } else { '' }))
    Write-Host ('=' * 70)
    Write-Host ''
}

function Show-Section([string]$Title) {
    Write-Host ''
    Write-Host ('-' * 70)
    Write-Host (' ' + $Title)
    Write-Host ('-' * 70)
    Write-Host ''
}

function Read-Choice([string]$Prompt = 'Option') {
    Write-Host -NoNewline (' ' + $Prompt + ': ')
    return [Console]::ReadLine()
}

function Wait-Back {
    Write-Host ''
    Write-Host ' [0] Back'
    while ($true) {
        $choice = Read-Choice
        if ($choice -eq '0') { return }
        Write-Rows @((New-Line 'Input' '[WARN] Enter 0 to go back'))
    }
}

function Read-Number([string]$Prompt, [int]$Minimum, [int]$Maximum) {
    while ($true) {
        $raw = Read-Choice ($Prompt + " ($Minimum-$Maximum, 0 cancels)")
        if ($raw -eq '0') { return $null }
        $value = 0
        if ([int]::TryParse($raw, [ref]$value) -and $value -ge $Minimum -and $value -le $Maximum) { return $value }
        Write-Rows @((New-Line 'Input' '[WARN] Enter a valid number'))
    }
}

function Read-Confirmation([string]$Prompt) {
    $answer = Read-Choice ($Prompt + ' [y/N]')
    return ($answer -ceq 'y' -or $answer -ceq 'Y')
}

function Format-Time($Utc, [bool]$Seconds = $true) {
    if ([string]::IsNullOrWhiteSpace([string]$Utc)) { return 'Never' }
    try {
        $date = [DateTime]::Parse([string]$Utc, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
        if ($Seconds) { return $date.ToString('yyyy-MM-dd HH:mm:ss') }
        return $date.ToString('yyyy-MM-dd HH:mm')
    } catch { return 'Unknown' }
}

function Format-StateTime($State, [string]$Name, [bool]$Seconds = $true) {
    if ($State.PSObject.Properties['HistoryKnown'] -and -not $State.HistoryKnown) { return 'Unknown' }
    return (Format-Time $State.$Name $Seconds)
}

function Get-StatusText($State) {
    if ($State.ReadKind -eq 'ReadError') { return '[FAIL] Saved state unreadable' }
    if ($State.ReadKind -eq 'InvalidJson' -and -not $State.CanPersist) { return '[WARN] Saved state invalid' }
    switch ($State.SynchronizationState) {
        'Synchronized' { return '[OK] Synchronized' }
        'Pending' { return '[WARN] Propagation pending' }
        'Accepted' { return '[OK] Update accepted' }
        'Failed' { return '[FAIL] Check failed' }
        default { return '[INFO] Unknown' }
    }
}

function Write-AppLog($Config, [string]$ReasonName, [string]$Result, [int]$ExitCode) {
    if (-not $Config.Logging.Enabled) { return }
    try {
        $path = Join-Path $LogDirectory 'DuckDNS-Manager.log'
        if ([IO.File]::Exists($path) -and (Get-Item -LiteralPath $path).Length -gt 1048576) {
            $old = Join-Path $LogDirectory 'DuckDNS-Manager.1.log'
            if ([IO.File]::Exists($old)) { [IO.File]::Delete($old) }
            [IO.File]::Move($path, $old)
        }
        $safe = [regex]::Replace($Result, '[^A-Za-z0-9 ._-]', '')
        [IO.File]::AppendAllText($path, ([DateTime]::UtcNow.ToString('o') + ' ' + $ReasonName +
            ' Exit=' + $ExitCode + ' ' + $safe + "`r`n"), [Text.UTF8Encoding]::new($false))
    } catch { }
}

function Initialize-BoundHttp {
    if ('DuckDns.Native.BoundHttp' -as [type]) { return }
    # Native delegate: network callbacks have no PowerShell runspace.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
namespace DuckDns.Native {
    public sealed class SourceBinding {
        private readonly IPAddress source;
        public SourceBinding(string address) {
            source = IPAddress.Parse(address);
            if (source.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("IPv4 source required.");
        }
        public IPEndPoint Bind(ServicePoint point, IPEndPoint remote, int retry) {
            if (remote.AddressFamily != AddressFamily.InterNetwork || retry > 2)
                throw new InvalidOperationException("IPv4 binding unavailable.");
            return new IPEndPoint(source, 0);
        }
    }
    public static class BoundHttp {
        public static string Get(string url, string source, int timeout) {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Proxy = null;
            request.AllowAutoRedirect = false;
            request.KeepAlive = false;
            request.Timeout = timeout;
            request.ReadWriteTimeout = timeout;
            request.ConnectionGroupName = "DuckDns-" + Guid.NewGuid().ToString("N");
            ServicePoint point = request.ServicePoint;
            SourceBinding binding = new SourceBinding(source);
            lock (point) {
                BindIPEndPoint previous = point.BindIPEndPointDelegate;
                HttpWebResponse response = null;
                try {
                    point.BindIPEndPointDelegate = binding.Bind;
                    response = (HttpWebResponse)request.GetResponse();
                    if (response.StatusCode != HttpStatusCode.OK)
                        throw new InvalidOperationException("Provider response unavailable.");
                    using (Stream stream = response.GetResponseStream()) {
                        byte[] data = new byte[129];
                        int count = 0;
                        while (count < data.Length) {
                            int read = stream.Read(data, count, data.Length - count);
                            if (read == 0) break;
                            count += read;
                        }
                        if (count > 128) throw new InvalidOperationException("Provider response invalid.");
                        return Encoding.ASCII.GetString(data, 0, count);
                    }
                } finally {
                    // Restoration must run even if response disposal or abort fails.
                    try { if (response != null) response.Close(); }
                    finally {
                        try { request.Abort(); }
                        finally {
                            try { point.CloseConnectionGroup(request.ConnectionGroupName); }
                            finally { point.BindIPEndPointDelegate = previous; }
                        }
                    }
                }
            }
        }
    }
}
'@ -IgnoreWarnings -ErrorAction Stop
}

function Test-UsableLocalIPv4([string]$Value) {
    if (-not (Test-IPv4 $Value)) { return $false }
    $n = [Net.IPAddress]::Parse($Value).GetAddressBytes()
    return ($n[0] -ne 0 -and $n[0] -ne 127 -and $n[0] -lt 224 -and
        -not ($n[0] -eq 169 -and $n[1] -eq 254))
}

function Get-UsableInterfaces {
    # .NET inventory also includes usable PPP/tunnel adapters. Never filter by name.
    $adapters = @()
    try { $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop) } catch { }
    $result = @()
    foreach ($network in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($network.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up) { continue }
        $id = [guid]::Empty
        if (-not [guid]::TryParse($network.Id, [ref]$id) -or $id -eq [guid]::Empty) { continue }
        try {
            $index = $network.GetIPProperties().GetIPv4Properties().Index
            $addresses = @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { [string]$_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource -and
                    (Test-UsableLocalIPv4 ([string]$_.IPAddress)) } |
                Sort-Object IPAddress | ForEach-Object { [string]$_.IPAddress } | Select-Object -Unique)
            if (-not $addresses.Count) { continue }
            $adapter = @($adapters | Where-Object { [string]$_.InterfaceGuid -and
                ([guid]$_.InterfaceGuid) -eq $id } | Select-Object -First 1)
            $virtual = ($network.NetworkInterfaceType -in @([Net.NetworkInformation.NetworkInterfaceType]::Tunnel,
                [Net.NetworkInformation.NetworkInterfaceType]::Ppp))
            if ($adapter.Count -and ($adapter[0].Virtual -eq $true -or $adapter[0].HardwareInterface -eq $false)) { $virtual = $true }
            $result += [pscustomobject]@{ InterfaceGuid = $id.ToString('D'); InterfaceAlias = $network.Name;
                InterfaceIndex = $index; IPv4 = $addresses[0]; Addresses = $addresses; IsVirtual = $virtual }
        } catch { continue }
    }
    return @($result | Sort-Object InterfaceAlias, InterfaceGuid)
}

function Get-PublicIpContext($Config) {
    if ($Config.NetworkInterface.Mode -eq 'Automatic') {
        return [pscustomobject]@{ Mode = 'Automatic'; Available = $true; InterfaceGuid = $null;
            InterfaceAlias = $null; InterfaceIndex = $null; IPv4 = $null }
    }
    $id = [guid]$Config.NetworkInterface.InterfaceGuid
    $selected = @()
    try { $selected = @(Get-UsableInterfaces | Where-Object { ([guid]$_.InterfaceGuid) -eq $id } | Select-Object -First 1) } catch { }
    if (-not $selected.Count) {
        return [pscustomobject]@{ Mode = 'Specific'; Available = $false; InterfaceGuid = $id.ToString('D');
            InterfaceAlias = $null; InterfaceIndex = $null; IPv4 = $null }
    }
    return [pscustomobject]@{ Mode = 'Specific'; Available = $true; InterfaceGuid = $id.ToString('D');
        InterfaceAlias = $selected[0].InterfaceAlias; InterfaceIndex = $selected[0].InterfaceIndex; IPv4 = $selected[0].IPv4 }
}

function Test-PublicIpContext($Context) {
    if ($Context.Mode -eq 'Automatic') { return $true }
    if (-not $Context.Available) { return $false }
    $current = @()
    try { $current = @(Get-UsableInterfaces | Where-Object { ([guid]$_.InterfaceGuid) -eq ([guid]$Context.InterfaceGuid) }) } catch { return $false }
    return ($current.Count -eq 1 -and $current[0].InterfaceIndex -eq $Context.InterfaceIndex -and
        $Context.IPv4 -in $current[0].Addresses)
}

function Invoke-BoundProvider([string]$Url, [string]$SourceIPv4) {
    Initialize-BoundHttp
    return [DuckDns.Native.BoundHttp]::Get($Url, $SourceIPv4, 8000)
}

function New-InterfaceUnavailableException {
    $failure = [InvalidOperationException]::new('Selected interface unavailable.')
    $failure.Data['DuckDnsInterfaceUnavailable'] = $true
    return $failure
}

function Test-InterfaceUnavailableException($ErrorRecord) {
    $failure = $ErrorRecord.Exception
    while ($null -ne $failure) {
        if ($failure.Data['DuckDnsInterfaceUnavailable']) { return $true }
        $failure = $failure.InnerException
    }
    return $false
}

function Invoke-Provider([string]$Url, $Context) {
    Assert-Deadline 16
    # Context is mandatory. Specific must never reach the automatic request path.
    if ($null -eq $Context -or -not (Test-PublicIpContext $Context)) { throw (New-InterfaceUnavailableException) }
    try {
        if ($Context.Mode -eq 'Specific') { $content = Invoke-BoundProvider $Url $Context.IPv4 }
        else { $content = (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop).Content }
        Assert-Deadline
        # Drop a response if the selected source ceased to be usable during the call.
        if (-not (Test-PublicIpContext $Context)) { throw (New-InterfaceUnavailableException) }
        $ip = ([string]$content).Trim()
        if (Test-IPv4 $ip $true) { return $ip }
    } catch [TimeoutException] { throw }
    catch { if (Test-InterfaceUnavailableException $_) { throw } }
    Assert-Deadline
    return $null
}

function New-PublicIpResult($IP, $Results, $Context, [bool]$Unavailable = $false) {
    return [pscustomobject]@{ IP = $IP; Results = @($Results); Context = $Context; InterfaceUnavailable = $Unavailable }
}

function Find-PublicIPv4($Config, [bool]$AllProviders = $false) {
    $results = @(); $context = Get-PublicIpContext $Config
    if (-not $context.Available) { return (New-PublicIpResult $null $results $context $true) }
    for ($attempt = 1; $attempt -le [int]$Config.Retry.Attempts; $attempt++) {
        foreach ($provider in $Providers) {
            try { $ip = Invoke-Provider $provider $context }
            catch {
                if (Test-InterfaceUnavailableException $_) { return (New-PublicIpResult $null $results $context $true) }
                throw
            }
            $results += [pscustomobject]@{ Provider = ([uri]$provider).Host; IP = $ip }
            if ($ip -and -not $AllProviders) { return (New-PublicIpResult $ip $results $context) }
        }
        if ($AllProviders) { break }
        if ($attempt -lt [int]$Config.Retry.Attempts) { Wait-Retry ([int]$Config.Retry.DelaySeconds) }
    }
    $first = @($results | Where-Object { $_.IP } | Select-Object -First 1)
    if ($first.Count) { return (New-PublicIpResult $first[0].IP $results $context) }
    return (New-PublicIpResult $null $results $context)
}

function Get-ResolverChain($Config) {
    if ($Config.Dns.Mode -eq 'System') { return @('Windows') }
    return @(@([string]$Config.Dns.ManualServer) + $ManualFallbacks | Select-Object -Unique)
}

function Test-NoAError($ErrorRecord) {
    $id = ([string]$ErrorRecord.FullyQualifiedErrorId).Split(',')[0]
    if ($id -in @('DNS_INFO_NO_RECORDS','DNS_ERROR_RCODE_NAME_ERROR')) { return $true }
    return ($ErrorRecord.Exception.NativeErrorCode -in @(9501,9003))
}

function Invoke-DnsQuery([string]$Domain, [string]$Server) {
    Assert-Deadline 16
    try {
        $options = @{ Name = $Domain; Type = 'A'; DnsOnly = $true; NoHostsFile = $true;
            QuickTimeout = $true; ErrorAction = 'Stop' }
        if ($Server -ne 'Windows') { $options.Server = $Server }
        $answers = @(Resolve-DnsName @options)
        $ips = @($answers | Where-Object { $_.Type -eq 'A' -and (Test-IPv4 ([string]$_.IPAddress)) } |
            ForEach-Object { [string]$_.IPAddress } | Select-Object -Unique)
        Assert-Deadline
        return [pscustomobject]@{ Success = $true; Addresses = $ips }
    } catch [TimeoutException] { throw }
    catch {
        Assert-Deadline
        if (Test-NoAError $_) { return [pscustomobject]@{ Success = $true; Addresses = @() } }
        return [pscustomobject]@{ Success = $false; Addresses = @() }
    }
}

function Resolve-HostA($Config, [bool]$Retry = $true, [bool]$TestChain = $false) {
    $count = 1; $results = @(); $chosen = $null
    if ($Retry) { $count = [int]$Config.Retry.Attempts }
    $chain = @(Get-ResolverChain $Config)
    for ($attempt = 1; $attempt -le $count; $attempt++) {
        foreach ($server in $chain) {
            $query = Invoke-DnsQuery (Get-DuckDnsDomain $Config) $server
            $results += [pscustomobject]@{ Server = $server; Success = $query.Success; Addresses = $query.Addresses }
            if ($query.Success) {
                if ($null -eq $chosen) {
                    $chosen = [pscustomobject]@{ Success = $true; Addresses = $query.Addresses;
                        Resolver = $server; IsFallback = ($server -ne $chain[0]); Results = @() }
                }
                if (-not $TestChain) { $chosen.Results = $results; return $chosen }
            }
        }
        if ($TestChain) { break }
        if ($attempt -lt $count) { Wait-Retry ([int]$Config.Retry.DelaySeconds) }
    }
    if ($null -ne $chosen) { $chosen.Results = $results; return $chosen }
    return [pscustomobject]@{ Success = $false; Addresses = @(); Resolver = $null; IsFallback = $false; Results = $results }
}

function Get-ResolverRow($Answer) {
    if (-not $Answer.Success) { return (New-Line 'DNS resolver' '[FAIL] Resolution failed') }
    $value = '[OK] ' + $Answer.Resolver
    if ($Answer.IsFallback) { $value = '[WARN] ' + $Answer.Resolver + ' fallback' }
    return (New-Line 'DNS resolver' $value)
}

function Get-ProviderConsensus($Results) {
    $valid = @($Results | Where-Object { $_.IP -and (Test-IPv4 ([string]$_.IP) $true) } |
        Group-Object Provider | ForEach-Object { $_.Group | Select-Object -Last 1 })
    $winner = @($valid | Group-Object IP | Where-Object { $_.Count -ge 2 } | Select-Object -First 1)
    if ($winner.Count) { return [string]$winner[0].Name }
    return $null
}

function Confirm-PublicIPv4($Config, $Found) {
    $results = @($Found.Results); $context = $Found.Context
    if ($null -eq $context -or -not (Test-PublicIpContext $context) -or
        $context.Mode -cne $Config.NetworkInterface.Mode -or ($context.Mode -eq 'Specific' -and
        ([guid]$context.InterfaceGuid) -ne ([guid]$Config.NetworkInterface.InterfaceGuid))) {
        return (New-PublicIpResult $null $results $context $true)
    }
    foreach ($provider in $Providers) {
        $hostName = ([uri]$provider).Host
        if (@($results | Where-Object { $_.Provider -eq $hostName -and $_.IP }).Count) { continue }
        try { $ip = Invoke-Provider $provider $context }
        catch {
            if (Test-InterfaceUnavailableException $_) { return (New-PublicIpResult $null $results $context $true) }
            throw
        }
        $results += [pscustomobject]@{ Provider = $hostName; IP = $ip }
        $consensus = Get-ProviderConsensus $results
        if ($consensus) { return (New-PublicIpResult $consensus $results $context) }
    }
    return (New-PublicIpResult (Get-ProviderConsensus $results) $results $context)
}

function Get-InterfaceFailureRows {
    return @((New-Line 'Network interface' '[FAIL] Selected interface unavailable'),
        (New-Line 'Public IPv4' '[FAIL] Could not query selected interface'),
        (New-Line 'DuckDNS API' '[SKIP] No valid IPv4 available'),
        (New-Line 'Result' '[FAIL] Network interface unavailable'))
}

function Get-ErrorExceptions($ErrorObject) {
    $exception = $ErrorObject
    if ($ErrorObject -is [Management.Automation.ErrorRecord]) { $exception = $ErrorObject.Exception }
    for ($depth = 0; $depth -lt 10 -and $exception -is [Exception]; $depth++) {
        $exception
        $exception = $exception.InnerException
    }
}

function Get-SafeRequestFailure($ErrorObject) {
    $exceptions = @(Get-ErrorExceptions $ErrorObject)
    foreach ($exception in $exceptions) {
        if ($exception.PSObject.Properties['Response'] -and $null -ne $exception.Response -and
            $exception.Response.PSObject.Properties['StatusCode']) {
            try {
                $httpCode = [int]$exception.Response.StatusCode
                if ($httpCode -ge 400 -and $httpCode -le 599) { return ('HTTP ' + $httpCode) }
            } catch { }
        }
    }
    foreach ($exception in $exceptions) {
        if ($exception -is [Net.WebException]) {
            switch ($exception.Status) {
                'NameResolutionFailure' { return 'API DNS lookup failed' }
                'ProxyNameResolutionFailure' { return 'Proxy DNS lookup failed' }
                'ConnectFailure' { return 'Connection failed' }
                'Timeout' { return 'Request timed out' }
                'TrustFailure' { return 'Certificate validation failed' }
                'SecureChannelFailure' { return 'TLS handshake failed' }
                'ConnectionClosed' { return 'Connection closed' }
                'SendFailure' { return 'Request send failed' }
                'ReceiveFailure' { return 'Response receive failed' }
                'RequestCanceled' { return 'Request canceled' }
            }
        }
        if ($exception -is [Security.Authentication.AuthenticationException]) { return 'TLS handshake failed' }
        if ($exception -is [TimeoutException]) { return 'Request timed out' }
    }
    # Exception messages, URLs, headers and response bodies may contain credentials.
    return 'Network request failed'
}

function Invoke-DuckDnsApi($Config, [string]$PublicIP, [bool]$SingleAttempt = $false) {
    $token = $null
    try { $tokenIdentity = Get-TokenFileIdentity; $token = Read-Token }
    catch { return [pscustomobject]@{ Kind = 'Token'; Status = 'Unavailable' } }
    try {
        $hostname = $Config.Hostname
        $url = 'https://www.duckdns.org/update?domains=' + [uri]::EscapeDataString($hostname) +
            '&token=' + [uri]::EscapeDataString($token) + '&ip=' + [uri]::EscapeDataString($PublicIP) + '&verbose=true'
        $attempts = [int]$Config.Retry.Attempts
        if ($SingleAttempt) { $attempts = 1 }
        $failure = 'Network request failed'
        for ($attempt = 1; $attempt -le $attempts; $attempt++) {
            Assert-Deadline 16
            try {
                $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
                Assert-Deadline
                # Windows PowerShell may return bytes when Content-Type is absent.
                $body = $response.Content
                if ($body -is [byte[]]) { $body = [Text.Encoding]::UTF8.GetString($body) }
                $body = ([string]$body).Trim().TrimStart([char]0xFEFF).Trim()
                $lines = @($body -split '\r\n|\n|\r')
                if ($lines.Count -and $lines[0].Trim() -eq 'KO') { return [pscustomobject]@{ Kind = 'Rejected'; Status = 'Rejected'; TokenIdentity = $tokenIdentity } }
                if ($lines.Count -and $lines[0].Trim() -eq 'OK') {
                    $status = 'Updated'
                    if (@($lines | Where-Object { $_.Trim() -eq 'NOCHANGE' }).Count) { $status = 'NoChange' }
                    return [pscustomobject]@{ Kind = 'Success'; Status = $status; TokenIdentity = $tokenIdentity }
                }
                return [pscustomobject]@{ Kind = 'InvalidResponse'; Status = 'InvalidResponse'; Failure = 'Unexpected API response' }
            } catch {
                Assert-Deadline
                $failure = Get-SafeRequestFailure $_
                if ($attempt -lt $attempts) { Wait-Retry ([int]$Config.Retry.DelaySeconds) }
            }
        }
        return [pscustomobject]@{ Kind = 'Network'; Status = 'Unavailable'; Failure = $failure }
    } finally {
        $url = $null
        $token = $null
    }
}

function Invoke-CheckFlow($Config, $State, [string]$RunReason, [bool]$SingleAttempt = $false) {
    $lines = @()
    $code = 0
    $now = [DateTime]::UtcNow.ToString('o')
    $previousPublic = $State.LastDetectedPublicIPv4
    $previousSync = $State.SynchronizationState
    $previousUpdate = $State.LastSuccessfulUpdateUtc
    $State.Domain = Get-DuckDnsDomain $Config
    $credentials = Get-CredentialsStatus $Config $State
    if ($credentials -eq '[WARN] Protected; verification pending') { Reset-CredentialVerification $State }
    $State.LastCheckUtc = $now
    $State.LastReason = $RunReason
    if (-not $Config.CompareIpBeforeUpdate) { $State.DuckDnsIPv4 = $null }
    if (-not (Test-TokenLocal)) {
        Reset-CredentialVerification $State
        $State.LastDetectedPublicIPv4 = $null
        $State.DuckDnsIPv4 = $null
        $lines += New-Line 'Credentials' '[FAIL] Unavailable'
        $lines += New-Line 'DuckDNS API' '[SKIP] No request sent'
        $lines += New-Line 'Result' '[FAIL] Token unavailable'
        $State.SynchronizationState = 'Failed'
        $State.LastResult = $lines[-1].Value
        $State.LastExitCode = $ExitCodes.Token
        return [pscustomobject]@{ Lines = $lines; ExitCode = $ExitCodes.Token }
    }
    $found = Find-PublicIPv4 $Config
    if ($found.InterfaceUnavailable) {
        return [pscustomobject]@{ Lines = @(Get-InterfaceFailureRows); ExitCode = $ExitCodes.PublicIp }
    }
    if (-not $found.IP) {
        $State.LastDetectedPublicIPv4 = $null
        $State.DuckDnsIPv4 = $null
        $lines += New-Line 'Public IPv4' '[FAIL] All providers failed'
        $lines += New-Line 'DuckDNS API' '[SKIP] No valid IPv4 available'
        $lines += New-Line 'Result' '[FAIL] Public IPv4 detection failed'
        $code = $ExitCodes.PublicIp
    } else {
        $ip = $found.IP
        $State.LastDetectedPublicIPv4 = $ip
        $lines += New-Line 'Public IPv4' ('[OK] ' + $ip)
        $before = $null
        if ($Config.CompareIpBeforeUpdate) {
            $before = Resolve-HostA $Config
            if (-not $before.Success) {
                $State.DuckDnsIPv4 = $null
                $lines += New-Line 'DuckDNS DNS' '[FAIL] Resolution failed'
                $lines += New-Line 'DuckDNS API' '[SKIP] Comparison unavailable'
                $lines += New-Line 'Result' '[FAIL] DNS resolution failed'
                $code = $ExitCodes.Dns
            } else {
                $shown = 'No A record'
                if ($before.Addresses.Count) { $shown = $before.Addresses -join ', ' }
                $lines += New-Line 'DuckDNS DNS' ('[OK] ' + $shown)
                $lines += Get-ResolverRow $before
                $State.DuckDnsIPv4 = $null
                if ($before.Addresses.Count) { $State.DuckDnsIPv4 = $shown }
            }
        }
        if ($code -eq 0) {
            $equal = $false
            if ($null -ne $before -and $before.Addresses.Count -eq 1) { $equal = ($before.Addresses[0] -eq $ip) }

            $recentPending = $false
            if ($credentials -eq '[OK] Protected and verified' -and -not $equal -and $previousSync -eq 'Pending' -and $previousPublic -eq $ip -and $previousUpdate) {
                try {
                    $age = ([DateTime]::UtcNow - [DateTime]::Parse([string]$previousUpdate).ToUniversalTime()).TotalMinutes
                    $recentPending = ($age -ge 0 -and $age -lt 5)
                } catch { }
            }
            if ($recentPending) {
                $State.SynchronizationState = 'Pending'
                $lines += New-Line 'DuckDNS API' '[SKIP] Waiting for DNS propagation'
                $lines += New-Line 'Result' '[WARN] Propagation pending'
                return [pscustomobject]@{ Lines = $lines; ExitCode = 0 }
            }
            if (-not $equal) {
                $confirmedIP = Confirm-PublicIPv4 $Config $found
                if ($confirmedIP.InterfaceUnavailable) {
                    $State.LastDetectedPublicIPv4 = $previousPublic
                    return [pscustomobject]@{ Lines = @(Get-InterfaceFailureRows); ExitCode = $ExitCodes.PublicIp }
                }
                if (-not $confirmedIP.IP) {
                    $State.LastDetectedPublicIPv4 = $previousPublic
                    $lines[0] = New-Line 'Public IPv4' '[WARN] Provider disagreement'
                    $lines += New-Line 'DuckDNS API' '[SKIP] IP change not confirmed'
                    $lines += New-Line 'Result' '[WARN] Public IPv4 change unconfirmed'
                    return [pscustomobject]@{ Lines = $lines; ExitCode = $ExitCodes.PublicIp }
                }
                $ip = $confirmedIP.IP
                $State.LastDetectedPublicIPv4 = $ip
                $lines[0] = New-Line 'Public IPv4' ('[OK] ' + $ip)
                if ($null -ne $before -and $before.Addresses.Count -eq 1) { $equal = ($before.Addresses[0] -eq $ip) }
            }
            $historyKnown = (-not $State.PSObject.Properties['HistoryKnown'] -or $State.HistoryKnown)
            $forced = $false
            if ($equal -and $Config.ForcedUpdate.Enabled -and $historyKnown) {
                $last = [DateTime]::MinValue
                if ($State.LastSuccessfulUpdateUtc) {
                    try { $last = [DateTime]::Parse([string]$State.LastSuccessfulUpdateUtc).ToUniversalTime() } catch { }
                }
                $forced = ([DateTime]::UtcNow - $last).TotalHours -ge [int]$Config.ForcedUpdate.IntervalHours
            }
            $needsVerification = ($credentials -ne '[OK] Protected and verified' -and
                (-not $State.PSObject.Properties['CanPersist'] -or $State.CanPersist))
            if ($equal -and -not $forced -and -not $needsVerification) {
                $State.SynchronizationState = 'Synchronized'
                $lines += New-Line 'DuckDNS API' '[SKIP] No update required'
                $lines += New-Line 'Result' '[OK] Synchronized'
            } else {
                $api = Invoke-DuckDnsApi $Config $ip ($SingleAttempt -or ($equal -and -not $forced))
                Set-CredentialOutcome $Config $State $api
                if ($api.Kind -eq 'Success') {
                    $State.LastSuccessfulUpdateUtc = [DateTime]::UtcNow.ToString('o')
                    $apiMessage = '[OK] Updated'
                    if ($api.Status -eq 'NoChange') { $apiMessage = '[OK] No change reported' }
                    if ($forced) { $apiMessage = $apiMessage + ' (forced)' }
                    $lines += New-Line 'DuckDNS API' $apiMessage
                    if (-not $Config.PostUpdateValidation) {
                        $State.SynchronizationState = 'Accepted'
                        $lines += New-Line 'DNS validation' '[SKIP] Disabled'
                        $lines += New-Line 'Result' '[OK] Update accepted'
                    } else {
                        Assert-Deadline 16
                        $confirmed = $false
                        $after = $null
                        for ($poll = 0; $poll -lt 3; $poll++) {
                            $after = Resolve-HostA $Config $false
                            if ($after.Success -and $after.Addresses.Count -eq 1 -and $after.Addresses[0] -eq $ip) { $confirmed = $true; break }
                            if ($poll -lt 2) { Wait-Retry 2 }
                        }
                        if ($confirmed) {
                            $State.DuckDnsIPv4 = $ip
                            $State.SynchronizationState = 'Synchronized'
                            $lines += New-Line 'DNS validation' ('[OK] ' + $ip)
                            $lines += New-Line 'Result' '[OK] Synchronized'
                        } else {
                            $State.SynchronizationState = 'Pending'
                            $State.DuckDnsIPv4 = $null
                            if ($after.Success -and $after.Addresses.Count) { $State.DuckDnsIPv4 = $after.Addresses -join ', ' }
                            $pendingDetail = '[WARN] Resolution unavailable'
                            if ($after.Success) { $pendingDetail = '[WARN] Previous address still returned' }
                            $lines += New-Line 'DNS validation' $pendingDetail
                            $lines += New-Line 'Result' '[WARN] Propagation pending'
                        }
                    }
                } elseif ($api.Kind -eq 'Token') {
                    $lines += New-Line 'Credentials' '[FAIL] Unavailable'
                    $lines += New-Line 'DuckDNS API' '[SKIP] No request sent'
                    $lines += New-Line 'Result' '[FAIL] Token unavailable'
                    $code = $ExitCodes.Token
                } else {
                    $message = '[FAIL] Request failed'
                    if ($api.Kind -eq 'Rejected') { $message = '[FAIL] Request rejected' }
                    elseif ($api.PSObject.Properties['Failure']) { $message = '[FAIL] ' + $api.Failure }
                    $lines += New-Line 'DuckDNS API' $message
                    $lines += New-Line 'Result' '[FAIL] DuckDNS update failed'
                    $code = $ExitCodes.Api
                }
            }
        }
    }
    return [pscustomobject]@{ Lines = $lines; ExitCode = $code }
}

function Complete-Check($Config, $State, [string]$RunReason, [bool]$SingleAttempt = $false) {
    $script:OpeningAddressCheck = $null
    if ($null -eq $script:RunClock) { Start-Deadline }
    if ($State.Domain -and $State.Domain -cne (Get-DuckDnsDomain $Config)) {
        foreach ($name in @('LastDetectedPublicIPv4','DuckDnsIPv4','LastCheckUtc','LastSuccessfulUpdateUtc','LastSuccessfulCheckUtc','LastReason','LastResult')) { $State.$name = $null }
        $State.SynchronizationState = 'Unknown'; $State.ConsecutiveFailures = 0
        Reset-CredentialVerification $State
    }
    try { $result = Invoke-CheckFlow $Config $State $RunReason $SingleAttempt }
    catch [TimeoutException] {
        $result = [pscustomobject]@{ Lines = @((New-Line 'Result' '[FAIL] Execution timeout')); ExitCode = $ExitCodes.Timeout }
    }
    $lastResult = $result.Lines[-1]
    if (-not @($result.Lines | Where-Object { $_.Label -eq 'Credentials' }).Count -and
        @($result.Lines | Where-Object { $_.Label -eq 'DuckDNS API' -and -not $_.Value.StartsWith('[SKIP]') }).Count) {
        $result.Lines = @($result.Lines | Select-Object -SkipLast 1) +
            @((New-Line 'Credentials' (Get-CredentialsStatus $Config $State)), $lastResult)
    }
    $State.ApplicationVersion = $ScriptVersion
    $State.LastResult = $result.Lines[-1].Value
    $State.LastExitCode = $result.ExitCode
    if ($result.ExitCode -eq 0) {
        $State.LastSuccessfulCheckUtc = [DateTime]::UtcNow.ToString('o')
        $State.ConsecutiveFailures = 0
    } else {
        $State.SynchronizationState = 'Failed'
        $State.ConsecutiveFailures = [int][Math]::Min(2147483647, ([long]$State.ConsecutiveFailures + 1))
    }
    if ($State.ReadKind -eq 'InvalidJson' -and $State.CanPersist) {
        $result.Lines = @((New-Line 'Saved state' '[WARN] Invalid state file recovered')) + $result.Lines
    }
    try { Save-State $State }
    catch {
        $result.Lines += New-Line 'Saved state' '[FAIL] Could not save status'
        $result.ExitCode = $ExitCodes.State
    }
    Write-AppLog $Config $RunReason $State.LastResult $result.ExitCode
    return $result
}

function Get-TaskService {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    return $service
}

function Get-ManagerTaskFolder($Service, [bool]$Create) {
    try { return $Service.GetFolder($TaskFolderName) }
    catch {
        if (-not $Create) { return $null }
        return $Service.GetFolder('\').CreateFolder('DuckDNS Manager', $null)
    }
}

function Get-TaskName([string]$Kind) { return ('DuckDNS Manager - ' + $Kind) }

function Resolve-WindowsAccountSid([string]$AccountName) {
    $account = [Security.Principal.NTAccount]::new($AccountName)
    return $account.Translate([Security.Principal.SecurityIdentifier]).Value
}

function Test-SystemTaskPrincipal([string]$UserId) {
    if ($UserId -in @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18')) { return $true }
    if ([string]::IsNullOrWhiteSpace($UserId)) { return $false }
    try { return ((Resolve-WindowsAccountSid $UserId) -eq 'S-1-5-18') }
    catch { return $false }
}

function Get-TaskEnabled($Config, [string]$Kind) {
    switch ($Kind) {
        'Startup' { return [bool]$Config.Scheduling.Startup.Enabled }
        'Network' { return [bool]$Config.Scheduling.NetworkReconnect.Enabled }
        'Periodic' { return [bool]$Config.Scheduling.Periodic.Enabled }
    }
    throw 'Unknown task kind.'
}

function Get-ExpectedAction([string]$Kind) {
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $actionArguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
        $InstalledScript + '" -Scheduled -Reason ' + $Kind
    return [pscustomobject]@{ Path = $exe; Arguments = $actionArguments }
}

function Get-NetworkSubscription {
    return '<QueryList><Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"><Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000)]]</Select></Query></QueryList>'
}

function Test-NoRepetition($Trigger) {
    return ([string]::IsNullOrEmpty([string]$Trigger.Repetition.Interval) -and
        [string]::IsNullOrEmpty([string]$Trigger.Repetition.Duration))
}

function New-ManagerTaskDefinition($Service, $Config, [string]$Kind) {
    $definition = $Service.NewTask(0)
    $definition.RegistrationInfo.Description = 'DuckDNS Manager public IPv4 synchronization (' + $Kind + ').'
    $definition.Principal.UserId = 'S-1-5-18'
    $definition.Principal.LogonType = 5
    $definition.Principal.RunLevel = 1
    $settings = $definition.Settings
    $settings.Enabled = (Get-TaskEnabled $Config $Kind)
    $settings.MultipleInstances = 2
    $settings.ExecutionTimeLimit = 'PT5M'
    $settings.DisallowStartIfOnBatteries = $false
    $settings.StopIfGoingOnBatteries = $false
    $settings.RunOnlyIfNetworkAvailable = $false
    $settings.StartWhenAvailable = $true
    $settings.Hidden = $false
    $settings.AllowDemandStart = $true
    $settings.RestartCount = 0
    switch ($Kind) {
        'Startup' {
            $trigger = $definition.Triggers.Create(8)
            $trigger.Delay = [Xml.XmlConvert]::ToString([TimeSpan]::FromSeconds([int]$Config.Scheduling.Startup.DelaySeconds))
        }
        'Network' {
            $trigger = $definition.Triggers.Create(0)
            $trigger.Subscription = Get-NetworkSubscription
        }
        'Periodic' {
            $trigger = $definition.Triggers.Create(1)
            $trigger.StartBoundary = [DateTime]::Now.AddMinutes([int]$Config.Scheduling.Periodic.IntervalMinutes).ToString('yyyy-MM-ddTHH:mm:ss')
            $trigger.Repetition.Interval = [Xml.XmlConvert]::ToString([TimeSpan]::FromMinutes([int]$Config.Scheduling.Periodic.IntervalMinutes))
            # Leave Duration unset: the native default repeats indefinitely.
            $trigger.Repetition.StopAtDurationEnd = $false
        }
    }
    $trigger.Enabled = $true
    $action = $definition.Actions.Create(0)
    $expected = Get-ExpectedAction $Kind
    $action.Path = $expected.Path
    $action.Arguments = $expected.Arguments
    return $definition
}

function Compare-Duration([string]$First, [string]$Second) {
    try { return ([Xml.XmlConvert]::ToTimeSpan($First) -eq [Xml.XmlConvert]::ToTimeSpan($Second)) }
    catch { return $false }
}

function Normalize-Subscription([string]$Subscription) {
    try {
        $document = New-Object Xml.XmlDocument
        $document.LoadXml($Subscription)
        $select = @($document.SelectNodes('/*[local-name()="QueryList"]/*[local-name()="Query"]/*[local-name()="Select"]'))
        $queries = @($document.SelectNodes('/*[local-name()="QueryList"]/*[local-name()="Query"]'))
        $suppressed = @($document.SelectNodes('//*[local-name()="Suppress"]'))
        if ($queries.Count -ne 1 -or $select.Count -ne 1 -or $suppressed.Count) { return $null }
        $path = [string]$select[0].GetAttribute('Path')
        $queryPath = [string]$queries[0].GetAttribute('Path')
        if ($queryPath -and $queryPath -ine $path) { return $null }
        $filter = [regex]::Replace($select[0].InnerText, '\s+', '')
        $match = [regex]::Match($filter, '^\*\[System\[\(*EventID=([0-9]+)\)*\]\]$')
        if (-not $match.Success) { return $null }
        return ($path.ToLowerInvariant() + '|EventID=' + $match.Groups[1].Value)
    } catch { return $null }
}


function Get-ArgumentSignature([string]$Arguments) {
    if (([regex]::Matches($Arguments, '"').Count % 2) -ne 0) { return $null }
    $tokens = @([regex]::Matches($Arguments, '"[^"]*"|[^\s"]+') | ForEach-Object { $_.Value.Trim('"') })
    $hostOptions = @(); $scriptOptions = @(); $file = $null; $seen = @{}
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $key = $tokens[$i].ToLowerInvariant()
        if ($seen.ContainsKey($key)) { return $null }
        $seen[$key] = $true
        switch ($key) {
            '-noprofile' { if ($file) { return $null }; $hostOptions += $key }
            '-noninteractive' { if ($file) { return $null }; $hostOptions += $key }
            '-windowstyle' { if ($file -or ++$i -ge $tokens.Count) { return $null }; $hostOptions += $key + '=' + $tokens[$i].ToLowerInvariant() }
            '-executionpolicy' { if ($file -or ++$i -ge $tokens.Count) { return $null }; $hostOptions += $key + '=' + $tokens[$i].ToLowerInvariant() }
            '-file' { if ($file -or ++$i -ge $tokens.Count) { return $null }; $file = $tokens[$i].ToLowerInvariant() }
            '-scheduled' { if (-not $file) { return $null }; $scriptOptions += $key }
            '-reason' { if (-not $file -or ++$i -ge $tokens.Count) { return $null }; $scriptOptions += $key + '=' + $tokens[$i].ToLowerInvariant() }
            default { return $null }
        }
    }
    if (-not $file) { return $null }
    return ((@($hostOptions | Sort-Object) -join '|') + '|file=' + $file + '|' + (@($scriptOptions | Sort-Object) -join '|'))
}

function Get-SafeTaskFailure($ErrorObject, [string]$Stage) {
    $exceptions = @(Get-ErrorExceptions $ErrorObject)
    foreach ($exception in $exceptions) {
        if ($exception.Data.Contains('TaskFailure')) { return [string]$exception.Data['TaskFailure'] }
    }
    $cause = $exceptions | Select-Object -Last 1
    $native = @($exceptions | Where-Object { $_ -is [Runtime.InteropServices.COMException] })
    if ($native.Count) { $cause = $native[-1] }
    if ($null -eq $cause) { return ($Stage + ' failed') }
    $code = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$cause.HResult), 0).ToString('X8')
    $reason = ''
    switch ($code) {
        '80070005' { $reason = '; access denied' }
        '80070057' { $reason = '; invalid argument' }
        '80070534' { $reason = '; account not resolved' }
        '80041318' { $reason = '; invalid task definition' }
        '8004131F' { $reason = '; task already running' }
    }
    return ($Stage + ' failed (0x' + $code + $reason + ')')
}

function Test-ManagerTask($Service, $Config, [string]$Kind, [ref]$Failure = ([ref]$null)) {
    $healthy = $false
    $stage = 'Folder'
    if ($null -ne $Failure) { $Failure.Value = $null }
    try {
        $folder = Get-ManagerTaskFolder $Service $false
        if ($null -eq $folder) { return $false }
        $stage = 'Task read'
        $task = $folder.GetTask((Get-TaskName $Kind))
        $def = $task.Definition
        $stage = 'Principal'
        if (-not (Test-SystemTaskPrincipal ([string]$def.Principal.UserId))) { return $false }
        if ([int]$def.Principal.LogonType -ne 5 -or [int]$def.Principal.RunLevel -ne 1) { return $false }
        $stage = 'Enabled state'
        if ([bool]$task.Enabled -ne (Get-TaskEnabled $Config $Kind) -or
            [bool]$def.Settings.Enabled -ne (Get-TaskEnabled $Config $Kind)) { return $false }
        $stage = 'Run policy'
        if ([int]$def.Settings.MultipleInstances -ne 2 -or
            -not (Compare-Duration ([string]$def.Settings.ExecutionTimeLimit) 'PT5M')) { return $false }
        $stage = 'Shared settings'
        if ($def.Settings.DisallowStartIfOnBatteries -or $def.Settings.StopIfGoingOnBatteries -or
            $def.Settings.RunOnlyIfNetworkAvailable -or -not $def.Settings.StartWhenAvailable -or
            $def.Settings.Hidden -or -not $def.Settings.AllowDemandStart -or [int]$def.Settings.RestartCount -ne 0) { return $false }
        $stage = 'Action count'
        if ([int]$def.Actions.Count -ne 1) { return $false }
        $stage = 'Action'
        $action = $def.Actions.Item(1)
        $expected = Get-ExpectedAction $Kind
        if ([int]$action.Type -ne 0 -or ([string]$action.Path).Trim('"') -ine $expected.Path -or
            (Get-ArgumentSignature ([string]$action.Arguments)) -cne (Get-ArgumentSignature $expected.Arguments) -or [string]$action.WorkingDirectory) { return $false }
        $stage = 'Trigger count'
        if ([int]$def.Triggers.Count -ne 1) { return $false }
        $stage = 'Trigger enabled'
        $trigger = $def.Triggers.Item(1)
        if (-not $trigger.Enabled) { return $false }
        switch ($Kind) {
            'Startup' {
                $stage = 'Startup delay'
                $expectedDelay = [Xml.XmlConvert]::ToString([TimeSpan]::FromSeconds([int]$Config.Scheduling.Startup.DelaySeconds))
                if ([int]$trigger.Type -ne 8 -or -not (Compare-Duration ([string]$trigger.Delay) $expectedDelay)) { return $false }
                $stage = 'Startup boundaries'
                if (-not (Test-NoRepetition $trigger) -or [string]$trigger.StartBoundary -or [string]$trigger.EndBoundary) { return $false }
            }
            'Network' {
                $stage = 'Network subscription'
                if ([int]$trigger.Type -ne 0 -or (Normalize-Subscription ([string]$trigger.Subscription)) -cne
                    (Normalize-Subscription (Get-NetworkSubscription))) { return $false }
                $stage = 'Network boundaries'
                if ([string]$trigger.Delay -or -not (Test-NoRepetition $trigger) -or [string]$trigger.StartBoundary -or [string]$trigger.EndBoundary) { return $false }
            }
            'Periodic' {
                $stage = 'Periodic repetition'
                $expectedInterval = [Xml.XmlConvert]::ToString([TimeSpan]::FromMinutes([int]$Config.Scheduling.Periodic.IntervalMinutes))
                if ([int]$trigger.Type -ne 1 -or -not (Compare-Duration ([string]$trigger.Repetition.Interval) $expectedInterval)) { return $false }
                $stage = 'Periodic boundaries'
                if (-not [string]::IsNullOrEmpty([string]$trigger.Repetition.Duration) -or
                    $trigger.Repetition.StopAtDurationEnd -or [string]$trigger.EndBoundary -or
                    [string]$trigger.RandomDelay) { return $false }
                $stage = 'Periodic start'
                $boundary = [DateTime]::MinValue
                if (-not [DateTime]::TryParse([string]$trigger.StartBoundary, [ref]$boundary)) { return $false }
                if ($boundary -gt [DateTime]::Now.AddMinutes([int]$Config.Scheduling.Periodic.IntervalMinutes + 1)) { return $false }
            }
        }
        $healthy = $true
        return $true
    } catch {
        if ($null -ne $Failure) { $Failure.Value = Get-SafeTaskFailure $_ $stage }
        return $false
    } finally {
        if (-not $healthy -and $null -ne $Failure -and -not $Failure.Value) { $Failure.Value = $stage + ' mismatch' }
    }
}

function Set-ManagerTask($Service, $Config, [string]$Kind) {
    $stage = 'Folder'
    try {
        $folder = Get-ManagerTaskFolder $Service $true
        $stage = 'Definition'
        $definition = New-ManagerTaskDefinition $Service $Config $Kind
        $stage = 'Registration'
        [void]$folder.RegisterTaskDefinition((Get-TaskName $Kind), $definition, 6, 'S-1-5-18', $null, 5, $null)
        $stage = 'Verification'
        $failure = $null
        if (-not (Test-ManagerTask $Service $Config $Kind ([ref]$failure))) {
            $exception = New-Object InvalidOperationException 'Scheduled task verification failed.'
            $exception.Data['TaskFailure'] = 'Verification: ' + $failure
            throw $exception
        }
    } catch {
        if (-not $_.Exception.Data.Contains('TaskFailure')) {
            $_.Exception.Data['TaskFailure'] = Get-SafeTaskFailure $_ $stage
        }
        throw
    }
}

function Repair-ManagerTasks($Config, [string[]]$Kinds = $TaskNames) {
    $results = @()
    try { $service = Get-TaskService }
    catch {
        $failure = Get-SafeTaskFailure $_ 'Task Scheduler connection'
        foreach ($kind in $Kinds) { $results += [pscustomobject]@{ Kind = $kind; Result = '[FAIL] ' + $failure } }
        return $results
    }
    foreach ($kind in $Kinds) {
        if (Test-ManagerTask $service $Config $kind) {
            $result = '[OK] Healthy'
            if (-not (Get-TaskEnabled $Config $kind)) { $result = '[SKIP] Disabled by configuration' }
        } else {
            try { Set-ManagerTask $service $Config $kind; $result = '[OK] Repaired' }
            catch { $result = '[FAIL] ' + (Get-SafeTaskFailure $_ 'Task repair') }
        }
        $results += [pscustomobject]@{ Kind = $kind; Result = $result }
    }
    return $results
}

function Get-TaskHealthRows($Config) {
    $rows = @()
    try {
        $service = Get-TaskService
        foreach ($kind in $TaskNames) {
            $message = '[FAIL] Needs repair'
            $failure = $null
            if (Test-ManagerTask $service $Config $kind ([ref]$failure)) {
                $message = '[OK]'
                if (-not (Get-TaskEnabled $Config $kind)) { $message = '[OFF] Disabled' }
            } else { $message = '[FAIL] ' + $failure }
            $rows += New-Line ($kind + ' task') $message
        }
    } catch {
        $failure = Get-SafeTaskFailure $_ 'Task Scheduler connection'
        foreach ($kind in $TaskNames) { $rows += New-Line ($kind + ' task') ('[FAIL] ' + $failure) }
    }
    return $rows
}

function Show-ResultScreen([string]$Title, $Rows) {
    Show-Header $Title
    Write-Rows $Rows
    Wait-Back
}

function Set-ConfigValue([string]$Key, $Value, [string]$TaskKind = '') {
    $handle = Enter-RunLock
    if ($null -eq $handle) { return @((New-Line 'Setting' '[SKIP] Another instance is running')) }
    try {
        $config = Read-Config
        switch ($Key) {
            'Compare' { $config.CompareIpBeforeUpdate = [bool]$Value }
            'PostValidation' { $config.PostUpdateValidation = [bool]$Value }
            'DnsSystem' { $config.Dns.Mode = 'System'; $config.Dns.ManualServer = $null }
            'DnsManual' { $config.Dns.Mode = 'Manual'; $config.Dns.ManualServer = [string]$Value }
            'Attempts' { $config.Retry.Attempts = [int]$Value }
            'Delay' { $config.Retry.DelaySeconds = [int]$Value }
            'Forced' { $config.ForcedUpdate.Enabled = [bool]$Value }
            'ForceInterval' { $config.ForcedUpdate.IntervalHours = [int]$Value }
            'Logging' { $config.Logging.Enabled = [bool]$Value }
            'Startup' { $config.Scheduling.Startup.Enabled = [bool]$Value }
            'StartupDelay' { $config.Scheduling.Startup.DelaySeconds = [int]$Value }
            'Network' { $config.Scheduling.NetworkReconnect.Enabled = [bool]$Value }
            'Periodic' { $config.Scheduling.Periodic.Enabled = [bool]$Value }
            'PeriodicInterval' { $config.Scheduling.Periodic.IntervalMinutes = [int]$Value }
            default { throw 'Unknown setting.' }
        }
        Assert-Config $config
        Save-Config $config
        if ($TaskKind) {
            $taskResult = @(Repair-ManagerTasks $config @($TaskKind))[0]
            if ($taskResult.Result.StartsWith('[FAIL]')) {
                return @((New-Line 'Setting' '[OK] Saved'), (New-Line ($TaskKind + ' task') $taskResult.Result))
            }
            return @((New-Line 'Setting' '[OK] Saved'), (New-Line ($TaskKind + ' task') '[OK] Updated'))
        }
        return @((New-Line 'Setting' '[OK] Saved'))
    } catch {
        return @((New-Line 'Setting' '[FAIL] Could not save setting'))
    } finally { Exit-RunLock $handle }
}

function Change-Hostname {
    Show-Header 'CHANGE HOSTNAME'
    $config = Read-Config
    Write-Rows @((New-Line 'Current hostname' $config.Hostname), (New-Line 'Domain' (Get-DuckDnsDomain $config)))
    Write-Host ''
    Write-Host ' [0] Cancel'
    while ($true) {
        $entry = Read-Choice 'New hostname'
        if ($entry -eq '0' -or [string]::IsNullOrWhiteSpace($entry)) { return }
        try { $hostname = Normalize-Hostname $entry; break }
        catch { Write-Rows @((New-Line 'Hostname' '[WARN] Enter a valid DuckDNS hostname')) }
    }
    if ($hostname -ceq $config.Hostname) { Show-ResultScreen 'CHANGE HOSTNAME' @((New-Line 'Hostname' '[SKIP] Hostname is unchanged')); return }
    $handle = Enter-RunLock
    if ($null -eq $handle) { Show-ResultScreen 'CHANGE HOSTNAME' @((New-Line 'Hostname' '[SKIP] Another instance is running')); return }
    try {
        $config = Read-Config
        $prior = Read-State -Recover
        if (-not $prior.CanPersist) { throw 'State access failure.' }
        $state = New-EmptyState
        $state.LastStateRecoveryUtc = $prior.LastStateRecoveryUtc
        $state.LastStateRecoveryReason = $prior.LastStateRecoveryReason
        Save-State $state
        $config.Hostname = $hostname
        Save-Config $config
        $rows = @((New-Line 'Hostname' ('[OK] ' + $hostname)), (New-Line 'Domain' (Get-DuckDnsDomain $config)),
            (New-Line 'Credentials' (Get-CredentialsStatus $config $state)),
            (New-Line 'Status' '[INFO] Check the new hostname with Update Now'))
    } catch { $rows = @((New-Line 'Hostname' '[FAIL] Could not change hostname')) }
    finally { Exit-RunLock $handle }
    Show-ResultScreen 'CHANGE HOSTNAME' $rows
}

function Change-Token {
    Show-Header 'CHANGE TOKEN'
    Write-Rows @((New-Line 'Credentials' (Get-CredentialsStatus (Read-Config) (Read-State))))
    Write-Host ''
    if ((Read-Choice 'Press Enter to enter a token, or 0 to cancel') -eq '0') { return }
    while ($true) {
        $secure = Read-Host ' New token (hidden; blank cancels)' -AsSecureString
        if ($null -eq $secure -or $secure.Length -eq 0) { return }
        try { $cipher = ConvertTo-TokenBytes $secure; break }
        catch { Write-Rows @((New-Line 'Credentials' '[WARN] Enter a valid token')) }
        finally { if ($secure) { $secure.Dispose() } }
    }
    $handle = $null; $saved = $false
    try {
        $handle = Enter-RunLock
        if ($null -eq $handle) {
            $rows = @((New-Line 'Setting' '[SKIP] Another instance is running'))
        } else {
            $config = Read-Config; $state = Read-State -Recover
            if (-not $state.CanPersist) { throw 'State access failure.' }
            Reset-CredentialVerification $state
            $state.LastSuccessfulUpdateUtc = $null; $state.LastSuccessfulCheckUtc = $null
            $state.SynchronizationState = 'Unknown'
            Save-State $state
            Write-AtomicBytes $TokenPath $cipher
            $saved = $true
            # Local persistence, check, real verification and final state all share this lock.
            Start-Deadline
            $result = Complete-Check $config $state 'Manual' $true
            $rows = @((New-Line 'Setting' '[OK] Token saved'),
                (New-Line 'Credentials' (Get-CredentialsStatus $config $state))) +
                @($result.Lines | Where-Object { $_.Label -ne 'Credentials' })
        }
    } catch {
        if ($saved) { $rows = @((New-Line 'Setting' '[OK] Token saved'),
            (New-Line 'Credentials' '[WARN] Protected; verification pending')) }
        else { $rows = @((New-Line 'Setting' '[FAIL] Could not save token')) }
    } finally {
        [Array]::Clear($cipher, 0, $cipher.Length)
        if ($null -ne $handle) { Exit-RunLock $handle }
    }
    Show-ResultScreen 'CHANGE TOKEN' $rows
}

function Get-InterfaceDisplayRows($Config) {
    $rows = @((New-Line 'Mode' $Config.NetworkInterface.Mode))
    if ($Config.NetworkInterface.Mode -eq 'Specific') {
        $context = Get-PublicIpContext $Config
        if ($context.Available) { $rows += New-Line 'Interface' $context.InterfaceAlias; $rows += New-Line 'Local IPv4' $context.IPv4 }
        else { $rows += New-Line 'Interface' '[FAIL] Selected interface unavailable' }
    }
    return $rows
}

function Save-NetworkInterface($Value, $TestedContext = $null) {
    $handle = Enter-RunLock
    if ($null -eq $handle) { return @((New-Line 'Setting' '[SKIP] Another instance is running')) }
    try {
        $config = Read-Config
        if ($Value.Mode -eq 'Specific' -and ($null -eq $TestedContext -or
            $TestedContext.Mode -ne 'Specific' -or ([guid]$TestedContext.InterfaceGuid) -ne ([guid]$Value.InterfaceGuid) -or
            -not (Test-PublicIpContext $TestedContext))) {
            return @((New-Line 'Setting' '[FAIL] Interface changed; select and test it again'))
        }
        $config.NetworkInterface = $Value
        Save-Config $config
        return @((New-Line 'Setting' '[OK] Network interface saved'))
    } catch { return @((New-Line 'Setting' '[FAIL] Could not save interface')) }
    finally { Exit-RunLock $handle }
}

function Select-NetworkInterface {
    while ($true) {
        Show-Header 'SELECT INTERFACE'
        $interfaces = @(Get-UsableInterfaces)
        if (-not $interfaces.Count) { Write-Rows @((New-Line 'Interfaces' '[WARN] No active IPv4 interfaces')) }
        for ($i = 0; $i -lt $interfaces.Count; $i++) {
            $name = $interfaces[$i].InterfaceAlias
            if ($interfaces[$i].IsVirtual) { $name += ' [Virtual]' }
            Write-Host (' [' + ($i + 1) + '] ' + $name)
            Write-Host ('     IPv4: ' + $interfaces[$i].IPv4)
            Write-Host ''
        }
        Write-Host ' [0] Back'
        $choice = Read-Choice
        if ($choice -eq '0') { return }
        $number = 0
        if (-not [int]::TryParse($choice, [ref]$number) -or $number -lt 1 -or $number -gt $interfaces.Count) {
            Write-Rows @((New-Line 'Input' '[WARN] Choose a listed interface')); continue
        }
        $selected = $interfaces[$number - 1]
        $config = Read-Config
        $config.NetworkInterface = [pscustomobject]@{ Mode = 'Specific'; InterfaceGuid = $selected.InterfaceGuid }
        Show-Header 'TEST INTERFACE'
        Write-Rows @((New-Line 'Interface' $selected.InterfaceAlias))
        Start-Deadline
        try {
            $found = Find-PublicIPv4 $config
            if ($found.IP) { $found = Confirm-PublicIPv4 $config $found }
        } catch { $found = $null }
        finally { $script:RunClock = $null }
        if ($null -eq $found -or -not $found.IP) {
            Write-Rows @((New-Line 'Local IPv4' $selected.IPv4), (New-Line 'Connectivity' '[FAIL] Public IP query failed'))
            Wait-Back; continue
        }
        Write-Rows @((New-Line 'Local IPv4' $found.Context.IPv4), (New-Line 'Connectivity' '[OK]'),
            (New-Line 'Public IPv4' ('[OK] ' + $found.IP)))
        if (-not (Read-Confirmation 'Use this interface?')) { continue }
        Show-ResultScreen 'NETWORK INTERFACE' (Save-NetworkInterface $config.NetworkInterface $found.Context)
        return
    }
}

function Show-NetworkInterface {
    while ($true) {
        $config = Read-Config
        Show-Header 'NETWORK INTERFACE'
        Write-Rows @(Get-InterfaceDisplayRows $config)
        Write-Host ''
        Write-Host ' [1] Automatic'
        if ($config.NetworkInterface.Mode -eq 'Specific') { Write-Host ' [2] Change Interface' }
        else { Write-Host ' [2] Select Interface' }
        Write-Host ''
        Write-Host ' [0] Back'
        switch (Read-Choice) {
            '0' { return }
            '1' { Show-ResultScreen 'NETWORK INTERFACE' (Save-NetworkInterface ([pscustomobject]@{ Mode = 'Automatic'; InterfaceGuid = $null })) }
            '2' { Select-NetworkInterface }
            default { Write-Rows @((New-Line 'Input' '[WARN] Choose an option from 0 to 2')) }
        }
    }
}

function Show-RetrySettings {
    while ($true) {
        $config = Read-Config
        Show-Header 'RETRY SETTINGS'
        Write-Rows @((New-Line 'Retry attempts' ([string]$config.Retry.Attempts)),
            (New-Line 'Retry delay' ([string]$config.Retry.DelaySeconds + ' s')))
        Write-Host ''
        Write-Host ' [1] Change Attempts'
        Write-Host ' [2] Change Delay'
        Write-Host ''
        Write-Host ' [0] Back'
        $choice = Read-Choice
        if ($choice -eq '0') { return }
        if ($choice -in @('1', '2')) {
            if ($choice -eq '1') { $value = Read-Number 'Retry attempts' 1 12; $key = 'Attempts' }
            else { $value = Read-Number 'Retry delay in seconds' 1 60; $key = 'Delay' }
            if ($null -ne $value) { Show-ResultScreen 'RETRY SETTINGS' (Set-ConfigValue $key $value) }
        } else { Write-Rows @((New-Line 'Input' '[WARN] Choose an option from 0 to 2')); Start-Sleep -Seconds 1 }
    }
}

function Show-ForcedSettings {
    while ($true) {
        $config = Read-Config
        $state = Read-State
        if ($state.Domain -and $state.Domain -cne (Get-DuckDnsDomain $config)) { $state = New-EmptyState }
        Show-Header 'FORCED UPDATE'
        $enabled = '[OFF]'; if ($config.ForcedUpdate.Enabled) { $enabled = '[ON]' }
        Write-Rows @((New-Line 'Forced update' $enabled),
            (New-Line 'Force interval' ([string]$config.ForcedUpdate.IntervalHours + ' h')),
            (New-Line 'Last successful API call' (Format-StateTime $state 'LastSuccessfulUpdateUtc' $false)))
        Write-Host ''
        Write-Host ' [1] Toggle Forced Update'
        Write-Host ' [2] Change Interval'
        Write-Host ''
        Write-Host ' [0] Back'
        $choice = Read-Choice
        switch ($choice) {
            '0' { return }
            '1' { Show-ResultScreen 'FORCED UPDATE' (Set-ConfigValue 'Forced' (-not $config.ForcedUpdate.Enabled)) }
            '2' {
                $value = Read-Number 'Force interval in hours' 1 168
                if ($null -ne $value) { Show-ResultScreen 'FORCED UPDATE' (Set-ConfigValue 'ForceInterval' $value) }
            }
            default { Write-Rows @((New-Line 'Input' '[WARN] Choose an option from 0 to 2')); Start-Sleep -Seconds 1 }
        }
    }
}


function Show-DnsSettings {
    while ($true) {
        $config = Read-Config
        Show-Header 'DNS SETTINGS'
        Write-Rows @((New-Line 'DNS mode' $config.Dns.Mode))
        if ($config.Dns.Mode -eq 'Manual') {
            Write-Rows @((New-Line 'Manual DNS' $config.Dns.ManualServer),
                (New-Line 'Fallback 1' $ManualFallbacks[0]), (New-Line 'Fallback 2' $ManualFallbacks[1]))
        }
        Write-Host ''
        Write-Host ' [1] Use Windows DNS'
        if ($config.Dns.Mode -eq 'Manual') { Write-Host ' [2] Change Manual DNS' }
        else { Write-Host ' [2] Use Manual DNS' }
        Write-Host ''
        Write-Host ' [0] Back'
        $choice = Read-Choice
        if ($choice -eq '0') { return }
        if ($choice -eq '1') { Show-ResultScreen 'DNS SETTINGS' (Set-ConfigValue 'DnsSystem' $null) }
        elseif ($choice -eq '2') {
            while ($true) {
                $dns = Read-Choice 'Manual DNS IPv4 (0 cancels)'
                if ($dns -eq '0') { break }
                if (Test-IPv4 $dns) { Show-ResultScreen 'DNS SETTINGS' (Set-ConfigValue 'DnsManual' $dns); break }
                Write-Rows @((New-Line 'Manual DNS' '[WARN] Enter a valid IPv4 address'))
            }
        } else { Write-Rows @((New-Line 'Input' '[WARN] Choose an option from 0 to 2')) }
    }
}

function Show-Configuration {
    while ($true) {
        $config = Read-Config
        Show-Header 'CONFIGURATION'
        $credentials = Get-CredentialsStatus $config (Read-State)
        $compare = '[OFF]'; if ($config.CompareIpBeforeUpdate) { $compare = '[ON]' }
        $validation = '[OFF]'; if ($config.PostUpdateValidation) { $validation = '[ON]' }
        $forced = '[OFF]'; if ($config.ForcedUpdate.Enabled) { $forced = '[ON]' }
        $logging = '[OFF]'; if ($config.Logging.Enabled) { $logging = '[ON]' }
        Write-Rows @((New-Line 'Hostname' $config.Hostname), (New-Line 'Domain' (Get-DuckDnsDomain $config)),
            (New-Line 'Credentials' $credentials))
        Write-Host ''
        $interface = 'Automatic'
        if ($config.NetworkInterface.Mode -eq 'Specific') {
            $context = Get-PublicIpContext $config
            $interface = '[FAIL] Selected interface unavailable'
            if ($context.Available) { $interface = $context.InterfaceAlias }
        }
        Write-Rows @((New-Line 'Network interface' $interface))
        Write-Host ''
        Write-Rows @((New-Line 'Compare IP' $compare), (New-Line 'Post-update validation' $validation),
            (New-Line 'DNS mode' $config.Dns.Mode))
        if ($config.Dns.Mode -eq 'Manual') { Write-Rows @((New-Line 'Manual DNS' $config.Dns.ManualServer)) }
        Write-Host ''
        Write-Rows @((New-Line 'Retry attempts' ([string]$config.Retry.Attempts)),
            (New-Line 'Retry delay' ([string]$config.Retry.DelaySeconds + ' s')))
        Write-Host ''
        Write-Rows @((New-Line 'Forced update' $forced),
            (New-Line 'Force interval' ([string]$config.ForcedUpdate.IntervalHours + ' h')))
        Write-Host ''
        Write-Rows @((New-Line 'Logging' $logging))
        Show-Section 'MENU'
        Write-Host ' [1] Change Hostname'
        Write-Host ' [2] Change Token'
        Write-Host ' [3] Network Interface'
        Write-Host ' [4] DNS Settings'
        Write-Host ' [5] Compare IP Before Update'
        Write-Host ' [6] Post-Update Validation'
        Write-Host ' [7] Retry Settings'
        Write-Host ' [8] Forced Update'
        Write-Host ' [9] Logging'
        Write-Host ''
        Write-Host ' [0] Back'
        $choice = Read-Choice
        switch ($choice) {
            '0' { return }
            '1' { Change-Hostname }
            '2' { Change-Token }
            '3' { Show-NetworkInterface }
            '4' { Show-DnsSettings }
            '5' { Show-ResultScreen 'CONFIGURATION' (Set-ConfigValue 'Compare' (-not $config.CompareIpBeforeUpdate)) }
            '6' { Show-ResultScreen 'CONFIGURATION' (Set-ConfigValue 'PostValidation' (-not $config.PostUpdateValidation)) }
            '7' { Show-RetrySettings }
            '8' { Show-ForcedSettings }
            '9' { Show-ResultScreen 'CONFIGURATION' (Set-ConfigValue 'Logging' (-not $config.Logging.Enabled)) }
            default { Write-Rows @((New-Line 'Input' '[WARN] Choose an option from 0 to 9')); Start-Sleep -Seconds 1 }
        }
    }
}

function Show-Scheduling {
    while ($true) {
        $config = Read-Config
        Show-Header 'SCHEDULING'
        $startup = '[OFF]'; if ($config.Scheduling.Startup.Enabled) { $startup = '[ON]' }
        $network = '[OFF]'; if ($config.Scheduling.NetworkReconnect.Enabled) { $network = '[ON]' }
        $periodic = '[OFF]'; if ($config.Scheduling.Periodic.Enabled) { $periodic = '[ON]' }
        Write-Rows @((New-Line 'Startup' $startup),
            (New-Line 'Startup delay' ([string]$config.Scheduling.Startup.DelaySeconds + ' s')))
        Write-Host ''
        Write-Rows @((New-Line 'Network reconnect' $network))
        Write-Host ''
        Write-Rows @((New-Line 'Periodic check' $periodic),
            (New-Line 'Periodic interval' ([string]$config.Scheduling.Periodic.IntervalMinutes + ' min')))
        Show-Section 'MENU'
        Write-Host ' [1] Startup'
        Write-Host ' [2] Startup Delay'
        Write-Host ' [3] Network Reconnect'
        Write-Host ' [4] Periodic Check'
        Write-Host ' [5] Periodic Interval'
        Write-Host ''
        Write-Host ' [0] Back'
        $choice = Read-Choice
        switch ($choice) {
            '0' { return }
            '1' { Show-ResultScreen 'SCHEDULING' (Set-ConfigValue 'Startup' (-not $config.Scheduling.Startup.Enabled) 'Startup') }
            '2' {
                $value = Read-Number 'Startup delay in seconds' 1 300
                if ($null -ne $value) { Show-ResultScreen 'SCHEDULING' (Set-ConfigValue 'StartupDelay' $value 'Startup') }
            }
            '3' { Show-ResultScreen 'SCHEDULING' (Set-ConfigValue 'Network' (-not $config.Scheduling.NetworkReconnect.Enabled) 'Network') }
            '4' { Show-ResultScreen 'SCHEDULING' (Set-ConfigValue 'Periodic' (-not $config.Scheduling.Periodic.Enabled) 'Periodic') }
            '5' {
                $value = Read-Number 'Periodic interval in minutes' 5 1440
                if ($null -ne $value) { Show-ResultScreen 'SCHEDULING' (Set-ConfigValue 'PeriodicInterval' $value 'Periodic') }
            }
            default { Write-Rows @((New-Line 'Input' '[WARN] Choose an option from 0 to 5')); Start-Sleep -Seconds 1 }
        }
    }
}

function Show-Status {
    $config = Read-Config
    $state = Read-State
    if ($state.Domain -and $state.Domain -cne (Get-DuckDnsDomain $config)) { $state = New-EmptyState }
    Show-Header 'STATUS'
    $public = 'Unknown'; if ($state.LastDetectedPublicIPv4) { $public = [string]$state.LastDetectedPublicIPv4 }
    $dns = 'Unknown'; if ($state.DuckDnsIPv4) { $dns = [string]$state.DuckDnsIPv4 }
    Write-Rows @((New-Line 'Domain' (Get-DuckDnsDomain $config)), (New-Line 'Public IP' $public),
        (New-Line 'DuckDNS IP' $dns), (New-Line 'Status' (Get-StatusText $state)))
    Write-Host ''
    $reasonText = 'Unknown'; if ($state.LastReason) { $reasonText = [string]$state.LastReason }
    $resultText = 'Unknown'; if ($state.LastResult) { $resultText = [string]$state.LastResult }
    Write-Rows @((New-Line 'Last check' (Format-StateTime $state 'LastCheckUtc')),
        (New-Line 'Last successful check' (Format-StateTime $state 'LastSuccessfulCheckUtc')),
        (New-Line 'Last update' (Format-StateTime $state 'LastSuccessfulUpdateUtc')),
        (New-Line 'Trigger' $reasonText), (New-Line 'Result' $resultText))
    if ($state.ConsecutiveFailures -gt 0) { Write-Rows @((New-Line 'Consecutive failures' ([string]$state.ConsecutiveFailures))) }
    Show-Section 'SCHEDULED TASKS'
    Write-Rows (Get-TaskHealthRows $config)
    Wait-Back
}

function Test-TrustedRuntimeAcl($Acl, [ref]$Failure = ([ref]$null)) {
    $Failure.Value = $null
    if (-not $Acl.AreAccessRulesProtected) { $Failure.Value = 'Inheritance enabled'; return $false }
    $seen = @()
    foreach ($rule in @($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
            if ($sid -in @('S-1-5-18','S-1-5-32-544')) { $Failure.Value = 'Trusted account denied'; return $false }
            continue
        }
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($sid -notin @('S-1-5-18','S-1-5-32-544')) { $Failure.Value = 'Unexpected allow rule'; return $false }
        if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
            [Security.AccessControl.FileSystemRights]::FullControl -or
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) {
            $Failure.Value = 'Incomplete trusted permissions'; return $false
        }
        $seen += $sid
    }
    if ('S-1-5-18' -notin $seen -or 'S-1-5-32-544' -notin $seen) {
        $Failure.Value = 'Missing SYSTEM/Administrators access'; return $false
    }
    return $true
}

function Test-RuntimeAcl([ref]$Failure = ([ref]$null)) {
    $Failure.Value = $null
    $stage = 'Runtime directory ACL read'
    try {
        $paths = @($Root, $TokenPath)
        if ([IO.File]::Exists($CredentialReceiptPath)) { $paths += $CredentialReceiptPath }
        foreach ($path in $paths) {
            $label = 'Runtime directory'
            if ($path -eq $TokenPath) { $label = 'Protected token' }
            elseif ($path -eq $CredentialReceiptPath) { $label = 'Verification receipt' }
            $stage = $label + ' ACL read'
            $acl = Get-Acl -LiteralPath $path
            $detail = $null
            if (-not (Test-TrustedRuntimeAcl $acl ([ref]$detail))) {
                $Failure.Value = $label + ': ' + $detail
                return $false
            }
        }
        return $true
    } catch { $Failure.Value = Get-SafeTaskFailure $_ $stage; return $false }
}

function New-SectionRow([string]$Name) { return [pscustomobject]@{ Label = ''; Value = ''; Section = $Name } }

function Get-FullDiagnosticRows($Config) {
    $rows = @((New-SectionRow 'CONFIGURATION'))
    $overall = '[OK]'
    try { Assert-Config $Config; $rows += New-Line 'Configuration' '[OK]' }
    catch { $rows += New-Line 'Configuration' '[FAIL] Invalid'; $overall = '[FAIL]' }
    $credentialStatus = Get-CredentialsStatus $Config (Read-State)
    $rows += New-Line 'Credentials' $credentialStatus
    if ($credentialStatus.StartsWith('[FAIL]')) { $overall = '[FAIL]' }
    elseif ($credentialStatus.StartsWith('[WARN]')) { $overall = '[WARN]' }
    $aclFailure = $null
    if (Test-RuntimeAcl ([ref]$aclFailure)) { $rows += New-Line 'Runtime ACL' '[OK]' }
    else { $rows += New-Line 'Runtime ACL' ('[FAIL] ' + $aclFailure); $overall = '[FAIL]' }
    $state = Read-State
    $stateText = '[OK]'
    if ($state.ReadKind -eq 'Missing') { $stateText = '[INFO] No saved state' }
    elseif ($state.ReadKind -in @('ReadError','InvalidJson')) { $stateText = '[FAIL] ' + $state.ReadKind; $overall = '[FAIL]' }
    elseif ($state.LastStateRecoveryUtc -and
        ([DateTime]::UtcNow - [DateTime]::Parse($state.LastStateRecoveryUtc).ToUniversalTime()).TotalHours -lt 24) {
        $stateText = '[WARN] Recovered from corruption'
        if ($overall -eq '[OK]') { $overall = '[WARN]' }
    }
    $rows += New-Line 'Saved state' $stateText
    $rows += New-Line 'Manager version' $ScriptVersion
    $rows += New-Line 'Config schema' ([string]$Config.SchemaVersion)
    $rows += New-SectionRow 'NETWORK'
    $rows += New-Line 'Interface mode' $Config.NetworkInterface.Mode
    Assert-Deadline 16
    try {
        $request = Invoke-WebRequest -Uri 'https://www.duckdns.org/' -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
        $rows += New-Line 'HTTPS' '[OK] DuckDNS reachable'
    } catch { $rows += New-Line 'HTTPS' '[FAIL] DuckDNS unavailable'; $overall = '[FAIL]' }
    $found = Find-PublicIPv4 $Config
    if ($Config.NetworkInterface.Mode -eq 'Specific') {
        if ($found.Context -and $found.Context.Available -and -not $found.InterfaceUnavailable) {
            $rows += New-Line 'Interface' ('[OK] ' + $found.Context.InterfaceAlias)
            $rows += New-Line 'Local IPv4' ('[OK] ' + $found.Context.IPv4)
        } else { $rows += New-Line 'Interface' '[FAIL] Selected interface unavailable' }
    }
    if ($found.IP) { $rows += New-Line 'Public IPv4' ('[OK] ' + $found.IP) }
    else {
        $message = '[FAIL] All providers failed'
        if ($found.InterfaceUnavailable) { $message = '[FAIL] Could not query selected interface' }
        $rows += New-Line 'Public IPv4' $message; $overall = '[FAIL]'
    }
    if ($Config.NetworkInterface.Mode -eq 'Automatic') { $rows += New-Line 'Public IP binding' '[INFO] Windows routing' }
    elseif ($found.IP -and $found.Context -and $found.Context.Mode -eq 'Specific') {
        $rows += New-Line 'Public IP binding' '[OK] Interface enforced'
    } else { $rows += New-Line 'Public IP binding' '[FAIL] Not verified' }
    $resolved = Resolve-HostA $Config $false
    if ($resolved.Success) {
        $display = 'No A record'; if ($resolved.Addresses.Count) { $display = $resolved.Addresses -join ', ' }
        $rows += New-Line 'DuckDNS DNS' ('[OK] ' + $display)
        if ($resolved.IsFallback -and $overall -eq '[OK]') { $overall = '[WARN]' }
    } else { $rows += New-Line 'DuckDNS DNS' '[FAIL] Resolution failed'; $overall = '[FAIL]' }
    $rows += Get-ResolverRow $resolved
    $rows += New-SectionRow 'AUTOMATION'
    $taskRows = @(Get-TaskHealthRows $Config)
    $rows += $taskRows
    if (@($taskRows | Where-Object { $_.Value.StartsWith('[FAIL]') }).Count) { $overall = '[FAIL]' }
    $rows += New-Line 'Overall status' $overall
    return $rows
}

function Show-DiagnosticTest([int]$Choice) {
    $config = Read-Config
    $rows = @()
    Start-Deadline
    try {
    switch ($Choice) {
        1 {
            try {
                $response = Invoke-WebRequest -Uri 'https://www.duckdns.org/' -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
                $rows += New-Line 'Internet' '[OK] DuckDNS HTTPS reachable'
            } catch { $rows += New-Line 'Internet' '[FAIL] DuckDNS HTTPS unavailable' }
        }
        2 {
            $found = Find-PublicIPv4 $config
            if ($found.IP) { $rows += New-Line 'Public IPv4' ('[OK] ' + $found.IP) }
            elseif ($found.InterfaceUnavailable) { $rows += @(Get-InterfaceFailureRows) }
            else { $rows += New-Line 'Public IPv4' '[FAIL] All providers failed' }
        }
        3 {
            $found = Find-PublicIPv4 $config $true
            if ($found.InterfaceUnavailable) { $rows += @(Get-InterfaceFailureRows) }
            foreach ($provider in $found.Results) {
                $message = '[FAIL] Unavailable'; if ($provider.IP) { $message = '[OK] ' + $provider.IP }
                $rows += New-Line $provider.Provider $message
            }
        }
        4 {
            $answer = Resolve-HostA $config
            if ($answer.Success) {
                $display = 'No A record'; if ($answer.Addresses.Count) { $display = $answer.Addresses -join ', ' }
                $rows += New-Line 'DuckDNS DNS' ('[OK] ' + $display)
            } else { $rows += New-Line 'DuckDNS DNS' '[FAIL] Resolution failed' }
            $rows += Get-ResolverRow $answer
        }
        5 {
            $answer = Resolve-HostA $config $false $true
            foreach ($item in $answer.Results) {
                $label = 'Windows DNS'
                if ($item.Server -ne 'Windows') {
                    $label = 'Manual DNS'
                    if ($item.Server -eq '1.1.1.1' -and $item.Server -ne $config.Dns.ManualServer) { $label = 'Cloudflare DNS' }
                    if ($item.Server -eq '8.8.8.8' -and $item.Server -ne $config.Dns.ManualServer) { $label = 'Google DNS' }
                }
                $value = '[FAIL]'; if ($item.Success) { $value = '[OK]' }
                if ($item.Server -ne 'Windows') { $value += ' ' + $item.Server }
                if ($item.Success -and -not $item.Addresses.Count) { $value += ' No A record' }
                $rows += New-Line $label $value
            }
        }
        6 { $rows = @(Get-TaskHealthRows $config) }
        7 { $rows = @(Get-FullDiagnosticRows $config) }
    }
    } catch [TimeoutException] { $rows = @((New-Line 'Result' '[FAIL] Execution timeout')) }
    finally { $script:RunClock = $null }
    $title = 'DIAGNOSTICS'; if ($Choice -eq 7) { $title = 'FULL DIAGNOSTICS' }
    Show-ResultScreen $title $rows
}

function Show-Diagnostics {
    while ($true) {
        Show-Header 'DIAGNOSTICS'
        Write-Host ' [1] Test Internet Connection'
        Write-Host ' [2] Detect Public IP'
        Write-Host ' [3] Test IP Providers'
        Write-Host ' [4] Resolve DuckDNS'
        Write-Host ' [5] Test DNS Resolver'
        Write-Host ' [6] Validate Scheduled Tasks'
        Write-Host ' [7] Run Full Diagnostics'
        Write-Host ''
        Write-Host ' [0] Back'
        $choice = Read-Choice
        if ($choice -eq '0') { return }
        if ($choice -match '^[1-7]$') { Show-DiagnosticTest ([int]$choice) }
        else { Write-Rows @((New-Line 'Input' '[WARN] Choose an option from 0 to 7')); Start-Sleep -Seconds 1 }
    }
}

function Remove-ManagerTasks {
    $service = Get-TaskService
    $folder = Get-ManagerTaskFolder $service $false
    if ($null -eq $folder) { return }
    foreach ($kind in $TaskNames) {
        $exists = $false
        try { $null = $folder.GetTask((Get-TaskName $kind)); $exists = $true } catch { }
        if ($exists) { $folder.DeleteTask((Get-TaskName $kind), 0) }
    }
    # The folder may contain unrelated tasks; leave it in that case.
    try { $service.GetFolder('\').DeleteFolder('DuckDNS Manager', 0) } catch { }
}

function Clear-ManagerLogs {
    $count = 0
    if (Test-Path -LiteralPath $LogDirectory -PathType Container) {
        foreach ($name in @('DuckDNS-Manager.log', 'DuckDNS-Manager.1.log')) {
            $path = Join-Path $LogDirectory $name
            if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force; $count++ }
        }
    }
    return $count
}

function Show-Maintenance {
    while ($true) {
        Show-Header 'MAINTENANCE'
        Write-Host ' [1] Repair Scheduled Tasks'
        Write-Host ' [2] Restore Defaults'
        Write-Host ' [3] Open Configuration Directory'
        Write-Host ' [4] Open Windows Task Scheduler'
        Write-Host ' [5] Clear Saved State'
        Write-Host ' [6] Clear Logs'
        Write-Host ' [7] Uninstall'
        Write-Host ''
        Write-Host ' [0] Back'
        $choice = Read-Choice
        switch ($choice) {
            '0' { return $false }
            '1' {
                $handle = Enter-RunLock
                if ($null -eq $handle) { $rows = @((New-Line 'Tasks' '[SKIP] Another instance is running')) }
                else {
                    try {
                        $rows = @()
                        $result = @(Repair-ManagerTasks (Read-Config))
                        foreach ($item in $result) { $rows += New-Line ($item.Kind + ' task') $item.Result }
                        $overall = '[OK] Tasks checked'
                        if (@($result | Where-Object { $_.Result.StartsWith('[FAIL]') }).Count) { $overall = '[FAIL] Some tasks need repair' }
                        $rows += New-Line 'Result' $overall
                    } finally { Exit-RunLock $handle }
                }
                Show-ResultScreen 'REPAIR SCHEDULED TASKS' $rows
            }
            '2' {
                Show-Header 'RESTORE DEFAULTS'
                Write-Host ' Operational settings and scheduling will return to defaults.'
                Write-Host ' Hostname and token will be preserved.'
                Write-Host ''
                if (-not (Read-Confirmation 'Restore defaults?')) { Show-ResultScreen 'RESTORE DEFAULTS' @((New-Line 'Settings' '[SKIP] No changes made')); break }
                $handle = Enter-RunLock
                if ($null -eq $handle) { $rows = @((New-Line 'Settings' '[SKIP] Another instance is running')) }
                else {
                    try {
                        $old = Read-Config
                        $defaults = New-DefaultConfig
                        $defaults.Hostname = $old.Hostname
                        Save-Config $defaults
                        $rows = @((New-Line 'Settings' '[OK] Restored'))
                        $result = @(Repair-ManagerTasks $defaults)
                        if (@($result | Where-Object { $_.Result.StartsWith('[FAIL]') }).Count) {
                            $rows += New-Line 'Scheduled tasks' '[WARN] Settings saved; tasks need repair'
                        } else { $rows += New-Line 'Scheduled tasks' '[OK] Reconciled' }
                    } catch { $rows = @((New-Line 'Settings' '[FAIL] Could not restore defaults')) }
                    finally { Exit-RunLock $handle }
                }
                Show-ResultScreen 'RESTORE DEFAULTS' $rows
            }
            '3' {
                try { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $Root + '"'); $rows = @((New-Line 'Directory' '[OK] Opened')) }
                catch { $rows = @((New-Line 'Directory' '[FAIL] Could not open directory')) }
                Show-ResultScreen 'MAINTENANCE' $rows
            }
            '4' {
                try { Start-Process -FilePath 'taskschd.msc'; $rows = @((New-Line 'Task Scheduler' '[OK] Opened')) }
                catch { $rows = @((New-Line 'Task Scheduler' '[FAIL] Could not open Task Scheduler')) }
                Show-ResultScreen 'MAINTENANCE' $rows
            }
            '5' {
                Show-Header 'CLEAR SAVED STATE'
                Write-Host ' Last check, result, and saved IP state will be cleared.'
                Write-Host ' Hostname, token, settings, and tasks will be preserved.'
                Write-Host ''
                if (-not (Read-Confirmation 'Clear saved state?')) { Show-ResultScreen 'CLEAR SAVED STATE' @((New-Line 'Saved state' '[SKIP] No changes made')); break }
                $handle = Enter-RunLock
                if ($null -eq $handle) { $rows = @((New-Line 'Saved state' '[SKIP] Another instance is running')) }
                else {
                    try { Remove-CorruptStateFiles; Save-State (New-EmptyState); $rows = @((New-Line 'Saved state' '[OK] Cleared')) }
                    catch { $rows = @((New-Line 'Saved state' '[FAIL] Could not clear state')) }
                    finally { Exit-RunLock $handle }
                }
                Show-ResultScreen 'CLEAR SAVED STATE' $rows
            }
            '6' {
                Show-Header 'CLEAR LOGS'
                Write-Host ' Application log files will be deleted.'
                Write-Host ''
                if (-not (Read-Confirmation 'Clear logs?')) { Show-ResultScreen 'CLEAR LOGS' @((New-Line 'Logs' '[SKIP] No changes made')); break }
                $handle = Enter-RunLock
                if ($null -eq $handle) { $rows = @((New-Line 'Logs' '[SKIP] Another instance is running')) }
                else {
                    try {
                        $count = Clear-ManagerLogs
                        $message = '[OK] Cleared'; if ($count -eq 0) { $message = '[SKIP] No logs to clear' }
                        $rows = @((New-Line 'Logs' $message))
                    } catch { $rows = @((New-Line 'Logs' '[FAIL] Could not clear logs')) }
                    finally { Exit-RunLock $handle }
                }
                Show-ResultScreen 'CLEAR LOGS' $rows
            }
            '7' {
                Show-Header 'UNINSTALL'
                Write-Host ' Scheduled tasks, configuration, token, state, and logs'
                Write-Host ' will be removed.'
                Write-Host ''
                if ((Read-Choice 'Type UNINSTALL to confirm') -cne 'UNINSTALL') {
                    Show-ResultScreen 'UNINSTALL' @((New-Line 'Uninstall' '[SKIP] No changes made'))
                    break
                }
                $handle = Enter-RunLock
                if ($null -eq $handle) { Show-ResultScreen 'UNINSTALL' @((New-Line 'Uninstall' '[SKIP] Another instance is running')); break }
                try {
                    Remove-ManagerTasks
                    Remove-CorruptStateFiles
                    [void](Clear-ManagerLogs)
                    foreach ($path in @($ConfigPath, $PreviousConfigPath, $TokenPath, $CredentialReceiptPath, $StatusPath, $InstalledScript)) {
                        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
                    }
                    $rows = @((New-Line 'Uninstall' '[OK] DuckDNS Manager removed'))
                } catch { $rows = @((New-Line 'Uninstall' '[FAIL] Some resources could not be removed')) }
                finally { Exit-RunLock $handle }
                try { Remove-Item -LiteralPath $LockPath -Force -ErrorAction Stop } catch { }
                try { Remove-Item -LiteralPath $LogDirectory -ErrorAction Stop } catch { }
                Set-Location -LiteralPath $env:TEMP
                try { Remove-Item -LiteralPath $Root -ErrorAction Stop }
                catch { $rows += New-Line 'Directory' '[WARN] Directory not empty' }
                Show-ResultScreen 'UNINSTALL' $rows
                return $true
            }
            default { Write-Rows @((New-Line 'Input' '[WARN] Choose an option from 0 to 7')); Start-Sleep -Seconds 1 }
        }
    }
}

function Copy-ManagerScript {
    $source = $MyInvocation.PSCommandPath
    if (-not $source) { $source = $PSCommandPath }
    if ([IO.Path]::GetFullPath($source) -ieq [IO.Path]::GetFullPath($InstalledScript)) { return $false }
    if ([IO.File]::Exists($InstalledScript)) {
        $existingText = [IO.File]::ReadAllText($InstalledScript)
        $match = [regex]::Match($existingText, "(?m)^\x24ScriptVersion = '([^']+)'$")
        if ($match.Success -and [version]$match.Groups[1].Value -gt [version]$ScriptVersion) {
            throw 'A newer manager version is already installed.'
        }
        $oldHash = [Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($InstalledScript))
        $newHash = [Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($source))
        if ([Convert]::ToBase64String($oldHash) -eq [Convert]::ToBase64String($newHash)) { return $false }
    }
    Write-AtomicBytes $InstalledScript ([IO.File]::ReadAllBytes($source))
    Set-SecureAcl $InstalledScript $false
    return $true
}

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation {
    Write-Host 'Administrator access is required.'
    Write-Host 'Requesting elevation...'
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $source = $PSCommandPath
    $args = '-NoProfile -ExecutionPolicy Bypass -File "' + $source + '"'
    try { Start-Process -FilePath $exe -ArgumentList $args -Verb RunAs; return $true }
    catch { Write-Host 'Elevation ................ [SKIP] Cancelled'; return $false }
}

function Install-Manager {
    Show-Header 'SETUP'
    $config = New-DefaultConfig
    while ($true) {
        Write-Host ' [0] Cancel'
        $entered = Read-Choice 'Hostname'
        if ($entered -eq '0' -or [string]::IsNullOrWhiteSpace($entered)) { return $false }
        try { $config.Hostname = Normalize-Hostname $entered; break }
        catch { Write-Rows @((New-Line 'Hostname' '[WARN] Enter a valid DuckDNS hostname')) }
    }
    if ((Read-Choice 'Press Enter to enter a token, or 0 to cancel') -eq '0') { return $false }
    while ($true) {
        $secure = Read-Host ' Token (hidden; blank cancels)' -AsSecureString
        if ($null -eq $secure -or $secure.Length -eq 0) { return $false }
        try { $cipher = ConvertTo-TokenBytes $secure; break }
        catch { Write-Rows @((New-Line 'Credentials' '[WARN] Enter a valid token')) }
        finally { if ($secure) { $secure.Dispose() } }
    }
    Write-Host ''
    Write-Rows @((New-Line 'Startup' '[ON] 20 s delay'),
        (New-Line 'Network reconnect' '[ON]'),
        (New-Line 'Periodic check' '[ON] Every 30 min'))
    try {
        if (-not [IO.Directory]::Exists($Root)) { [void][IO.Directory]::CreateDirectory($Root) }
        Set-SecureAcl $Root $true
        $handle = Enter-RunLock
        if ($null -eq $handle) { throw 'Another instance is running.' }
        try {
            Protect-Runtime
            $priorState = Read-State -Recover
            if (-not $priorState.CanPersist) { throw 'State access failure.' }
            Save-Config $config
            Write-AtomicBytes $TokenPath $cipher
            Set-SecureAcl $TokenPath $false
            $initialState = New-EmptyState
            $initialState.LastStateRecoveryUtc = $priorState.LastStateRecoveryUtc
            $initialState.LastStateRecoveryReason = $priorState.LastStateRecoveryReason
            Save-State $initialState
            [void](Copy-ManagerScript)
            Protect-Runtime
            $taskResults = @(Repair-ManagerTasks $config)
            if (@($taskResults | Where-Object { $_.Result.StartsWith('[FAIL]') }).Count) {
                foreach ($item in $taskResults) { Write-Rows @((New-Line ($item.Kind + ' task') $item.Result)) }
                throw 'Scheduled task installation failed.'
            }
            Write-Rows @((New-Line 'Installing' '[OK]'), (New-Line 'Scheduled tasks' '[OK] 3 configured'))
            Start-Deadline
            $state = Read-State -Recover
            $check = Complete-Check $config $state 'Manual'
            Write-Rows @((New-Line 'Domain' (Get-DuckDnsDomain $config)),
                (New-Line 'Credentials' (Get-CredentialsStatus $config $state)),
                (New-Line 'Initial check' $check.Lines[-1].Value))
        } finally { Exit-RunLock $handle }
        Write-Host ''
        Write-Host ' Opening dashboard ...'
        Start-Sleep -Seconds 1
        return $true
    } catch {
        Write-Rows @((New-Line 'Installing' '[FAIL] Setup incomplete'))
        Write-Host ' Correct the installation issue and run the manager again.'
        return $false
    } finally {
        [Array]::Clear($cipher, 0, $cipher.Length)
    }
}

function Get-AddressCheckConfigKey($Config) {
    return (@($Config.Hostname, $Config.NetworkInterface.Mode, [string]$Config.NetworkInterface.InterfaceGuid,
        $Config.Dns.Mode, [string]$Config.Dns.ManualServer) -join '|')
}

function Get-OpeningAddressCheck($Config) {
    $check = [pscustomobject]@{
        ConfigKey = (Get-AddressCheckConfigKey $Config)
        PublicIP = '[FAIL] Unavailable'
        DuckDnsIP = '[FAIL] Unavailable'
        Status = '[FAIL] Address check failed'
        CheckedUtc = $null
    }
    $priorClock = $script:RunClock
    Start-Deadline
    try {
        $found = Find-PublicIPv4 $Config
        if ($found.IP) { $check.PublicIP = [string]$found.IP }
        elseif ($found.InterfaceUnavailable) { $check.PublicIP = '[FAIL] Selected interface unavailable' }
        else { $check.PublicIP = '[FAIL] All providers failed' }
        $dns = Resolve-HostA $Config $false
        if ($dns.Success) {
            $check.DuckDnsIP = 'No A record'
            if ($dns.Addresses.Count) { $check.DuckDnsIP = $dns.Addresses -join ', ' }
        } else { $check.DuckDnsIP = '[FAIL] Resolution failed' }
        if (-not $found.IP) { $check.Status = '[FAIL] Public IPv4 unavailable' }
        elseif (-not $dns.Success) { $check.Status = '[FAIL] DNS resolution failed' }
        elseif (-not $dns.Addresses.Count) { $check.Status = '[WARN] No A record' }
        elseif ($dns.Addresses.Count -eq 1 -and $dns.Addresses[0] -eq $found.IP) { $check.Status = '[OK] IPs match' }
        else { $check.Status = '[WARN] IPs differ' }
    } catch [TimeoutException] { $check.Status = '[FAIL] Address check timed out' }
    catch { $check.Status = '[FAIL] Address check failed' }
    finally {
        $check.CheckedUtc = [DateTime]::UtcNow.ToString('o')
        $script:RunClock = $priorClock
    }
    return $check
}

function Show-Dashboard {
    $config = Read-Config
    $state = Read-State
    if ($state.Domain -and $state.Domain -cne (Get-DuckDnsDomain $config)) { $state = New-EmptyState }
    Show-Header ''
    $public = 'Unknown'; if ($state.LastDetectedPublicIPv4) { $public = [string]$state.LastDetectedPublicIPv4 }
    $dns = 'Unknown'; if ($state.DuckDnsIPv4) { $dns = [string]$state.DuckDnsIPv4 }
    $status = Get-StatusText $state
    $lastCheck = Format-StateTime $state 'LastCheckUtc' $false
    $opening = $script:OpeningAddressCheck
    if ($null -ne $opening -and $opening.ConfigKey -ceq (Get-AddressCheckConfigKey $config)) {
        $public = $opening.PublicIP; $dns = $opening.DuckDnsIP; $status = $opening.Status
        $lastCheck = [DateTime]::Parse($opening.CheckedUtc).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
    }
    Write-Rows @((New-Line 'Domain' (Get-DuckDnsDomain $config)),
        (New-Line 'Status' $status),
        (New-Line 'Public IP' $public), (New-Line 'DuckDNS IP' $dns),
        (New-Line 'Last check' $lastCheck))
    Show-Section 'AUTOMATION'
    $startup = '[OFF]'; if ($config.Scheduling.Startup.Enabled) { $startup = '[ON] ' + $config.Scheduling.Startup.DelaySeconds + ' s delay' }
    $network = '[OFF]'; if ($config.Scheduling.NetworkReconnect.Enabled) { $network = '[ON]' }
    $periodic = '[OFF]'; if ($config.Scheduling.Periodic.Enabled) { $periodic = '[ON] Every ' + $config.Scheduling.Periodic.IntervalMinutes + ' min' }
    Write-Rows @((New-Line 'Startup' $startup), (New-Line 'Network reconnect' $network),
        (New-Line 'Periodic check' $periodic))
    Show-Section 'MENU'
    Write-Host ' [1] Update Now'
    Write-Host ' [2] Configuration'
    Write-Host ' [3] Scheduling'
    Write-Host ' [4] Status'
    Write-Host ' [5] Diagnostics'
    Write-Host ' [6] Maintenance'
    Write-Host ''
    Write-Host ' [0] Exit'
    Write-Host ''
}

function Run-Update([string]$RunReason, [bool]$Interactive) {
    $handle = Enter-RunLock
    if ($null -eq $handle) {
        $result = [pscustomobject]@{ Lines = @((New-Line 'Update' '[SKIP] Another instance is running'),
            (New-Line 'Result' '[SKIP] No check performed')); ExitCode = 0 }
    } else {
        try {
            $config = $null
            try { Migrate-Config; $config = Read-Config }
            catch {
                $result = [pscustomobject]@{ Lines = @((New-Line 'Configuration' '[FAIL] Invalid or unavailable'),
                    (New-Line 'Result' '[FAIL] Check could not start')); ExitCode = $ExitCodes.Config }
            }
            if ($null -ne $config) {

                $state = Read-State -Recover
                $debounced = $false
                if ($RunReason -eq 'Network' -and $state.LastSuccessfulCheckUtc -and $state.LastExitCode -eq 0 -and $state.ReadKind -eq 'Valid') {
                    $age = ([DateTime]::UtcNow - [DateTime]::Parse($state.LastSuccessfulCheckUtc).ToUniversalTime()).TotalSeconds
                    $debounced = ($age -ge 0 -and $age -lt 15)
                }
                if ($debounced) {
                    $result = [pscustomobject]@{ Lines = @((New-Line 'Update' '[SKIP] Recent successful check'),
                        (New-Line 'Result' '[SKIP] No check performed')); ExitCode = 0 }
                } else {
                    try { Start-Deadline; $result = Complete-Check $config $state $RunReason }
                    catch {
                        $result = [pscustomobject]@{ Lines = @((New-Line 'Result' '[FAIL] Unexpected internal error')); ExitCode = $ExitCodes.Internal }
                    }
                }
            }
            if ($result.ExitCode -eq $ExitCodes.Config -or $result.ExitCode -eq $ExitCodes.Internal) {
                $state = Read-State -Recover
                $state.ConsecutiveFailures = [int][Math]::Min(2147483647, ([long]$state.ConsecutiveFailures + 1))
                $state.LastCheckUtc = [DateTime]::UtcNow.ToString('o')
                $state.LastReason = $RunReason
                $state.LastResult = $result.Lines[-1].Value
                $state.SynchronizationState = 'Failed'
                $state.LastExitCode = $result.ExitCode
                try { Save-State $state }
                catch { $result = [pscustomobject]@{ Lines = @((New-Line 'Saved state' '[FAIL] Could not save status')); ExitCode = $ExitCodes.State } }
            }
        } finally { Exit-RunLock $handle }
    }
    if ($Interactive) { Show-ResultScreen 'UPDATE NOW' $result.Lines }
    return [int]$result.ExitCode
}

function Start-Manager {
    try {
        Add-Type -AssemblyName 'System.Security'
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if ($Scheduled) {
            if (-not [IO.File]::Exists($ConfigPath)) { return $ExitCodes.Config }
            return (Run-Update $Reason $false)
        }
        if (-not (Test-Elevated)) {
            [void](Request-Elevation)
            return 0
        }
        if (-not [IO.File]::Exists($ConfigPath)) {
            if (-not (Install-Manager)) { return $ExitCodes.Config }
        } else {
            try {
                $config = Read-Config
                $handle = Enter-RunLock
                if ($null -ne $handle) {
                    try {
                        Protect-Runtime
                        Migrate-Config
                        $upgraded = Copy-ManagerScript
                        if ($upgraded) { [void](Repair-ManagerTasks $config) }
                    } finally { Exit-RunLock $handle }
                }
            } catch {
                Write-Host 'Configuration ............. [FAIL] Invalid or unavailable'
                return $ExitCodes.Config
            }
        }
        Show-Header 'OPENING CHECK'
        Write-Rows @((New-Line 'Address check' '[INFO] Querying public IPv4 and DuckDNS DNS'))
        $script:OpeningAddressCheck = Get-OpeningAddressCheck (Read-Config)
        while ($true) {
            Show-Dashboard
            $choice = Read-Choice
            switch ($choice) {
                '0' { return 0 }
                '1' { [void](Run-Update 'Manual' $true) }
                '2' { Show-Configuration }
                '3' { Show-Scheduling }
                '4' { Show-Status }
                '5' { Show-Diagnostics }
                '6' { if (Show-Maintenance) { return 0 } }
                default { Write-Rows @((New-Line 'Input' '[WARN] Choose an option from 0 to 6')); Start-Sleep -Seconds 1 }
            }
        }
    } catch {
        if (-not $Scheduled) { Write-Host 'Manager ................... [FAIL] Unexpected internal error' }
        return $ExitCodes.Internal
    }
}

exit (Start-Manager)
