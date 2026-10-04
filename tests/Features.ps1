<# Safe feature suite: synthetic interfaces, mocked HTTP/DPAPI boundaries, temporary files. #>
[CmdletBinding()]
param([string]$Source = (Join-Path (Split-Path -Parent $PSScriptRoot) 'DuckDNS-Manager.ps1'))
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('duckdns-features-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$priorProgramData = $env:ProgramData; $env:ProgramData = $testRoot
$passed = 0
function Assert($Condition, [string]$Name) {
    if (-not $Condition) { throw ('FAILED: ' + $Name) }
    $script:passed++; Write-Output ('PASS: ' + $Name)
}
function Assert-Throws($Action, [string]$Name) {
    $thrown = $false; try { & $Action } catch { $thrown = $true }
    Assert $thrown $Name
}
try {
    foreach ($file in @($Source,$PSCommandPath)) {
        $tokens = $null; $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
        Assert ($errors.Count -eq 0) ('parser: ' + [IO.Path]::GetFileName($file))
        Assert (@([IO.File]::ReadAllBytes($file) | Where-Object { $_ -gt 127 }).Count -eq 0) ('ASCII: ' + [IO.Path]::GetFileName($file))
    }
    $sourceText = [IO.File]::ReadAllText($Source) -replace '(?m)^exit \(Start-Manager\)\s*$', ''
    . ([scriptblock]::Create($sourceText))
    function Set-SecureAcl { }
    [void][IO.Directory]::CreateDirectory($Root)
    foreach ($entry in @(' EXAMPLE.DUCKDNS.ORG ','example','example.duckdns.org')) {
        Assert ((Normalize-Hostname $entry) -ceq 'example') 'bare/FQDN input normalized to one hostname'
    }
    foreach ($entry in @('.example','host name','host..name','https://example','example.com','-example','example-',('a' * 64),'')) {
        Assert-Throws { [void](Normalize-Hostname $entry) } ('invalid hostname: ' + $entry)
    }
    $config = New-DefaultConfig; $config.Hostname = 'example'; $config.Retry.Attempts = 1
    Assert ((Get-DuckDnsDomain $config) -ceq 'example.duckdns.org') 'fixed derived suffix'
    Assert ($null -eq $config.PSObject.Properties['Domain']) 'canonical config has no Domain'
    $handle = Enter-RunLock
    try {
        foreach ($schema in @(1,2)) {
            $legacy = $config | ConvertTo-Json -Depth 10 | ConvertFrom-Json
            $legacy.PSObject.Properties.Remove('Hostname'); $legacy.PSObject.Properties.Remove('NetworkInterface')
            $legacy | Add-Member -NotePropertyName Domain -NotePropertyValue 'example.duckdns.org'
            $legacy.SchemaVersion = $schema; $legacy.Logging.Enabled = $true
            if ($schema -eq 1) {
                $legacy.PSObject.Properties.Remove('Dns')
                $legacy | Add-Member -NotePropertyName ValidationDns -NotePropertyValue '192.168.1.1'
            } else { $legacy.Dns.Mode = 'Manual'; $legacy.Dns.ManualServer = '192.168.1.1' }
            Write-AtomicBytes $TokenPath ([byte[]]@(11,22,33,44))
            Write-AtomicJson $ConfigPath $legacy
            $saved = New-EmptyState; $saved.Domain = 'example.duckdns.org'; $saved.DuckDnsIPv4 = '8.8.4.4'
            Save-State $saved
            Migrate-Config
            $next = Read-Config
            Assert ($next.SchemaVersion -eq 3 -and $next.Hostname -ceq 'example' -and
                $next.NetworkInterface.Mode -eq 'Automatic' -and $null -eq $next.NetworkInterface.InterfaceGuid) ('schema migration: ' + $schema)
            Assert ($next.Logging.Enabled -and $next.Dns.ManualServer -eq '192.168.1.1') 'migration preserves user settings'
            Assert (([IO.File]::ReadAllBytes($TokenPath) -join ',') -eq '11,22,33,44' -and
                (Read-State).DuckDnsIPv4 -eq '8.8.4.4') 'migration preserves protected token bytes and applicable state'
            Assert ((Get-Content $PreviousConfigPath -Raw | ConvertFrom-Json).SchemaVersion -eq $schema) 'one valid prior schema backup'
        }
    } finally { Exit-RunLock $handle }
    Assert-Throws { Migrate-Config } 'migration requires lock'
    $bad = $config | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $bad.Hostname = 'example.duckdns.org'
    Assert-Throws { Assert-Config $bad } 'schema 3 rejects noncanonical FQDN storage'
    $bad.Hostname = 123
    Assert-Throws { Assert-Config $bad } 'hostname must be stored as text'
    $bad.Hostname = 'example'; $bad.SchemaVersion = '3'
    Assert-Throws { Assert-Config $bad } 'schema version must be an integer'
    $bad.SchemaVersion = 3
    $bad.Hostname = 'example'; $bad.NetworkInterface.Mode = 'Specific'; $bad.NetworkInterface.InterfaceGuid = 'not-a-guid'
    Assert-Throws { Assert-Config $bad } 'specific mode requires stable GUID'
    $bad.NetworkInterface.Mode = 'Automatic'; $bad.NetworkInterface.InterfaceGuid = [guid]::NewGuid().ToString('D')
    Assert-Throws { Assert-Config $bad } 'automatic mode cannot retain a specific GUID'
    foreach ($address in @('192.168.1.20','10.7.0.2','100.64.1.3')) { Assert (Test-UsableLocalIPv4 $address) 'private/VPN source usable' }
    foreach ($address in @('127.0.0.1','169.254.2.3','0.0.0.0','224.1.2.3','::1')) { Assert (-not (Test-UsableLocalIPv4 $address)) 'unusable source excluded' }

    $guidA = '11111111-1111-4111-8111-111111111111'; $guidB = '22222222-2222-4222-8222-222222222222'
    $script:interfaces = @([pscustomobject]@{ InterfaceGuid=$guidA;InterfaceAlias='Wi-Fi';InterfaceIndex=7;
        IPv4='192.168.2.30';Addresses=@('192.168.2.30');IsVirtual=$false },
        [pscustomobject]@{InterfaceGuid=$guidB;InterfaceAlias='VPN';InterfaceIndex=9;
        IPv4='10.7.0.2';Addresses=@('10.7.0.2');IsVirtual=$true})
    function Get-UsableInterfaces { return $script:interfaces }
    $script:boundCalls = @(); $script:autoCalls = 0
    function Invoke-BoundProvider($Url,$SourceIPv4) {
        $script:boundCalls += [pscustomobject]@{Url=$Url;Source=$SourceIPv4}
        if ($script:failBound) { throw 'Synthetic connection failure' }
        if ($script:dropDuringCall) { $script:interfaces = @() }
        if ($script:disagreement -and ([uri]$Url).Host -ne 'api.ipify.org') { return '8.8.4.4' }
        return '8.8.8.8'
    }
    function Invoke-WebRequest { $script:autoCalls++; return [pscustomobject]@{Content='8.8.8.8'} }
    $auto = Find-PublicIPv4 $config
    Assert ($auto.IP -eq '8.8.8.8' -and $script:autoCalls -eq 1 -and $script:boundCalls.Count -eq 0) 'Automatic keeps normal Windows request path'
    $config.NetworkInterface.Mode = 'Specific'; $config.NetworkInterface.InterfaceGuid = $guidA
    $found = Find-PublicIPv4 $config
    $confirmed = Confirm-PublicIPv4 $config $found
    Assert ($confirmed.IP -eq '8.8.8.8' -and $script:boundCalls.Count -eq 2 -and
        @($script:boundCalls | Where-Object { $_.Source -ne '192.168.2.30' }).Count -eq 0 -and
        $script:autoCalls -eq 1) 'Specific consensus binds every provider to the same selected source'
    $script:interfaces[0].InterfaceAlias = 'Renamed adapter'; $script:interfaces[0].InterfaceIndex = 17
    $script:interfaces[0].IPv4 = '192.168.2.40'; $script:interfaces[0].Addresses = @('192.168.2.40')
    $renamed = Find-PublicIPv4 $config
    Assert ($renamed.Context.InterfaceAlias -eq 'Renamed adapter' -and $renamed.Context.InterfaceIndex -eq 17 -and
        $script:boundCalls[-1].Source -eq '192.168.2.40') 'GUID survives alias, index and DHCP changes on a new run'
    $count = $script:boundCalls.Count
    $stale = Confirm-PublicIPv4 $config $found
    Assert ($stale.InterfaceUnavailable -and -not $stale.IP -and $script:boundCalls.Count -eq $count) 'mid-consensus source changes reject old observations'
    $other = $config | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $other.NetworkInterface.InterfaceGuid = $guidB
    $crossed = Confirm-PublicIPv4 $other $renamed
    Assert ($crossed.InterfaceUnavailable -and -not $crossed.IP) 'consensus cannot cross configured interface identities'
    $script:failBound = $true
    $failed = Find-PublicIPv4 $config
    Assert (-not $failed.IP -and -not $failed.InterfaceUnavailable -and $script:autoCalls -eq 1) 'provider connection failure never falls back to Automatic'
    $realBoundMock = ${function:Invoke-BoundProvider}
    function Invoke-BoundProvider { throw [InvalidOperationException]::new('Synthetic HTTP response failure') }
    $failed = Find-PublicIPv4 $config
    Assert (-not $failed.IP -and -not $failed.InterfaceUnavailable) 'ordinary HTTP exception is not misreported as interface disappearance'
    ${function:Invoke-BoundProvider} = $realBoundMock
    $script:failBound = $false; $savedInterfaces = $script:interfaces
    $script:dropDuringCall = $true
    $dropped = Find-PublicIPv4 $config
    Assert ($dropped.InterfaceUnavailable -and -not $dropped.IP) 'interface loss during a provider call drops its response'
    $script:dropDuringCall = $false
    $missing = Find-PublicIPv4 $config
    Assert ($missing.InterfaceUnavailable -and $script:autoCalls -eq 1) 'missing selected GUID fails strictly'
    $script:interfaces = $savedInterfaces
    $handle = Enter-RunLock
    try { Save-Config $config } finally { Exit-RunLock $handle }
    $originalConfig = [IO.File]::ReadAllText($ConfigPath)
    $rows = Save-NetworkInterface $config.NetworkInterface $found.Context
    Assert ($rows[0].Value.StartsWith('[FAIL]') -and [IO.File]::ReadAllText($ConfigPath) -ceq $originalConfig) 'stale tested interface cannot be saved'
    $rows = Save-NetworkInterface $config.NetworkInterface $renamed.Context
    Assert ($rows[0].Value.StartsWith('[OK]')) 'currently usable tested GUID can be saved'
    $rows = Save-NetworkInterface ([pscustomobject]@{Mode='Automatic';InterfaceGuid=$null})
    Assert ($rows[0].Value.StartsWith('[OK]') -and (Read-Config).NetworkInterface.Mode -eq 'Automatic') 'Automatic saves without a selection test'

    # Receipt encryption is mocked in memory; no production DPAPI/token is used.
    $script:localReadable = $true; $script:receipt = $null
    function Test-TokenLocal { return $script:localReadable }
    function Read-CredentialReceipt {
        if ($null -eq $script:receipt) { throw 'Synthetic missing receipt' }
        return $script:receipt
    }
    function Write-CredentialReceipt($Value) {
        if (-not $script:RunLockHeld) { throw 'Receipt requires lock' }
        if ($script:failReceipt) { throw 'Synthetic receipt persistence failure' }
        $script:receipt = $Value
    }
    $config = Read-Config; $config.Logging.Enabled = $false
    $state = New-EmptyState
    Assert ((Get-CredentialsStatus $config $state) -eq '[WARN] Protected; verification pending') 'local protection alone never verifies credentials'
    $handle = Enter-RunLock
    try {
        $accepted = [pscustomobject]@{Kind='Success';Status='NoChange';TokenIdentity=(Get-TokenFileIdentity)}
        Set-CredentialOutcome $config $state $accepted
        Save-State $state
        Assert ((Get-CredentialsStatus $config (Read-State)) -eq '[OK] Protected and verified' -and
            $state.LastCredentialVerificationUtc) 'real acceptance outcome binds receipt to current pair and persists timestamp'
        $statusJson = [IO.File]::ReadAllText($StatusPath)
        Assert ($statusJson -notmatch 'TokenIdentity|TokenLength|token=|TokenPrefix|TokenSuffix') 'state contains no token/ciphertext fingerprint or secret details'
        $config.Hostname = 'another'
        Assert ((Get-CredentialsStatus $config $state) -eq '[WARN] Protected; verification pending') 'hostname change invalidates prior verification'
        $config.Hostname = 'example'
        Write-AtomicBytes $TokenPath ([byte[]]@(55,66,77,88))
        Assert ((Get-CredentialsStatus $config $state) -eq '[WARN] Protected; verification pending') 'protected token replacement invalidates prior verification'
        Set-CredentialOutcome $config $state $accepted
        Assert ($state.CredentialStatus -eq 'Pending') 'token changed during API validation cannot receive a valid receipt'
        $rejected = [pscustomobject]@{Kind='Rejected';TokenIdentity=(Get-TokenFileIdentity)}
        Set-CredentialOutcome $config $state $rejected
        Assert ((Get-CredentialsStatus $config $state) -eq '[FAIL] Rejected') 'explicit KO is recorded for the current pair'
        $script:localReadable = $false
        Assert ((Get-CredentialsStatus $config $state) -eq '[FAIL] Unavailable') 'decryption failure overrides prior rejection/verification'
        $script:localReadable = $true
        Reset-CredentialVerification $state
        Set-CredentialOutcome $config $state ([pscustomobject]@{Kind='Network'})
        Assert ((Get-CredentialsStatus $config $state) -eq '[WARN] Protected; verification pending') 'network failure retains token and pending status'
        $accepted.TokenIdentity = Get-TokenFileIdentity
        Set-CredentialOutcome $config $state $accepted
        $oldState = $state | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        Set-CredentialOutcome $config $state $accepted
        Assert ((Get-CredentialsStatus $config $oldState) -eq '[WARN] Protected; verification pending') 'receipt/state partial persistence never reuses an old success'
        $script:failReceipt = $true
        Set-CredentialOutcome $config $state $accepted
        Assert ($state.CredentialStatus -eq 'Pending' -and -not $state.LastCredentialVerificationUtc) 'receipt write failure cannot claim verification'
        $script:failReceipt = $false
        $script:apiCalls = 0
        function Invoke-DuckDnsApi($Config,$PublicIP,$SingleAttempt) {
            $script:apiCalls++; return [pscustomobject]@{Kind=$script:apiKind;Status='NoChange';TokenIdentity=(Get-TokenFileIdentity);Failure=$script:apiFailure}
        }
        function Resolve-HostA { return [pscustomobject]@{Success=$true;Addresses=@('8.8.8.8');Resolver='Windows';IsFallback=$false} }
        $script:apiKind = 'Success'; $state = New-EmptyState
        $result = Complete-Check $config $state 'Manual'
        Assert ($result.ExitCode -eq 0 -and $script:apiCalls -eq 1 -and
            (Get-CredentialsStatus $config $state) -eq '[OK] Protected and verified') 'first matching-DNS check still verifies credentials through API'
        $beforeBound = $script:boundCalls.Count; $beforeAuto = $script:autoCalls
        $result = Complete-Check $config $state 'Manual'
        Assert ($script:apiCalls -eq 1 -and $script:autoCalls -eq ($beforeAuto + 1) -and
            $script:boundCalls.Count -eq $beforeBound) 'verified unchanged check uses only first provider and skips API'
        $config.NetworkInterface.Mode = 'Specific'; $config.NetworkInterface.InterfaceGuid = $guidA
        $script:interfaces = @()
        $result = Complete-Check $config $state 'Manual'
        Assert ($result.ExitCode -eq 12 -and $script:apiCalls -eq 1 -and
            ($result.Lines.Value -join '|') -eq '[FAIL] Selected interface unavailable|[FAIL] Could not query selected interface|[SKIP] No valid IPv4 available|[FAIL] Network interface unavailable') 'unavailable interface returns exact structured failure and no API'
        $script:interfaces = $savedInterfaces
        $script:disagreement = $true
        function Resolve-HostA { return [pscustomobject]@{Success=$true;Addresses=@('1.1.1.1');Resolver='Windows';IsFallback=$false} }
        # Three different results cannot form a consensus.
        function Invoke-BoundProvider($Url,$SourceIPv4) {
            $script:boundCalls += [pscustomobject]@{Url=$Url;Source=$SourceIPv4}
            switch (([uri]$Url).Host) { 'api.ipify.org' { return '8.8.8.8' }; 'ipv4.icanhazip.com' { return '8.8.4.4' }; default { return '9.9.9.9' } }
        }
        $state.LastDetectedPublicIPv4 = '1.1.1.1'; $state.DuckDnsIPv4 = '1.1.1.1'
        $result = Complete-Check $config $state 'Manual'
        Assert ($result.ExitCode -eq 12 -and $script:apiCalls -eq 1 -and $state.LastDetectedPublicIPv4 -eq '1.1.1.1' -and
            $state.DuckDnsIPv4 -eq '1.1.1.1') 'unconfirmed provider observations preserve known public/DuckDNS state'
        function Resolve-HostA { return [pscustomobject]@{Success=$false;Addresses=@();Resolver=$null;IsFallback=$false} }
        $result = Complete-Check $config $state 'Manual'
        Assert ($result.ExitCode -eq 13 -and $script:apiCalls -eq 1) 'DNS comparison failure blocks credential validation and updates'
        $config.NetworkInterface.Mode = 'Automatic'; $config.NetworkInterface.InterfaceGuid = $null
        function Resolve-HostA { return [pscustomobject]@{Success=$true;Addresses=@('8.8.8.8');Resolver='Windows';IsFallback=$false} }
        $script:apiKind = 'Network'
        $protectedTokenBefore = [Convert]::ToBase64String([IO.File]::ReadAllBytes($TokenPath))
        foreach ($apiFailure in @('HTTP 403','TLS handshake failed','Request timed out')) {
            $script:apiFailure = $apiFailure; $state = New-EmptyState
            $result = Complete-Check $config $state 'Manual'
            Assert ($result.ExitCode -eq 14 -and @($result.Lines | Where-Object { $_.Label -eq 'DuckDNS API' -and $_.Value -eq ('[FAIL] ' + $apiFailure) }).Count -eq 1) ('update screen displays safe API failure: ' + $apiFailure)
            Assert ((Get-CredentialsStatus $config $state) -eq '[WARN] Protected; verification pending' -and
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($TokenPath)) -eq $protectedTokenBefore) ('API diagnostic preserves pending credentials and protected token: ' + $apiFailure)
        }
        $script:apiFailure = $null
    } finally { Exit-RunLock $handle }
    # Execute setup/edit workflows with mock input and mock Windows boundaries.
    $script:consoleLines = @(); $script:choices = [Collections.Queue]::new()
    function Write-Host($Object, [switch]$NoNewline) { $script:consoleLines += [string]$Object }
    function Clear-Host { }
    function Start-Sleep { }
    function Read-Choice { return [string]$script:choices.Dequeue() }
    function Read-Host($Prompt,[switch]$AsSecureString) {
        return (ConvertTo-SecureString 'TEST-FIXTURE-NOT-A-CREDENTIAL' -AsPlainText -Force)
    }
    $script:fixtureRevision = 90
    function ConvertTo-TokenBytes { $script:fixtureRevision++; return [byte[]]@($script:fixtureRevision,22,33,44) }
    function Protect-Runtime { }
    function Copy-ManagerScript { return $false }
    function Repair-ManagerTasks {
        return @([pscustomobject]@{Kind='Startup';Result='[OK]'},[pscustomobject]@{Kind='Network';Result='[OK]'},
            [pscustomobject]@{Kind='Periodic';Result='[OK]'})
    }
    function Resolve-HostA { return [pscustomobject]@{Success=$true;Addresses=@('8.8.8.8');Resolver='Windows';IsFallback=$false} }
    function Invoke-DuckDnsApi {
        if (-not $script:RunLockHeld) { throw 'API validation escaped installation/edit lock' }
        if ($null -ne (Enter-RunLock)) { throw 'Competing run entered initial validation' }
        $script:apiCalls++
        return [pscustomobject]@{Kind=$script:apiKind;Status='NoChange';TokenIdentity=(Get-TokenFileIdentity)}
    }
    $realSaveState = ${function:Save-State}; $script:stateWriteLocks = @()
    function Save-State($State) {
        $script:stateWriteLocks += $script:RunLockHeld
        & $realSaveState $State
    }
    $script:apiKind = 'Success'; $script:choices.Enqueue('example.duckdns.org'); $script:choices.Enqueue('')
    $beforeApi = $script:apiCalls
    Assert (Install-Manager) 'mock installation completes with matching DNS'
    $installedConfig = Read-Config; $installedState = Read-State
    Assert ($script:apiCalls -eq ($beforeApi + 1) -and $installedState.LastCredentialVerificationUtc -and
        $installedConfig.Hostname -ceq 'example') 'setup makes real-outcome validation even when initial DNS matches'
    Assert (@($script:stateWriteLocks | Where-Object { -not $_ }).Count -eq 0 -and
        $script:stateWriteLocks.Count -ge 2 -and -not $script:RunLockHeld) 'setup holds exclusive lock through all persistence and releases it'
    Assert (@($script:consoleLines | Where-Object { $_ -match '^ Credentials .*Protected and verified' }).Count -eq 1 -and
        @($script:consoleLines | Where-Object { $_ -match '^ Token .*\[OK\]' }).Count -eq 0) 'setup displays one unified credential result'
    foreach ($outcome in @('Network','Rejected')) {
        $script:apiKind = $outcome; $script:choices.Enqueue('example'); $script:choices.Enqueue('')
        Assert (Install-Manager) ('setup retains protected token after ' + $outcome)
        $status = Get-CredentialsStatus (Read-Config) (Read-State)
        $expected = '[WARN] Protected; verification pending'
        if ($outcome -eq 'Rejected') { $expected = '[FAIL] Rejected' }
        Assert ($status -ceq $expected -and [IO.File]::Exists($TokenPath)) ('setup credential result: ' + $outcome)
    }
    function Show-ResultScreen($Title,$Rows) { $script:lastUiRows = @($Rows) }
    $beforeToken = Get-TokenFileIdentity
    $script:choices.Enqueue('newhost.duckdns.org')
    Change-Hostname
    Assert ((Read-Config).Hostname -ceq 'newhost' -and (Get-TokenFileIdentity) -ceq $beforeToken -and
        (Read-State).CredentialStatus -ceq 'Pending' -and -not $script:RunLockHeld) 'Change Hostname preserves protected token and invalidates credentials under lock'
    $script:apiKind = 'Success'; $script:choices.Enqueue('')
    Change-Token
    Assert ((Get-TokenFileIdentity) -cne $beforeToken -and (Get-CredentialsStatus (Read-Config) (Read-State)) -ceq
        '[OK] Protected and verified' -and -not $script:RunLockHeld) 'Change Token persists new protected bytes and verifies current hostname under lock'
    $script:consoleLines = @(); $script:choices.Enqueue('0')
    Show-Configuration
    Assert (($script:consoleLines -join '|') -match '\[3\] Network Interface.*\[4\] DNS Settings.*\[9\] Logging' -and
        @($script:consoleLines | Where-Object { $_ -match '^ Credentials ' }).Count -eq 1 -and
        @($script:consoleLines | Where-Object { $_ -match '^ Token ' }).Count -eq 0) 'Configuration menu ordering and unified credential line'
    $script:consoleLines = @(); $script:choices.Enqueue('')
    Assert (-not (Read-Confirmation 'Use this interface?')) 'interface confirmation defaults to No'

    # Compile the production C# delegate and invoke it directly; this is not a live Windows binding test.
    Initialize-BoundHttp -WarningAction SilentlyContinue
    $binding = [DuckDns.Native.SourceBinding]::new('192.168.2.40')
    $endpoint = $binding.Bind($null,[Net.IPEndPoint]::new([Net.IPAddress]::Parse('8.8.8.8'),443),0)
    Assert ($endpoint.Address.ToString() -eq '192.168.2.40' -and $endpoint.Port -eq 0) 'compiled native delegate returns chosen IPv4 with ephemeral port'
    Assert-Throws { [void]$binding.Bind($null,[Net.IPEndPoint]::new([Net.IPAddress]::IPv6Loopback,443),0) } 'compiled delegate rejects IPv6 remote endpoints'
    Assert-Throws { [void]$binding.Bind($null,[Net.IPEndPoint]::new([Net.IPAddress]::Parse('8.8.8.8'),443),3) } 'compiled delegate bounds repeated bind failures'
    Write-Output ("All $passed feature assertions passed. Live Windows binding/DPAPI/ACL/COM remains untested.")
} finally {
    $env:ProgramData = $priorProgramData
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
