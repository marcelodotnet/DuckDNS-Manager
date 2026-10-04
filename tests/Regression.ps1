<# Safe regression suite: temporary files, mocked network/credentials/ACL/COM. #>
[CmdletBinding()]
param([string]$Source = (Join-Path (Split-Path -Parent $PSScriptRoot) 'DuckDNS-Manager.ps1'))
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('duckdns-tests-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$priorProgramData = $env:ProgramData
$env:ProgramData = $testRoot
$env:SystemRoot = $(if ($env:SystemRoot) { $env:SystemRoot } else { '/windows' })
$passed = 0
function Assert($Condition, [string]$Name) {
    if (-not $Condition) { throw ('FAILED: ' + $Name) }
    $script:passed++
    Write-Output ('PASS: ' + $Name)
}
try {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
    Assert ($errors.Count -eq 0) 'PowerShell parser'
    $bytes = [IO.File]::ReadAllBytes($Source)
    Assert (@($bytes | Where-Object { $_ -gt 127 }).Count -eq 0) 'ASCII source'
    $text = [IO.File]::ReadAllText($Source)
    $text = $text -replace '(?m)^exit \(Start-Manager\)\s*$', ''
    . ([scriptblock]::Create($text))
    # Windows boundaries are mocked. No real API, credential, ACL or task calls.
    $realApi = ${function:Invoke-DuckDnsApi}
    function Set-SecureAcl { }
    [void][IO.Directory]::CreateDirectory($Root)
    $realMigration = ${function:Migrate-Config}
    function Migrate-Config { }
    Assert ((Normalize-Hostname ' EXAMPLE.DUCKDNS.ORG ') -eq 'example') 'hostname normalization'
    Assert ((Normalize-Hostname 'test-name') -eq 'test-name') 'bare hostname normalization'
    $invalid = $false
    try { [void](Normalize-Domain 'https://example.duckdns.org') } catch { $invalid = $true }
    Assert $invalid 'invalid domain rejected'
    Assert (Test-IPv4 '8.8.8.8' $true) 'public IPv4'
    foreach ($ip in @('192.168.1.1','127.0.0.1','100.64.0.1','203.0.113.42','01.2.3.4','256.1.1.1','::1')) {
        Assert (-not (Test-IPv4 $ip $true)) ('invalid/nonpublic IPv4: ' + $ip)
    }
    function New-LegacyFixture($Config) {
        $fixture = $Config | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $fixture | Add-Member -NotePropertyName Domain -NotePropertyValue (Get-DuckDnsDomain $Config)
        $fixture.PSObject.Properties.Remove('Hostname'); $fixture.PSObject.Properties.Remove('NetworkInterface')
        return $fixture
    }
    $config = New-DefaultConfig; $config.Hostname = 'example'
    Assert-Config $config
    Assert ($config.SchemaVersion -eq 3 -and $config.Dns.Mode -eq 'System') 'schema 3 defaults'
    $v1 = New-LegacyFixture $config
    $v1.PSObject.Properties.Remove('Dns'); $v1.SchemaVersion = 1
    $v1 | Add-Member -NotePropertyName ValidationDns -NotePropertyValue '1.1.1.1'
    $v2 = Convert-ConfigV3 $v1
    Assert ($v2.Dns.Mode -eq 'System' -and $null -eq $v2.Dns.ManualServer) 'default v1 migration'
    $v1 = New-LegacyFixture $config
    $v1.PSObject.Properties.Remove('Dns'); $v1.SchemaVersion = 1
    $v1 | Add-Member -NotePropertyName ValidationDns -NotePropertyValue '192.168.1.1'
    $v2 = Convert-ConfigV3 $v1
    Assert ($v2.Dns.Mode -eq 'Manual' -and $v2.Dns.ManualServer -eq '192.168.1.1') 'custom v1 migration'
    Assert (@(Get-ResolverChain $config).Count -eq 1 -and @(Get-ResolverChain $config)[0] -eq 'Windows') 'system DNS only'
    $config.Dns.Mode = 'Manual'; $config.Dns.ManualServer = '192.168.1.1'
    Assert ((@(Get-ResolverChain $config) -join ',') -eq '192.168.1.1,1.1.1.1,8.8.8.8') 'manual fallback order'
    $script:queries = @()
    function Invoke-DnsQuery($Domain,$Server) {
        $script:queries += $Server
        return [pscustomobject]@{ Success = ($Server -eq '8.8.8.8'); Addresses = @('8.8.4.4') }
    }
    $dns = Resolve-HostA $config $false
    Assert ($dns.Resolver -eq '8.8.8.8' -and $dns.IsFallback -and $script:queries.Count -eq 3) 'manual fallback selected'
    $script:queries = @()
    function Invoke-DnsQuery($Domain,$Server) {
        $script:queries += $Server
        return [pscustomobject]@{ Success = $true; Addresses = @() }
    }
    $dns = Resolve-HostA $config $false
    Assert ($dns.Success -and $dns.Addresses.Count -eq 0 -and $script:queries.Count -eq 1) 'no A does not trigger fallback'
    $results = @([pscustomobject]@{Provider='a';IP='8.8.8.8'},[pscustomobject]@{Provider='b';IP='8.8.8.8'},[pscustomobject]@{Provider='c';IP='8.8.4.4'})
    Assert ((Get-ProviderConsensus $results) -eq '8.8.8.8') 'two-provider consensus'
    Assert ($null -eq (Get-ProviderConsensus @($results[0],$results[0]))) 'duplicate provider is not consensus'
    Assert ($null -eq (Get-ProviderConsensus @($results[0],$results[2]))) 'provider disagreement'
    $state = Read-State
    Assert ($state.ReadKind -eq 'Missing' -and $state.CanPersist) 'missing state normal'
    $handle = Enter-RunLock
    try {
        $other = Enter-RunLock
        Assert ($null -eq $other) 'exclusive lock contention'
        $legacyFixture = New-LegacyFixture $config
        $legacyFixture.SchemaVersion = 1; $legacyFixture.PSObject.Properties.Remove('Dns')
        $legacyFixture | Add-Member -NotePropertyName ValidationDns -NotePropertyValue '192.168.1.1'
        Write-AtomicJson $ConfigPath $legacyFixture
        & $realMigration
        $migrated = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        $migrationBackup = Get-Content $PreviousConfigPath -Raw | ConvertFrom-Json
        Assert ($migrated.SchemaVersion -eq 3 -and $migrationBackup.SchemaVersion -eq 1) 'migration atomically preserves v1 backup'
        Save-Config $config
        $config.ForcedUpdate.Enabled = $true
        Save-Config $config
        $previous = Get-Content $PreviousConfigPath -Raw | ConvertFrom-Json
        Assert (-not $previous.ForcedUpdate.Enabled) 'known-good previous config'
        Save-State (New-EmptyState)
        Assert ((Read-State).ReadKind -eq 'Valid') 'atomic first state creation'
        [IO.File]::WriteAllText($StatusPath,'{broken')
        $state = Read-State
        Assert ($state.ReadKind -eq 'InvalidJson' -and -not $state.CanPersist) 'invalid JSON detection without mutation'
        $state = Read-State -Recover
        Assert ($state.CanPersist -and $state.LastStateRecoveryReason -eq 'InvalidJson') 'invalid JSON recovery'
        Assert (@(Get-CorruptStateFiles).Count -eq 1) 'corrupt bytes preserved'
        Save-State $state
        Assert ((Read-State).LastStateRecoveryReason -eq 'InvalidJson') 'recovery evidence persisted'
        [IO.File]::WriteAllText($StatusPath,'{broken-again')
        Save-State (Read-State -Recover)
        Assert (@(Get-CorruptStateFiles).Count -eq 2) 'recovery filenames do not overwrite'
        $before = [IO.File]::ReadAllText($StatusPath)
        $unreadable = [IO.FileStream]::new($StatusPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try {
            $state = Read-State -Recover
            Assert ($state.ReadKind -eq 'ReadError' -and -not $state.CanPersist -and -not $state.HistoryKnown) 'read error preserves unknown history'
            $failed = $false; try { Save-State $state } catch { $failed = $true }
            Assert $failed 'read error prohibits state overwrite'
            Assert ((Format-StateTime $state 'LastSuccessfulUpdateUtc') -eq 'Unknown') 'unreadable history never displays Never'
            Assert ((Get-StatusText $state) -eq '[FAIL] Saved state unreadable') 'unreadable state visible in status'
        } finally { $unreadable.Dispose() }
        Assert ([IO.File]::ReadAllText($StatusPath) -eq $before) 'unreadable state unchanged'
        $script:InternalLimitSeconds = 0
        Start-Deadline
        $timedOut = $false; try { Assert-Deadline } catch [TimeoutException] { $timedOut = $true }
        Assert $timedOut 'deadline exception'
        $script:InternalLimitSeconds = 240; $script:RunClock = $null
        $script:apiCalls = 0; $script:confirmCalls = 0
        function Test-TokenLocal { return $true }
        function Get-CredentialsStatus { return '[OK] Protected and verified' }
        function Set-CredentialOutcome { }
        function Find-PublicIPv4 { return [pscustomobject]@{ IP='8.8.8.8'; Results=@() } }
        function Resolve-HostA { return [pscustomobject]@{Success=$true;Addresses=@('8.8.8.8');Resolver='Windows';IsFallback=$false} }
        function Confirm-PublicIPv4 { $script:confirmCalls++; return [pscustomobject]@{IP='8.8.8.8';Results=@()} }
        function Invoke-DuckDnsApi { $script:apiCalls++; return [pscustomobject]@{Kind='Success';Status='Updated'} }
        $config.ForcedUpdate.Enabled = $false
        $state = New-EmptyState; $state.ConsecutiveFailures = 3
        $result = Complete-Check $config $state 'Manual'
        Assert ($result.ExitCode -eq 0 -and $state.LastSuccessfulCheckUtc -and $state.ConsecutiveFailures -eq 0) 'success resets failures and records successful check'
        Assert ($script:apiCalls -eq 0 -and $script:confirmCalls -eq 0) 'unchanged address lightweight'
        $unknown = New-StateReadResult 'ReadError' $false $false
        $config.ForcedUpdate.Enabled = $true
        $result = Complete-Check $config $unknown 'Manual'
        Assert ($script:apiCalls -eq 0 -and $result.ExitCode -eq 15) 'unreadable history cannot make forced update due'
        $config.ForcedUpdate.Enabled = $false
        function Resolve-HostA { return [pscustomobject]@{Success=$true;Addresses=@('8.8.4.4');Resolver='Windows';IsFallback=$false} }
        $config.PostUpdateValidation = $false
        $state = Read-State
        $result = Complete-Check $config $state 'Manual'
        Assert ($state.SynchronizationState -eq 'Accepted' -and $script:apiCalls -eq 1) 'accepted without DNS validation'
        $pending = Read-State
        $pending.SynchronizationState = 'Pending'
        $beforeCalls = $script:confirmCalls
        $result = Complete-Check $config $pending 'Periodic'
        Assert ($pending.SynchronizationState -eq 'Pending' -and $script:apiCalls -eq 1 -and $script:confirmCalls -eq $beforeCalls) 'pending propagation suppresses repeat API and confirmation'
        function Confirm-PublicIPv4 { return [pscustomobject]@{IP=$null;Results=@()} }
        $state = Read-State
        $state.SynchronizationState = 'Unknown'
        $result = Complete-Check $config $state 'Manual'
        Assert ($script:apiCalls -eq 1 -and $result.ExitCode -eq 12 -and $state.ConsecutiveFailures -eq 1) 'unconfirmed change cannot publish'
        function Resolve-HostA { return [pscustomobject]@{Success=$false;Addresses=@();Resolver=$null;IsFallback=$false} }
        $state = Read-State
        $result = Complete-Check $config $state 'Manual'
        Assert ($script:apiCalls -eq 1 -and $result.ExitCode -eq 13 -and $state.ConsecutiveFailures -eq 2) 'DNS failure cannot publish'
        $script:InternalLimitSeconds = 0; $script:RunClock = $null
        function Find-PublicIPv4 { Assert-Deadline; return $null }
        $state = Read-State
        $result = Complete-Check $config $state 'Periodic'
        Assert ($result.ExitCode -eq 16 -and $state.ConsecutiveFailures -eq 3) 'controlled timeout persisted'
        $script:InternalLimitSeconds = 240
        Remove-CorruptStateFiles
        Assert (@(Get-CorruptStateFiles).Count -eq 0) 'managed corruption backups cleared'
    } finally { Exit-RunLock $handle }
    Assert (-not $script:RunLockHeld) 'lock released'
    Assert (Compare-Duration 'PT300S' 'PT5M') 'equivalent scheduler duration'
    $subscription = Get-NetworkSubscription
    $equivalent = $subscription.Replace('EventID=10000',' ( EventID = 10000 ) ').Replace('<QueryList>','<QueryList> ')
    Assert ((Normalize-Subscription $subscription) -eq (Normalize-Subscription $equivalent)) 'equivalent event subscription'
    $a = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\DuckDNS\DuckDNS-Manager.ps1" -Scheduled -Reason Startup'
    $b = '-NonInteractive  -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\DuckDNS\DuckDNS-Manager.ps1 -Reason Startup -Scheduled'
    Assert ((Get-ArgumentSignature $a) -eq (Get-ArgumentSignature $b)) 'equivalent action arguments'

    Assert (Test-NoAError ([pscustomobject]@{FullyQualifiedErrorId='DNS_INFO_NO_RECORDS,ResolveDnsName';Exception=[Exception]::new()})) 'no-A response classification'
    Assert (-not (Test-NoAError ([pscustomobject]@{FullyQualifiedErrorId='ERROR_TIMEOUT,ResolveDnsName';Exception=[Exception]::new()}))) 'resolver timeout classification'
    function Get-TokenFileIdentity { return 'mock-ciphertext-identity' }
    function Read-Token { return 'TEST-FIXTURE-NOT-A-CREDENTIAL' }
    function Invoke-WebRequest { return [pscustomobject]@{Content=$script:apiBody} }
    $script:RunClock = $null
    $script:apiBody = "OK`n8.8.8.8`nUPDATED"
    Assert ((& $realApi $config '8.8.8.8' $true).Kind -eq 'Success') 'mock API acceptance'
    $script:apiBody = "OK`n8.8.8.8`nNOCHANGE"
    Assert ((& $realApi $config '8.8.8.8' $true).Status -eq 'NoChange') 'mock API no-change'
    $script:apiBody = 'KO'
    Assert ((& $realApi $config '8.8.8.8' $true).Kind -eq 'Rejected') 'mock API explicit rejection'
    $script:apiBody = 'unrecognized'
    Assert ((& $realApi $config '8.8.8.8' $true).Kind -eq 'InvalidResponse') 'mock API malformed response is not credential rejection'
    function New-FakeCollection([bool]$Triggers) {
        $collection = [pscustomobject]@{ Items = [Collections.ArrayList]::new(); Count = 0; IsTrigger = $Triggers }
        $collection | Add-Member -MemberType ScriptMethod -Name Create -Value {
            param($type)
            if ($this.IsTrigger) {
                $item = [pscustomobject]@{ Type=$type; Enabled=$false; Delay=''; Subscription='';
                    StartBoundary=''; EndBoundary=''; RandomDelay='';
                    Repetition=[pscustomobject]@{Interval='';Duration='';StopAtDurationEnd=$false} }
            } else { $item = [pscustomobject]@{Type=$type;Path='';Arguments='';WorkingDirectory=''} }
            [void]$this.Items.Add($item); $this.Count = $this.Items.Count
            return $item
        }
        $collection | Add-Member -MemberType ScriptMethod -Name Item -Value { param($index) return $this.Items[$index-1] }
        return $collection
    }
    function New-FakeDefinition {
        return [pscustomobject]@{
            RegistrationInfo=[pscustomobject]@{Description=''}
            Principal=[pscustomobject]@{UserId='';LogonType=0;RunLevel=0}
            Settings=[pscustomobject]@{Enabled=$true;MultipleInstances=0;ExecutionTimeLimit='';
                DisallowStartIfOnBatteries=$true;StopIfGoingOnBatteries=$true;RunOnlyIfNetworkAvailable=$true;
                StartWhenAvailable=$false;Hidden=$false;AllowDemandStart=$false;RestartCount=0}
            Triggers=(New-FakeCollection $true)
            Actions=(New-FakeCollection $false)
        }
    }
    $folder = [pscustomobject]@{}
    $folder | Add-Member -MemberType ScriptMethod -Name GetTask -Value { param($name) return $script:fakeTask }
    $folder | Add-Member -MemberType ScriptMethod -Name RegisterTaskDefinition -Value {
        param($name,$definition,$flags,$user,$password,$logon,$sddl)
        $script:fakeTask = [pscustomobject]@{Definition=$definition;Enabled=$definition.Settings.Enabled}
        return 0
    }
    $service = [pscustomobject]@{Folder=$folder}
    $service | Add-Member -MemberType ScriptMethod -Name NewTask -Value { param($flags) return (New-FakeDefinition) }
    $service | Add-Member -MemberType ScriptMethod -Name GetFolder -Value { param($name) return $this.Folder }
    $config = New-DefaultConfig; $config.Hostname = 'example'
    foreach ($kind in @('Startup','Network','Periodic')) {
        $definition = New-ManagerTaskDefinition $service $config $kind
        $script:fakeTask = [pscustomobject]@{Definition=$definition;Enabled=$definition.Settings.Enabled}
        Assert (Test-ManagerTask $service $config $kind) ('task semantic validation: '+$kind)
        Assert ($definition.Principal.UserId -eq 'SYSTEM' -and $definition.Settings.ExecutionTimeLimit -eq 'PT5M' -and
            $definition.Settings.MultipleInstances -eq 2) ('task principal and limits: '+$kind)
        if ($kind -eq 'Startup') { Assert ($definition.Triggers.Item(1).Delay -eq 'PT20S') 'fixed boot delay' }
        if ($kind -eq 'Periodic') {
            Assert ($definition.Triggers.Item(1).Repetition.Interval -eq 'PT30M' -and
                $definition.Triggers.Item(1).Repetition.Duration -eq '') 'indefinite periodic repetition'
        }
        $definition.Settings.MultipleInstances = 0
        Assert (-not (Test-ManagerTask $service $config $kind)) ('task mismatch detection: '+$kind)
        Set-ManagerTask $service $config $kind
        Assert (Test-ManagerTask $service $config $kind) ('mock task repair: '+$kind)
    }
    $config.Scheduling.Periodic.Enabled = $false
    Set-ManagerTask $service $config 'Periodic'
    Assert (Test-ManagerTask $service $config 'Periodic') 'configured disabled task healthy'
    # A recent failed check must not be debounced; skips must not write status.
    function Read-Config { return $script:config }
    function Complete-Check($Config,$State,$Reason) { $script:checkCalls++; return [pscustomobject]@{Lines=@();ExitCode=0} }
    $script:checkCalls = 0
    $handle = Enter-RunLock
    try {
        $state = New-EmptyState; $state.Domain = Get-DuckDnsDomain $config
        $state.LastCheckUtc = [DateTime]::UtcNow.ToString('o')
        $state.LastSuccessfulCheckUtc = [DateTime]::UtcNow.ToString('o')
        Save-State $state
        $before = [IO.File]::ReadAllText($StatusPath)
        Assert ((Run-Update 'Periodic' $false) -eq 0) 'competing run exits zero'
        Assert ([IO.File]::ReadAllText($StatusPath) -eq $before) 'competing run cannot change state'
    } finally { Exit-RunLock $handle }
    Assert ((Run-Update 'Network' $false) -eq 0 -and $script:checkCalls -eq 0) 'recent successful check debounced'
    Assert ([IO.File]::ReadAllText($StatusPath) -eq $before) 'debounce cannot change state'
    $handle = Enter-RunLock
    try { $state.LastExitCode = 13; Save-State $state } finally { Exit-RunLock $handle }
    Assert ((Run-Update 'Network' $false) -eq 0 -and $script:checkCalls -eq 1) 'recent failure permits new network check'
    Write-Output ("All $passed assertions passed. Windows ACL/DPAPI/COM integration remains untested.")
} finally {
    $env:ProgramData = $priorProgramData
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
