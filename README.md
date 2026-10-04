# DuckDNS Manager for Windows

A lightweight Windows PowerShell 5.1 console manager that keeps one DuckDNS
hostname synchronized with the current public IPv4. It uses native Windows
Task Scheduler COM definitions and requires no external modules or programs.

## Installation

1. Download `DuckDNS-Manager.ps1` to the Windows computer that will run updates.
2. Open an interactive Windows PowerShell 5.1 window and run:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\DuckDNS-Manager.ps1
   ```

3. Accept the administrator/UAC prompt, enter your DuckDNS hostname (bare or ending in `.duckdns.org`), and enter a fresh token at the hidden prompt.
4. Review setup, then open **Status** or **Diagnostics** in the dashboard.

The manager installs into `C:\ProgramData\DuckDNS\`. Setup creates three tasks,
performs the initial check and attempts real API validation, including when DNS
already matches. A network outage may leave validation pending while setup
completes. A securely saved token is retained if validation is unavailable or
DuckDNS rejects the request. A rejected request needs investigation; a saved
or decryptable token alone does not prove API acceptance.

## Hostname and credentials

Configuration stores only a single DNS label, for example `"Hostname": "example"`.
Input may be `example` or `example.duckdns.org`; both become `example`. The suffix
is fixed, and displayed Domain is always derived as `example.duckdns.org`.
Configuration includes **Change Hostname**, **Change Token** and one Credentials
line:

| Credentials | Meaning |
| --- | --- |
| `[OK] Protected and verified` | Locally decryptable token and real API acceptance of the current pair |
| `[WARN] Protected; verification pending` | Locally protected; no current accepted/rejected verification receipt |
| `[FAIL] Rejected` | DuckDNS explicitly rejected the current pair |
| `[FAIL] Unavailable` | Missing, unreadable, undecryptable or invalid protected token |

Changing Hostname or Token immediately invalidates prior verification. An actual
accepted API request verifies the new pair, including a matching-DNS first check.
Network/service failure leaves verification pending and retains the token. An
opaque verification ID and success time enter status; the token-file identity
stays in a separate DPAPI-protected receipt, never in status, logs or the UI.
Legacy token files are preserved by migration. The dashboard stays compact.

## Network interface

**Configuration > Network Interface** offers Automatic and Specific modes.
Automatic preserves normal Windows routing. Specific stores the interface GUID;
current alias, index and usable IPv4 are resolved each run, so rename and DHCP
changes do not require reconfiguration. Active usable virtual/VPN adapters are
included and marked when their virtual nature is reliably detectable.

A selection is tested with bound provider queries and independent-provider
consensus before the default-No **Use this interface? [y/N]** prompt. A failed or
stale test cannot save the choice. Specific mode binds only public-IP provider
requests to that interface's current source IPv4. DNS and DuckDNS API traffic
continue through normal Windows routing. No route, metric or gateway is changed.

Specific queries use a native .NET Framework source-binding delegate, a fresh
connection group and direct connections without proxy or redirect fallback.
Temporary binding is restored and connections closed in `finally`. If the GUID
is missing/down or has no usable IPv4, the check fails with code 12 and sends no
API request. There is no Automatic fallback. A source change during consensus
invalidates that attempt; the next run resolves the new address afresh. Full
Diagnostics reports Interface mode, current source and whether a provider query
actually succeeded through binding. VPN/firewall/routing policy can prevent a
bound query; validate actual egress on the target Windows machine.

## Default behavior

| Setting | Default |
| --- | --- |
| Compare public IPv4 with DuckDNS A record | On |
| Post-update DNS validation | On |
| Network interface | Automatic: normal Windows routing |
| DNS mode | System: Windows DNS, without public fallback |
| Retry attempts / delay | 6 total attempts / 5 seconds |
| Startup | On, fixed 20-second boot delay |
| Network reconnect | On, NetworkProfile event 10000 |
| Periodic | On, every 30 minutes indefinitely |
| Forced Update | Off; 24-hour interval when enabled |
| Logging | Off |

In **Configuration > DNS Settings**, Manual mode queries your configured IPv4
DNS server, then `1.1.1.1`, then `8.8.8.8` only if the preceding resolver fails.
A valid no-A/NXDOMAIN answer stops fallback. System mode uses Windows DNS and
preserves VPN, corporate and interface DNS choices. If comparison is enabled
and all relevant DNS queries fail, the manager does not send an API update.

Public IPv4 discovery tries ipify, icanhazip and Amazon in that order. When the
first valid address already matches DNS, no additional provider is queried.
Before publishing a changed address, two independent providers must agree.
With comparison disabled, every proposed API update requires this consensus
because the manager cannot know whether the current record already matches.

Forced Update permits a fresh API call even if DNS already matches when its
configured interval since the last accepted API call has elapsed. Missing
history permits a first forced call; unreadable history never makes it due.

An accepted update with post-update validation disabled reports **Update
accepted**. A DNS answer still showing the old address reports **Propagation
pending**. While that same accepted address is pending, another API call is
suppressed for five minutes. **Synchronized** requires a matching DNS answer.

## Runtime, security and recovery

| File | Purpose |
| --- | --- |
| `DuckDNS-Manager.ps1` | Installed application and scheduled action |
| `config.json` | Non-sensitive schema 3 configuration |
| `config.previous.json` | One valid previous configuration; no automatic restore |
| `token.dat` | Token encrypted with Windows DPAPI LocalMachine |
| `credentials.dat` | DPAPI-protected verification receipt for the current pair |
| `status.json` | Check/API and credential history, result, failure count, version and recovery evidence |
| `status.corrupt-*.json` | Preserved invalid state files |
| `run.lock` | Exclusive file handle across all execution sources |
| `logs\` | Optional logs with one rotated copy |

SYSTEM and local Administrators are the trusted principals. The token is tied
to this Windows installation and never enters configuration, status, logs or
console output. Local administrators remain trusted. The HTTPS update request
contains the token internally; errors suppress its complete URL.

Configuration, state and token writes use complete temporary files in the same
runtime directory before atomic replacement/move. JSON is validated before
replacement. Configuration changes preserve one previous valid configuration.
Schemas 1 and 2 migrate automatically under the lock to schema 3. Old `Domain`
becomes bare `Hostname`; the token, logs, settings and applicable state remain
untouched. For schema 1, old default `1.1.1.1` becomes System DNS and a custom
resolver becomes Manual DNS. New interface selection defaults to Automatic.

Invalid readable state is renamed without overwriting a backup, and a new
valid state records recovery evidence. Read errors preserve the original file;
current IP/DNS checks may proceed, but state cannot be overwritten and the run
reports exit code 15. Status shows unknown history rather than inventing dates.
**Clear Saved State** resets state and removes manager-owned corrupt backups.
Changing the hostname clears the previous hostname's history, including forced
update eligibility, while preserving token, configuration and tasks.

## Diagnostics and maintenance

Full Diagnostics groups configuration/security, network and automation checks.
It reports actual resolver use, runtime ACL health, saved-state health and task
configuration. The unified Credentials line reports local protection plus the persisted result
of an actual API request for the current pair; diagnostics themselves never send
an update to test credentials. Change Token retains the protected token and runs
a check with at most one API validation attempt, respecting DNS comparison and
provider consensus.

Maintenance repairs tasks, restores defaults while preserving hostname/token,
opens the runtime folder or Task Scheduler, clears state/logs, and uninstalls.
Restore Defaults returns DNS to System mode and interface selection to Automatic. Uninstall removes only manager-owned
files/tasks, including configuration/state backups, and leaves unrelated files.
Run a newer script copy manually to upgrade while preserving installed data.

Logging is off by default. When enabled, it writes concise sanitized results
and rotates at roughly 1 MiB with one previous log. Dates are stored in UTC and
displayed in local time.

## Execution and exit codes

All tasks run as SYSTEM, use IgnoreNew and a five-minute hard limit. The global
lock also prevents overlap between different tasks and manual runs. Network
event bursts are suppressed for 15 seconds only after a recent successful
check; recent failures allow a new network check. These skips do not change
saved history. The application checks an internal 240-second execution budget
before/after network operations and before retry sleeps, then attempts to save
a controlled timeout result and release the lock.

| Code | Meaning |
| ---: | --- |
| 0 | Successful check, accepted/pending update, or execution skip |
| 10 | Configuration unavailable or invalid |
| 11 | Token unavailable or cannot be decrypted |
| 12 | Selected interface/public IPv4 unavailable or change unconfirmed |
| 13 | DNS comparison failed |
| 14 | DuckDNS request rejected, failed or malformed |
| 15 | State inaccessible or could not be persisted |
| 16 | Internal execution timeout |
| 99 | Unexpected internal error |

## Tests and validation

Run both safe suites:

```powershell
powershell.exe -NoProfile -File .\tests\Regression.ps1
powershell.exe -NoProfile -File .\tests\Features.ps1
```

The suites use temporary files, synthetic interfaces and mocked Windows/network
boundaries. They never call the real DuckDNS API. PowerShell 7.4.13/Linux passed
78 regression and 83 feature assertions (161 total), including parser/ASCII,
migration, atomic writes, locks, state recovery, DNS selection, consensus,
DHCP/rename/disconnection handling, strict source selection, credential
transitions, setup/edit lock scope and console flows, timeouts, debounce and simulated task semantics. The production
C# binding delegate was compiled and invoked directly. Actual Windows source
binding, DPAPI, ACLs, native DNS and Task Scheduler integration were not executed.
Windows PowerShell 5.1 compatibility was reviewed statically. No production
credential was used for testing.

See [design](docs/DESIGN.md) and [Task Scheduler details](docs/TASK-SCHEDULER.md).
No software license has been added.

## Wake-on-LAN limitation

A powered-off computer cannot run this manager. If the public IPv4 changes
while it is off, DuckDNS can remain stale until the computer runs again. An
always-on device is needed to maintain the record during that interval.
