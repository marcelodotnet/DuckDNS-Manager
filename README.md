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

3. Accept the administrator/UAC prompt, enter your DuckDNS subdomain or full
   hostname, and enter a fresh token at the hidden prompt.
4. Review setup, then open **Status** or **Diagnostics** in the dashboard.

The manager installs into `C:\ProgramData\DuckDNS\`. Setup creates three tasks,
performs the initial check and attempts real API validation, including when DNS
already matches. A network outage may leave validation pending while setup
completes. A securely saved token is retained if validation is unavailable or
DuckDNS rejects the request. A rejected request needs investigation; a saved
or decryptable token alone does not prove API acceptance.

## Default behavior

| Setting | Default |
| --- | --- |
| Compare public IPv4 with DuckDNS A record | On |
| Post-update DNS validation | On |
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
| `config.json` | Non-sensitive schema 2 configuration |
| `config.previous.json` | One valid previous configuration; no automatic restore |
| `token.dat` | Token encrypted with Windows DPAPI LocalMachine |
| `status.json` | Check/API history, result, failure count, version and recovery evidence |
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
Schema 1 migrates automatically under the lock: old default `1.1.1.1` becomes
System mode; a custom resolver becomes Manual mode. Other settings and token
are preserved.

Invalid readable state is renamed without overwriting a backup, and a new
valid state records recovery evidence. Read errors preserve the original file;
current IP/DNS checks may proceed, but state cannot be overwritten and the run
reports exit code 15. Status shows unknown history rather than inventing dates.
**Clear Saved State** resets state and removes manager-owned corrupt backups.
Changing the domain clears the previous domain's history, including forced
update eligibility, while preserving token, configuration and tasks.

## Diagnostics and maintenance

Full Diagnostics groups configuration/security, network and automation checks.
It reports actual resolver use, runtime ACL health, saved-state health and task
configuration. Diagnostics only check local token protection; they do not prove
DuckDNS credential acceptance. Change Token performs one API validation request
with a confirmed current IPv4 when available.

Maintenance repairs tasks, restores defaults while preserving domain/token,
opens the runtime folder or Task Scheduler, clears state/logs, and uninstalls.
Restore Defaults returns DNS to System mode. Uninstall removes only manager-owned
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
| 12 | Public IPv4 unavailable or change unconfirmed |
| 13 | DNS comparison failed |
| 14 | DuckDNS request rejected, failed or malformed |
| 15 | State inaccessible or could not be persisted |
| 16 | Internal execution timeout |
| 99 | Unexpected internal error |

## Tests and validation

Run the safe mock regression suite with:

```powershell
powershell.exe -NoProfile -File .\tests\Regression.ps1
```

The suite uses temporary files and mock Windows/network boundaries; it never
calls the real DuckDNS API. Parser and 78 assertions passed on PowerShell
7.4.13/Linux during development, including migration, atomic writes, lock
contention, state recovery/read errors, provider consensus, DNS selection,
timeout handling, failure transitions, debounce and simulated task validation.
Compatibility with PowerShell 5.1 was reviewed statically. Actual Windows
PowerShell 5.1, DPAPI, ACL behavior, native DNS timeout/error behavior and Task
Scheduler creation/repair/trigger execution require Windows integration tests.
No production credential was used for testing.

See [design](docs/DESIGN.md) and [Task Scheduler details](docs/TASK-SCHEDULER.md).
No software license has been added.

## Wake-on-LAN limitation

A powered-off computer cannot run this manager. If the public IPv4 changes
while it is off, DuckDNS can remain stale until the computer runs again. An
always-on device is needed to maintain the record during that interval.
