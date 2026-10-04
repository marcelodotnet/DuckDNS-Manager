# Design

## Architecture and compatibility

Version 1.1.0 is one primary ASCII-only PowerShell script targeting Windows
PowerShell 5.1 and .NET Framework. Native COM Task Scheduler, DPAPI, filesystem
ACLs, Resolve-DnsName and HTTPS implement the runtime. No service, GUI, modules,
IPv6 updater, multiple profiles or internet self-updater are included.

`C:\ProgramData\DuckDNS\` holds the installed script, config, encrypted token,
state, global lock, recovery files and optional logs. Console pages retain
status markers, dynamic dotted alignment and `[0] Back`; DNS Settings and the
requested reliability/diagnostic rows extend the existing interface.

## Configuration schema 2

See `examples/config.example.json`. `Dns.Mode` is System or Manual. Manual
requires an IPv4 `Dns.ManualServer`. System defaults to null manual server.
Existing schema 1 is accepted for migration, not written by new configuration
changes. Its default ValidationDns `1.1.1.1` maps to System; another address maps
to Manual. Migration executes under the same exclusive lock and preserves a
validated schema 1 copy in `config.previous.json` before atomic replacement.
Every later valid configuration replacement refreshes that one previous copy.
The manager never silently restores the backup or changes the token in migration.

## State and history

State contains Domain, LastCheckUtc, LastSuccessfulCheckUtc,
LastSuccessfulUpdateUtc, LastReason, LastResult, LastDetectedPublicIPv4,
DuckDnsIPv4, SynchronizationState, LastExitCode, ConsecutiveFailures,
ApplicationVersion, LastStateRecoveryUtc and LastStateRecoveryReason.

SynchronizationState is Unknown, Synchronized, Pending, Accepted or Failed.
LastSuccessfulUpdateUtc means an API request was accepted, including NOCHANGE.
It is independent of DNS confirmation. LastSuccessfulCheckUtc advances after a
meaningful successful DDNS check: already matching DNS, confirmed update,
accepted update with validation off, or propagation pending after acceptance.
Failures preserve that timestamp and increment ConsecutiveFailures; a success
resets the counter. Skips for contention/debounce change neither field.
Credential changes record their validation result separately from the full
check success/failure accounting and never imply DNS confirmation.

A domain change clears domain-specific IP, synchronization, check, API and
result history. It retains the configured token and automation. The prior API
timestamp cannot make a forced call eligible for the new domain. Views and the
update flow also guard against a mismatched state domain.

## Lock and installation

`run.lock` is opened with FileShare.None; ownership is the live exclusive file
handle, not the presence or age of the file. There is no indefinite wait.
All successful acquisitions release through finally. Changes to configuration,
token, tasks and saved state use this same lock.

Setup collects input and completes UAC before locking. A minimal directory/ACL
bootstrap allows the lock file to exist. Once locked, it secures the runtime,
creates config/token/state, installs the script, creates tasks, performs the
initial check and any needed API credential validation, persists final state,
then releases the lock before opening the dashboard. A scheduled task that
starts during setup exits 0 silently without changing state.

Network runs may skip within 15 seconds of a successful meaningful check only
when the latest result is still successful and state is valid. A recent failed
check does not suppress an event indicating newly available connectivity.

## State recovery

Read results carry transient Missing, Valid, InvalidJson or ReadError metadata,
plus explicit history/persistence flags. These flags never enter status JSON.

- Missing: a normal empty state; history starts with Never.
- Valid: validate known state fields and read legacy state with new defaults.
- InvalidJson: read-only views report invalid state. Under the lock, rename the
  original to `status.corrupt-YYYYMMDDTHHMMSSZ.json` without overwriting a backup,
  secure it, and create clean state with recovery time/reason. Collisions advance
  the filename timestamp until a free name is found.
- ReadError: preserve the file and report unknown history. Current IP/DNS/API
  work can continue safely; forced-update eligibility is disabled, and Save-State
  refuses to overwrite it. The run returns state failure code 15.

Recovery evidence is retained across normal checks. Full Diagnostics reports
recovery within the previous 24 hours. Clear Saved State resets state and deletes
`status.corrupt-*.json`. This pattern and config.previous.json are manager-owned;
Uninstall removes them without deleting unrelated content.

## DNS resolution

System mode queries Resolve-DnsName with Type A, DnsOnly and NoHostsFile and
without Server. It never queries Cloudflare/Google automatically.

Manual mode queries the configured address, then internal constants `1.1.1.1`
and `8.8.8.8` after genuine resolver failures. Duplicate addresses are queried
only once per chain. Valid empty A results, DNS_INFO_NO_RECORDS (9501) and
DNS_ERROR_RCODE_NAME_ERROR (9003) are valid no-A outcomes and stop fallback.
Other errors remain failures. Queries use QuickTimeout and budget checks;
Windows integration must verify actual native error and timeout behavior.
Resolver diagnostics can inspect the full relevant chain without using fallback
answers to override an earlier valid no-A answer.

## Public IPv4 and decisions

Every provider result is strictly validated as public IPv4, excluding private,
loopback, link-local, shared, multicast and selected reserved/documentation ranges.
Normal discovery checks ipify, icanhazip and Amazon sequentially until a valid IP.

1. Check local token protection and discover IPv4.
2. If comparison is enabled, resolve the current domain. Total resolver failure
   prevents an API call. A valid no-A answer permits initial synchronization.
3. If DNS already matches, skip additional providers and the API unless Forced
   Update is enabled and due from known history.
4. If a new address would be published, require agreement from two different
   providers; the third provider resolves disagreement. No consensus means no API
   call. Comparison disabled requires consensus for each proposed update.
5. A recent accepted address still awaiting propagation is checked through DNS,
   but further provider confirmation/API calls are suppressed for five minutes.
6. Parse API OK, NOCHANGE or explicit KO. Malformed output is an API failure,
   not proof of credential rejection. HTTP exceptions remain sanitized.
7. Validation off records Accepted. Validation on polls DNS up to three times:
   matching IPv4 records Synchronized; otherwise records Pending.
8. Finalize timestamps/failure count and atomically persist state.

Setup also sends a single validation request when an already-matching DNS result
would otherwise leave the token untested. If DNS comparison itself fails, online
validation remains pending to preserve the no-blind-update rule. Change Token
saves first, confirms the public address through providers, then attempts a single
API validation request. The token is retained on rejection/network failure.

## Time budget and errors

A monotonic Stopwatch supplies a 240-second internal budget for an update,
setup's initial network work, token validation or a diagnostic operation. Every
HTTP/DNS attempt checks a reserve before starting and checks elapsed time after
return; sleeps check their full duration. HTTP requests have an 8-second timeout
and DNS uses QuickTimeout. Reaching the budget produces code 16, attempts state
persistence and releases the lock. Native network operations can finish after
the budget boundary; Windows tests must measure their actual timing. Task
Scheduler's PT5M is the final hard stop, not the normal timeout path.

Configuration/token/public-IP/DNS/API/state errors have dedicated codes 10-15;
unexpected failures use 99. State access/persistence failure takes precedence
when the result cannot be saved. Propagation pending and execution skips use 0.

## Security and atomic writes

DPAPI LocalMachine protects token.dat, and the runtime ACL permits SYSTEM and
BUILTIN Administrators. Runtime ACL diagnostics verify protected access rules
on the directory and token. Local administrators remain trusted; this is not a
boundary against an administrator of the computer.

The application never prints/logs the token or complete update URL. HTTP
exception text is suppressed because it can carry credentials. Configuration,
state, backups and sanitized logs do not receive the token. Recovery artifacts
preserve state bytes only; no credential is inserted into state.

Atomic writes create a same-directory temporary file, fully write it, validate
JSON from that file, secure its ACL, then Replace the existing destination or
Move for first creation. The live file is never truncated. Temporary files are
removed in finally when possible. State/config serialization is validated before
replacement. Known-good configuration backup is committed before the new live
configuration is installed.

## Regression boundary

`tests/Regression.ps1` uses temporary filesystem data and mocked Windows/network
boundaries. It validates logic and simulated task semantics without installing
or updating a real hostname. Linux PowerShell execution does not establish
Windows PowerShell 5.1, native COM/DPAPI/ACL or network-event integration correctness.
