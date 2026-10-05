# Design

## Architecture and compatibility

Version 1.3.0 is one primary ASCII-only PowerShell script targeting Windows
PowerShell 5.1 and .NET Framework. Native COM Task Scheduler, DPAPI, filesystem
ACLs, Resolve-DnsName and HTTPS implement the runtime. No service, GUI, modules,
IPv6 updater, multiple profiles or internet self-updater are included.

`C:\ProgramData\DuckDNS\` holds the installed script, config, encrypted token,
state, global lock, recovery files and optional logs. Console pages retain
status markers, dynamic dotted alignment and `[0] Back`; DNS Settings and the
requested reliability/diagnostic rows extend the existing interface.

## Configuration schema 3

See `examples/config.example.json`. Canonical `Hostname` is a normalized single
DNS label. Inputs may carry `.duckdns.org`, but storage cannot; `Get-DuckDnsDomain`
derives the fixed FQDN for DNS and display. API `domains` receives bare Hostname.
Schema 3 rejects a canonical Domain field or noncanonical hostname.

`Dns.Mode` is System or Manual; Manual requires an IPv4 `ManualServer`.
`NetworkInterface.Mode` is Automatic or Specific. Automatic requires null
`InterfaceGuid`; Specific requires a nonempty stable GUID. Alias/index/source IP
are transient and never become the configured identity.

Schemas 1 and 2 are validated before conversion. Domain becomes Hostname. Schema
1 default ValidationDns `1.1.1.1` maps to System; another address maps to Manual.
Schema 2 DNS and all operational settings remain intact. Interface defaults to
Automatic. Migration writes under run.lock, preserves one validated old schema
copy in `config.previous.json`, atomically installs schema 3 and leaves token.dat,
logs and applicable state intact. Later saves refresh that one previous copy.
There is no automatic backup restore.

## Credential verification lifecycle

The single Credentials line combines local DPAPI readability and actual API
acceptance/rejection for the current Hostname + Token. Protection or DNS alone
never proves acceptance. State adds CredentialStatus (Pending/Verified/Rejected),
CredentialHostname, an opaque CredentialVerificationId and
LastCredentialVerificationUtc. Legacy state defaults to Pending.

`credentials.dat` is an atomic DPAPI LocalMachine receipt containing that ID,
hostname, result and SHA256 identity of the protected token file. The ciphertext
identity never enters plaintext state, console or logs. It identifies the exact
protected file without copying the plaintext token. Receipt/ID/current-file
mismatch or receipt read failure yields Pending; local token failure yields
Unavailable. Only an API OK/KO can create a new receipt. The API captures the
file identity before reading the current token; changed identity at receipt
creation cannot mark the replacement verified. A receipt is written before the
state ID; incomplete persistence cannot revive an older accepted result.

Hostname edits clear domain-specific history and verification under the lock.
Token edits persist Pending before replacing token.dat, then run a check with
one API attempt. A failed request retains the token. Explicit KO records
Rejected; malformed/network replies do not establish rejection. Current accepted
verification survives a later transient service failure. A matching-DNS check
uses one validation request while credentials are pending, without extra provider
queries. Once verified, unchanged normal checks skip the API. Genuine DNS failure
still blocks the call. An unreadable state cannot trigger an extra matching-DNS
credential validation or forced update.

## Interface-bound public IP discovery

.NET interface GUIDs supply stable identity, including usable PPP/tunnel devices.
Only operationally Up interfaces with preferred, non-SkipAsSource local IPv4
addresses are offered. Loopback, link-local, unspecified and multicast sources
are excluded. Private/VPN addresses are valid sources. Optional native adapter
metadata identifies virtual devices; names never decide identity or eligibility.

A run resolves one immutable context (GUID, current index, alias and source IPv4).
Every provider in discovery and consensus uses that context. Before and after
each call, the GUID/index/source must still be usable. A missing GUID, down
adapter or DHCP change in flight invalidates the attempt and yields code 12,
without an API call or fallback to Automatic. The next run resolves current DHCP
and index values. Confirmation rejects a context from a different configured
GUID/mode. Unconfirmed results never overwrite the known public/DuckDNS address.

Automatic uses the existing Invoke-WebRequest path. Specific uses HttpWebRequest
and ServicePoint.BindIPEndPointDelegate in a small in-memory C# helper compatible
with .NET Framework. The delegate executes native code without a PowerShell
runspace. Each call has a unique connection group, disables keep-alive, proxy
and redirects, bounds response size and binds an IPv4 endpoint with ephemeral
port. The ServicePoint is temporarily guarded; nested finally blocks close the
response/stream, abort the request, close the group and restore the previous
delegate even if disposal fails. No unbound pooled connection is reused. DNS
and DuckDNS API requests never use this helper. Routes/metrics/gateways remain
untouched. Windows firewall/VPN/host-routing behavior still requires integration
validation; connection failures never opt into another source.

Selection testing occurs before user confirmation without holding run.lock.
It requires bound discovery and provider consensus. Save then acquires the lock,
reads fresh config, checks the same tested GUID/index/address and changes only
NetworkInterface. Failed/stale/default-No choices preserve current settings.
Diagnostics claims Interface enforced only after a bound valid provider response;
Automatic reports Windows routing.

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
Credential verification and check results remain separate fields; API acceptance
never implies DNS confirmation. Token changes run the normal check accounting.

A hostname change clears domain-specific IP, synchronization, check, API and
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
3. If DNS already matches, skip additional providers. Skip the API when the current
   pair is verified and no Forced Update is due from known history.
4. If a new address would be published, require agreement from two different
   providers; the third provider resolves disagreement. No consensus means no API
   call. Comparison disabled requires consensus for each proposed update.
5. A recent accepted address with current verified credentials still awaiting propagation is checked through DNS,
   but further provider confirmation/API calls are suppressed for five minutes.
6. Parse API OK, NOCHANGE or explicit KO. Malformed output is an API failure,
   not proof of credential rejection. HTTP exceptions remain sanitized.
   Decode byte-array response content as UTF-8 before parsing, including when
   Windows PowerShell receives no Content-Type header. Strip an optional UTF-8
   byte-order mark and accept LF, CRLF or CR line endings. Empty/HTML responses
   remain invalid; their bodies are not displayed or persisted.
7. Validation off records Accepted. Validation on polls DNS up to three times:
   matching IPv4 records Synchronized; otherwise records Pending.
8. Finalize timestamps/failure count and atomically persist state.

Setup and Change Token use the shared check flow, holding the lock through
persistence and real verification. Matching DNS still allows one validation
request for a pending pair. DNS comparison failure blocks it. The protected
token is retained after network failure/rejection. Post-update validation off
always reports Accepted, including an accepted credential validation call.

Interactive opening performs a separate read-only observation before the first
dashboard: public IPv4 discovery respects interface selection, and A-record
resolution respects DNS selection even when update comparison is disabled. The
in-memory result supplies current addresses, comparison status and observation
time without calling the API or changing credentials/saved history. Failed reads
do not reuse saved addresses. A hostname/interface/DNS configuration key prevents
displaying observations for changed settings, and a subsequent update check
clears the observation. Scheduled entry bypasses this opening check.

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

API failures expose only fixed transport categories or numeric HTTP status codes.
Nested exceptions are inspected without copying their messages, URLs, headers
or response bodies. Task repair reports the failing operation and native HRESULT;
post-registration validation identifies the mismatched setting group.

## Security and atomic writes

DPAPI LocalMachine protects token.dat and credentials.dat, and the runtime ACL permits SYSTEM and
BUILTIN Administrators. Runtime ACL diagnostics verify protected access rules
on the directory, token and receipt when present. They identify the affected item
and distinguish enabled inheritance, unexpected allow rules, denied/incomplete
trusted permissions, missing trusted principals and sanitized read errors.
Local administrators remain trusted; this is not a
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

`tests/Regression.ps1` and `tests/Features.ps1` use temporary filesystem data and mocked Windows/network
boundaries. It validates logic and simulated task semantics without installing
or updating a real hostname. Linux PowerShell execution does not establish
Windows PowerShell 5.1, native COM/DPAPI/ACL or network-event integration correctness.

## Binding references

- [ServicePoint.BindIPEndPointDelegate (.NET Framework)](https://learn.microsoft.com/en-us/dotnet/api/system.net.servicepoint.bindipendpointdelegate?view=netframework-4.8.1)
- [Get-NetIPAddress source-address state](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress)
- [HttpWebRequest.AllowAutoRedirect](https://learn.microsoft.com/en-us/dotnet/api/system.net.httpwebrequest.allowautoredirect?view=netframework-4.8.1)
