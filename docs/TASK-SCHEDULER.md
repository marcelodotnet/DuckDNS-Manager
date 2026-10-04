# Task Scheduler

Task definitions are created and inspected through native Task Scheduler COM
(`Schedule.Service`). COM task definitions use the Windows Task Scheduler XML
schema internally; exported XML text is not used as a health fingerprint.

Folder: `\DuckDNS Manager\`

| Task | Trigger | Default configuration |
| --- | --- | --- |
| DuckDNS Manager - Startup | BootTrigger | Fixed Delay PT20S; no RandomDelay |
| DuckDNS Manager - Network | EventTrigger | NetworkProfile Operational event 10000 |
| DuckDNS Manager - Periodic | TimeTrigger | PT30M repetition, Duration omitted/empty, indefinite |

The periodic StartBoundary is set to now plus its configured interval at task
creation/repair. Repetition has no finite duration, no end boundary and
StopAtDurationEnd false. Startup delay and periodic interval remain configurable.

The event subscription is:

```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">
    <Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000)]]</Select>
  </Query>
</QueryList>
```

## Shared settings

| Setting | Value |
| --- | --- |
| Principal | SYSTEM / NT AUTHORITY\SYSTEM / S-1-5-18 |
| Logon type | ServiceAccount (5) |
| Run level | Highest (1) |
| MultipleInstancesPolicy | IgnoreNew (2) |
| ExecutionTimeLimit | PT5M |
| StartWhenAvailable | true |
| DisallowStartIfOnBatteries | false |
| StopIfGoingOnBatteries | false |
| RunOnlyIfNetworkAvailable | false |
| Hidden task | false |
| AllowDemandStart | true |
| RestartCount | 0 |
| Enabled | Mirrors the corresponding configuration switch |

There is one enabled trigger per task; disabling a schedule disables the task.
Its trigger definition remains available for validation and later re-enabling.

The Exec action launches:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\DuckDNS\DuckDNS-Manager.ps1" -Scheduled -Reason <Startup|Network|Periodic>
```

Paths are derived from SystemRoot and ProgramData. The PowerShell window is
hidden while the task itself is visible in Task Scheduler. Scheduled mode never
shows a menu, waits for keyboard input or requests elevation.

## Health and repair

Health compares principal, logon type, run level, enabled state, action path,
argument meaning, trigger count/type/settings, boot delay, event subscription,
periodic repetition, instance policy, time limit and relevant shared settings.
Durations are parsed as TimeSpan values. Event subscriptions are parsed and
normalized for their channel/event filter. Action arguments tolerate equivalent
whitespace, quoting and supported option ordering. Irrelevant exported XML
formatting/element ordering does not make a task unhealthy.

Repair preserves a healthy task; otherwise it creates/replaces the definition
and verifies the result. Registration uses CREATE_OR_UPDATE (6), SYSTEM and
ServiceAccount (5). A failure remains visible as Needs repair.

IgnoreNew only prevents concurrent instances of the same task. Different tasks
and manual runs still share the exclusive run.lock. A competing run exits 0
without changing saved state. Setup retains this lock through its first check.
The application checks its 240-second budget and tries to finish/persist before
the Task Scheduler 300-second hard termination.

## Windows integration checklist

Run on Windows PowerShell 5.1 with administrator access: install all three tasks,
inspect principal/action/settings, validate and repair a deliberately altered
task, verify fixed boot delay, reconnect event and indefinite periodic execution,
confirm SYSTEM can decrypt token.dat, and measure timeout/lock behavior across
different triggers. These real COM/OS tests have not been executed on Linux.

## Native references

- [BootTrigger.Delay](https://learn.microsoft.com/en-us/windows/win32/taskschd/boottrigger-delay)
- [RepetitionPattern.Duration](https://learn.microsoft.com/en-us/windows/win32/taskschd/repetitionpattern-duration)
- [ITaskFolder.RegisterTaskDefinition](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-registertaskdefinition)
