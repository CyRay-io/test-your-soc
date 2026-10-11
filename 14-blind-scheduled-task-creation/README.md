# Does your SIEM ever see a new scheduled task?

Windows will not log a created scheduled task until you switch one audit setting on.

- Test page: https://cyray.io/test-your-soc/blind-scheduled-task-creation
- Where to run it: a test Windows machine you own

Run on a test machine you own, as an administrator.

First, save your current audit policy; at the end, put it back:

```bat
auditpol /backup /file:C:\Temp\orig-audit.csv
auditpol /restore /file:C:\Temp\orig-audit.csv
```

## Simulation (harmless)

```bat
schtasks /create /tn TysDemo /tr "cmd /c exit" /sc onlogon /ru SYSTEM /f
```

The task does nothing but exit. Delete it right after the test.

Cleanup:

```bat
schtasks /delete /tn TysDemo /f
```

## Event it should produce

- Security event 4698 "A scheduled task was created".
- Lab saw: TaskName, TaskContent (the task XML), and the Subject fields.

## Is the source even on?

```bat
auditpol /get /subcategory:"Other Object Access Events"
```

"No Auditing" means Windows is not writing this event at all. Nothing reaches your SIEM, whatever rules it has. Lab read "No Auditing" by default on Windows 11 and on two Server domain controllers. With it off, the schtasks command above produced no 4698.

## Setting to enable

```bat
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

With it on, the same command produced one 4698. Noise: about 2.3 events per hour (event 4702, task updated) on an idle member server. Other machine types: not measured.

## The rule that catches it

CyRay rule "Scheduled Task Creation". Its condition matches this logged event: any Security 4698, except CyRay’s own agent task and tasks a customer has excluded.

## Revert

```bat
auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable
schtasks /delete /tn TysDemo /f
```

## Detection logic

This page describes the rule condition in words only; it has no Sigma rule, so none is included here.
