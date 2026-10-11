# Would you know if an attacker read your audit policy?

Before switching logging off, an attacker first checks what is being logged. Is that command logged?

- Test page: https://cyray.io/test-your-soc/blind-audit-policy-enumeration
- Where to run it: a test Windows machine you own

Run on a test machine you own, as an administrator.

First, save your current audit policy; at the end, put it back:

```bat
auditpol /backup /file:C:\Temp\orig-audit.csv
auditpol /restore /file:C:\Temp\orig-audit.csv
```

## Simulation (harmless, read-only)

```bat
auditpol /get /category:*
```

Cleanup: none needed.

## Event it should produce

- Security event 4688 (process creation), NewProcessName auditpol.exe, plus the full command line.
- By default the lab saw 0 events for this command.

## Is the source even on?

```bat
auditpol /get /subcategory:"Process Creation"
```

"No Auditing" means Windows does not write process-creation events, so this command leaves no trace in your SIEM.

## Settings to enable

```bat
auditpol /set /subcategory:"Process Creation" /success:enable
```

Then, in PowerShell:

```bat
$P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-ItemProperty -Path $P -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null
```

The registry value adds the command line to the event. Without it the field is empty. With both on, the lab saw 4688 for auditpol.exe with the command line. Noise: not measured.

## The rule that catches it

CyRay rule "Audit Policy Enumerated". Its condition matches this logged command: the process ends in auditpol.exe and the command line contains "get".

## Revert

```bat
auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable
```

Then, in PowerShell:

```bat
Remove-ItemProperty -Path $P -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
```

If the value existed before you started, do not remove it. Or restore your saved policy (see "Before you start").

## Detection logic

This page describes the rule condition in words only; it has no Sigma rule, so none is included here.
