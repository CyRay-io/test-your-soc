# Your SIEM sees PowerShell start. Does it see what PowerShell ran?

Windows does not record the text of an ordinary PowerShell command until you switch one policy on.

- Test page: https://cyray.io/test-your-soc/blind-powershell-script-block
- Where to run it: a test Windows machine you own

Run on a test machine you own, as an administrator.

First, save your current audit policy; at the end, put it back:

```bat
auditpol /backup /file:C:\Temp\orig-audit.csv
auditpol /restore /file:C:\Temp\orig-audit.csv
```

## Simulation (harmless)

```bat
powershell.exe -NoProfile -Command "Write-EventLog -LogName Application -Source 'x' -EventId 1 -RawData 1,2"
```

The command stops with an error on purpose (no message, unknown source), so it writes nothing to the Application log. Windows still records its text, which is the point.

Cleanup: none needed.

## Event it should produce

- Event 4104 in Microsoft-Windows-PowerShell/Operational, whose script block text is that exact line.
- As found (policy not set), the lab saw 0 such events.
- Windows still logs a few 4104 at Warning level for blocks it flags as suspicious. An ordinary command is not one of them.

## Is the source even on?

```bat
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -ErrorAction SilentlyContinue
```

No output means the policy is not set, so ordinary commands leave no text in your SIEM.

## Setting to enable

In PowerShell, as administrator:

```bat
New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force
New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force
```

With it on, the same command produced one 4104 with its text. Noise: 0 events in one idle 10-minute window. Real use will add one event per script block run.

## The rule that catches it

CyRay rule "PowerShell Write-EventLog Usage". Its condition matches this logged event: a 4104 whose script block text contains "Write-EventLog" and "-RawData ". Without the policy, there is no text to match.

## Revert

```bat
Remove-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Recurse -Force
```

If the policy was set before you started, do not remove it.

## Detection logic

This page describes the rule condition in words only; it has no Sigma rule, so none is included here.
