# Malware asks "am I in a sandbox?" Does your SIEM hear the question?

One reg.exe line checks for a VirtualBox key. Windows only logs it if process auditing is on.

- Test page: https://cyray.io/test-your-soc/blind-vm-check-registry
- Where to run it: a test Windows machine you own

Run on a test machine you own, as an administrator.

First, save your current audit policy; at the end, put it back:

```bat
auditpol /backup /file:C:\Temp\orig-audit.csv
auditpol /restore /file:C:\Temp\orig-audit.csv
```

## Simulation (harmless, read-only)

```bat
reg query HKLM\HARDWARE\ACPI\DSDT\VBOX__
```

Expect "unable to find" unless the machine is a VirtualBox guest. The event is logged either way, found or not.

Cleanup: none needed.

## Event it should produce

- Security event 4688, NewProcessName reg.exe, with the command line.
- By default the lab saw 0 events.

## Is the source even on?

```bat
auditpol /get /subcategory:"Process Creation"
```

"No Auditing" means no process-creation events are written, so this check is invisible.

## Settings to enable

Same two settings as the audit policy page: Process Creation success, and the command-line registry value.

Noise: not measured.

## The rule that catches it

CyRay rule "VM Environment Discovery Using Registry (Process)". Its condition matches this logged command: a registry "query" whose command line contains "vbox".

## Revert

Same revert as the audit policy page. No cleanup of the simulation is needed.

## Detection logic

This page describes the rule condition in words only; it has no Sigma rule, so none is included here.
