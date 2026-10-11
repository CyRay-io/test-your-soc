# Hard links hide files in plain sight. Does your SIEM see one made?

This event needs two things switched on, not one.

- Test page: https://cyray.io/test-your-soc/blind-hard-link-creation
- Where to run it: a test Windows machine you own

Run on a test machine you own, as an administrator.

First, save your current audit policy; at the end, put it back:

```bat
auditpol /backup /file:C:\Temp\orig-audit.csv
auditpol /restore /file:C:\Temp\orig-audit.csv
```

## Is the source even on?

```bat
auditpol /get /subcategory:"File System"
```

"No Auditing" means Windows writes no file-system audit events. Even with it on, an audit rule (SACL) on the folder is also required. The event only appears when both are in place.

## Settings to enable

Turn on File System audit plus a SACL on the folder, then test:

```bat
mkdir C:\TysTest
```

```bat
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

Then the SACL on the test folder, in PowerShell:

```bat
$D = 'C:\TysTest'
$acl = Get-Acl $D -Audit
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','Modify,Delete,CreateFiles,WriteData,AppendData','ContainerInherit,ObjectInherit','None','Success,Failure')
$acl.AddAuditRule($rule); Set-Acl $D $acl
```

Noise: not measured. File-system auditing can be heavy; keep the SACL on a small test folder.

## Simulation (harmless)

```bat
echo x > C:\TysTest\a.txt
fsutil hardlink create C:\TysTest\b.txt C:\TysTest\a.txt
```

Cleanup:

```bat
rmdir /s /q C:\TysTest
```

## Event it should produce

- Security event 4664 "An attempt was made to create a hard link".
- Lab saw: File Name and Link Name.
- By default the lab saw 0 events.

## The rule that catches it

CyRay rule "NTFS Hard Link Creation". Its condition matches this logged event: Security 4664 with a file name present. It sees the event only when File System auditing and a SACL exist.

## Revert

```bat
auditpol /set /subcategory:"File System" /success:disable /failure:disable
```

Remove the SACL, in PowerShell (this removes every audit rule on that folder):

```bat
$acl = Get-Acl $D -Audit
$acl.Audit | %{ [void]$acl.RemoveAuditRuleAll($_) }; Set-Acl $D $acl
```

Then delete the test folder with the cleanup line above.

## Detection logic

This page describes the rule condition in words only; it has no Sigma rule, so none is included here.
