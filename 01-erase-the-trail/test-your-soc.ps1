# TEST YOUR SOC — run on a machine you own. Safe: Windows recreates the file.
# STEP 1 — leave something in the history worth erasing.
whoami; Get-Process | Select-Object -First 1 | Out-Null

# STEP 2 — Medusa's move, with the path written out: delete the PowerShell history file on disk.
Remove-Item -Force $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# STEP 3 — open your SOC / EDR. Did anything alert on the deletion?
# Nothing to clean up. A new history file is created automatically.
