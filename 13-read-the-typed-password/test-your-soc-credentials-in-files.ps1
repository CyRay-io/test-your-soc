# test-your-soc-credentials-in-files.ps1 — run on a machine you own.
# Safe: reads your own PowerShell history file. Read-only, nothing changed, nothing to undo.
# STEP 1 - ask PowerShell where its own console history is kept.
powershell -NoProfile -Command "(Get-PSReadLineOption).HistorySavePath"
# STEP 2 - the actual technique: read that file, the way an intruder harvests typed secrets.
powershell -NoProfile -Command "Get-Content (Get-PSReadLineOption).HistorySavePath -Tail 20"
# STEP 3 - open your SOC / EDR. Did console history access alert?
