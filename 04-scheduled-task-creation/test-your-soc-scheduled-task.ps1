# test-your-soc-scheduled-task.ps1 — run on a machine you own.
# Safe: creates one harmless task that only exits, then deletes it. Runs as you, no admin.
# STEP 1 - the real persistence move: register a scheduled task via schtasks.
schtasks /create /tn "CyRaySOCTest" /tr "cmd /c exit" /sc once /st 23:59 /f
# STEP 2 - open your SOC / EDR. Did scheduled-task creation alert?
# STEP 3 - clean up: delete exactly the task this script created.
schtasks /delete /tn "CyRaySOCTest" /f
