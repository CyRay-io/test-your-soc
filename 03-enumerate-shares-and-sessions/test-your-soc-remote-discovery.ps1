# test-your-soc-remote-discovery.ps1 — run on a machine you own.
# Safe: read-only enumeration. Nothing is changed, nothing to undo.
# STEP 1 - list the shares and sessions visible from this machine.
net view
# STEP 2 - the broader sweep an intruder runs to see everything reachable.
net view /all
# STEP 3 - open your SOC / EDR. Did share/session enumeration alert?
