from Evtx.Evtx import Evtx

log_path = "/Users/justinlugo/Desktop/github_projects/EVTX-ATTACK-SAMPLES/Credential Access/sysmon_13_keylogger_directx.evtx"

with Evtx(log_path) as log:
    for record in log.records():
        print (record.xml())
        break