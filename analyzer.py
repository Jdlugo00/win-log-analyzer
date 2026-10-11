from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

log_path = "/Users/justinlugo/Desktop/github_projects/EVTX-ATTACK-SAMPLES/Credential Access/sysmon_13_keylogger_directx.evtx"

with Evtx(log_path) as log:
    for record in log.records():
        xml_text = record.xml()
        root = ET.fromstring(xml_text)
        event_id_tag = root.find("e:System/e:EventID", ns)
        print(event_id_tag.text)
        break