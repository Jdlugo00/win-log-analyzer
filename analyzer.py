from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from pathlib import Path

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
samples_folder = Path("/Users/justinlugo/Desktop/github_projects/EVTX-ATTACK-SAMPLES")


def count_event_ids(log_path):
    """Return a dictionary of {event_id: count} for one .evtx file."""
    counts = {}
    with Evtx(str(log_path)) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            event_id = root.find("e:System/e:EventID", ns).text
            counts[event_id] = counts.get(event_id, 0) + 1
    return counts


files_checked = 0
files_failed = 0

for log_path in samples_folder.rglob("*.evtx"):
    files_checked += 1
    print(f"Checking {files_checked}: {log_path.name}", flush=True)
    try:
        counts = count_event_ids(log_path)
    except Exception as error:
        files_failed += 1
        print(f"Could not read {log_path.name}: {error}")
        continue

    if "4625" in counts:
        print(f"{counts['4625']:>5} failed logons  {log_path.name}")

print(f"\nChecked {files_checked} files, {files_failed} could not be read.")