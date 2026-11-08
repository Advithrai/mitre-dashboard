"""
make_synthetic.py  -  writes a SYNTHETIC test file in the Wazuh/Sysmon format.

Run anywhere:  python make_synthetic.py

IMPORTANT: this is NOT the Windows-APT 2025 dataset. It is a made-up lab:
new computer names (lab-pc-01, lab-pc-02), today's date, new process IDs.
The "activity" is ordinary Windows administration (listing user accounts,
reading a registry value, loading a system library, a DNS lookup). Nothing
here is malware and nothing runs; it is only rows of text in the shape the
dashboard expects, so we can show the dashboard works on a file that did not
come from the dataset.

Outputs (in the folder you run it from):
  synthetic_lab_test.csv          -> upload this in the dashboard
  synthetic_lab_answer_key.csv    -> the technique each activity maps to
  csv_template.csv                -> empty template + 2 example rows
"""
import hashlib
import uuid
from datetime import datetime, timedelta

import pandas as pd

P = "_source.data.win.eventdata."
COLS = ["_source.@timestamp", "_source.agent.name", "_source.rule.id",
        "_source.rule.description", "_source.rule.mitre.id",
        "_source.data.win.system.eventID",
        P + "image", P + "parentImage", P + "commandLine",
        P + "processGuid", P + "parentProcessGuid", P + "sourceProcessGUID",
        P + "targetFilename", P + "targetObject", P + "imageLoaded",
        P + "destinationPort", P + "targetImage", P + "queryName"]

SYS = "C:\\Windows\\System32\\"
# The dashboard treats a row as an "attack command" when its parent program is
# the agent. We reuse the same two agent names the model was trained on.
AGENTS = {"lab-pc-01": "C:\\Users\\Public\\splunkd.exe",
          "lab-pc-02": "C:\\Users\\Public\\caldera-agent3.exe"}

# Wazuh rules for the common Sysmon events (number, description)
RULE = {"1": ("61603", "Sysmon - Event 1: Process creation"),
        "3": ("61605", "Sysmon - Event 3: Network connection"),
        "7": ("61607", "Sysmon - Event 7: Image loaded"),
        "11": ("61613", "Sysmon - Event 11: File created"),
        "13": ("61615", "Sysmon - Event 13: Registry value set"),
        "22": ("61650", "Sysmon - Event 22: DNS query")}

# One activity per technique. Each has: the tool launched, a short benign
# command, the follow-on programs, and the artifacts (files/registry/etc.).
# These are standard administration actions, described plainly.
ACTIVITIES = [
    {"tech": "T1087.001", "tool": "cmd.exe", "cmd": "list local user accounts",
     "children": [("net.exe", "net user"), ("net1.exe", "net1 user")], "art": []},
    {"tech": "T1069.001", "tool": "cmd.exe", "cmd": "list the administrators group",
     "children": [("net.exe", "net localgroup administrators"),
                  ("net1.exe", "net1 localgroup administrators")], "art": []},
    {"tech": "T1082", "tool": "cmd.exe", "cmd": "show system information",
     "children": [("systeminfo.exe", "systeminfo")], "art": []},
    {"tech": "T1016", "tool": "cmd.exe", "cmd": "show network configuration",
     "children": [("ipconfig.exe", "ipconfig /all")], "art": []},
    {"tech": "T1112", "tool": "cmd.exe", "cmd": "set a registry value",
     "children": [("reg.exe", "reg add value")],
     "art": [("13", "targetObject", "HKCU\\Software\\DemoLab\\Mode")]},
    {"tech": "T1518.001", "tool": "cmd.exe", "cmd": "check installed security software",
     "children": [("reg.exe", "reg query software")],
     "art": [("13", "targetObject", "HKLM\\Software\\Microsoft\\Windows Defender\\Status")]},
    {"tech": "T1057", "tool": "cmd.exe", "cmd": "list running processes",
     "children": [("tasklist.exe", "tasklist")], "art": []},
    {"tech": "T1033", "tool": "cmd.exe", "cmd": "show the current user",
     "children": [("whoami.exe", "whoami")], "art": []},
    {"tech": "T1007", "tool": "cmd.exe", "cmd": "list system services",
     "children": [("sc.exe", "sc query")], "art": []},
    {"tech": "T1049", "tool": "cmd.exe", "cmd": "list network connections",
     "children": [("netstat.exe", "netstat -ano")],
     "art": [("3", "destinationPort", "445")]},
    {"tech": "T1518", "tool": "cmd.exe", "cmd": "list installed programs",
     "children": [("wmic.exe", "wmic product get name")], "art": []},
    {"tech": "T1046", "tool": "cmd.exe", "cmd": "check a remote port",
     "children": [("curl.exe", "curl connectivity check")],
     "art": [("3", "destinationPort", "8080"),
             ("22", "queryName", "update.example.com")]},
]


def guid():
    return "{" + str(uuid.uuid4()).upper() + "}"


def sha1(s):
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def main():
    rows, key = [], []
    start = datetime(2026, 10, 27, 10, 0, 0)
    t = start
    rep = 3                                   # each activity runs 3 times, split across the 2 PCs

    def blank():
        return {c: "" for c in COLS}

    def add(agent, event, image, parent, cmd="", guid_=None, parent_guid=None, art_field=None,
            art_val=None, src_guid=None):
        rid, desc = RULE[event]
        r = blank()
        r["_source.@timestamp"] = t.strftime("%b %-d, 2026 @ %H:%M:%S.000")
        r["_source.agent.name"] = agent
        r["_source.rule.id"] = rid
        r["_source.rule.description"] = desc
        r["_source.data.win.system.eventID"] = event
        r[P + "image"] = image
        r[P + "parentImage"] = parent
        r[P + "commandLine"] = cmd
        r[P + "processGuid"] = guid_ or guid()
        r[P + "parentProcessGuid"] = parent_guid or ""
        if src_guid:
            r[P + "sourceProcessGUID"] = src_guid
        if art_field:
            r[art_field] = art_val
        rows.append(r)
        return r[P + "processGuid"]

    for i in range(rep):
        for act in ACTIVITIES:
            agent = list(AGENTS)[(i + ACTIVITIES.index(act)) % 2]
            agent_img = AGENTS[agent]
            # 1. the launch row: agent starts the tool  -> this is one "attack command"
            launch_cmd = act["cmd"]
            g_launch = add(agent, "1", SYS + act["tool"], agent_img, cmd=launch_cmd,
                           parent_guid=guid())
            key.append({"agent": agent,
                        "ts": rows[-1]["_source.@timestamp"],
                        "cmd_sha1": sha1(launch_cmd),
                        "true_technique": act["tech"],
                        "brand_new_attack": "true"})
            t += timedelta(seconds=3)
            # 2. child programs
            last = g_launch
            for img, ccmd in act["children"]:
                last = add(agent, "1", SYS + img, SYS + act["tool"], cmd=ccmd,
                           parent_guid=g_launch)
                t += timedelta(seconds=1)
            # 3. artifacts (file/registry/network/DNS), attached to the last child
            for event, field, val in act["art"]:
                add(agent, event, SYS + act["children"][-1][0], SYS + act["tool"],
                    guid_=last, art_field=P + field, art_val=val)
                t += timedelta(seconds=1)
            t += timedelta(seconds=30)        # gap before the next activity

    # background noise so the file looks realistic (not attack rows)
    for i in range(120):
        r = blank()
        r["_source.@timestamp"] = (start + timedelta(seconds=i * 7)).strftime(
            "%b %-d, 2026 @ %H:%M:%S.000")
        r["_source.agent.name"] = "lab-pc-01" if i % 2 else "lab-pc-02"
        r["_source.rule.id"] = "61603"
        r["_source.rule.description"] = "Sysmon - Event 1: Process creation"
        r["_source.data.win.system.eventID"] = "1"
        r[P + "image"] = SYS + "svchost.exe"
        r[P + "parentImage"] = SYS + "services.exe"
        r[P + "processGuid"] = guid()
        rows.append(r)

    df = pd.DataFrame(rows, columns=COLS)
    df.to_csv("synthetic_lab_test.csv", index=False)
    pd.DataFrame(key).to_csv("synthetic_lab_answer_key.csv", index=False)

    # a small template people can copy
    tmpl = pd.DataFrame(rows[:2], columns=COLS)
    tmpl.to_csv("csv_template.csv", index=False)

    print("Wrote synthetic_lab_test.csv:", len(df), "rows,", len(COLS), "columns")
    print("Wrote synthetic_lab_answer_key.csv:", len(key), "attack commands")
    print("Wrote csv_template.csv (2 example rows)")
    print("\nThis file is SYNTHETIC: new hosts (lab-pc-01/02), date 27 Oct 2026, "
          "ordinary admin activity. Not from the dataset, not malware.")


if __name__ == "__main__":
    main()
