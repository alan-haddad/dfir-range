#!/usr/bin/env python3
"""
Instructor solver. SPOILERS: this file shows how every answer is derived.

Re-derives every answer from the generated evidence bundle alone: never from
the seed, the generator source or expected answers. CI runs it on fresh seeds
and then grades its output with the site's own checker, which proves every
module is solvable for every seed.

Standard library only. Usage:
    python3 -I tools/solver/solve.py <bundle_dir> <answers_out.json> [<decoded_out_dir>]
The optional decoded_out_dir receives decoded payloads so the inert-content
scan can check text that is hidden inside Base64 and XOR.
"""

import base64
import email
import email.policy
import json
import re
import socket
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def find_one(root: Path, pattern: str) -> Path:
    hits = sorted(root.glob(pattern))
    if len(hits) != 1:
        raise SystemExit(f"expected exactly one match for {pattern}, found {len(hits)}")
    return hits[0]


def opt(questions: dict, module: str, qid: str, predicate) -> str:
    q = next(q for q in questions["modules"][module]["questions"] if q["id"] == qid)
    matches = [o["id"] for o in q["options"] if predicate(o["label"])]
    if len(matches) != 1:
        raise SystemExit(f"{module}.{qid}: option predicate matched {len(matches)} options")
    return matches[0]


def sysmon_events(xml_path: Path) -> list:
    events = []
    for ev in ET.parse(xml_path).getroot().findall("e:Event", NS):
        eid = int(ev.find("e:System/e:EventID", NS).text)
        data = {d.get("Name"): (d.text or "") for d in ev.findall("e:EventData/e:Data", NS)}
        events.append({"id": eid, **data})
    return events


def main() -> None:
    bundle = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    decoded_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    questions = json.loads((bundle / "questions.json").read_text())
    answers: dict = {}
    decoded: dict = {}

    # ---- m01: encoded command -------------------------------------------
    events = sysmon_events(find_one(bundle, "*/logs/*Sysmon-Operational.xml"))
    enc = None
    for e in events:
        if e["id"] != 1 or not e["Image"].lower().endswith("powershell.exe"):
            continue
        m = re.search(r"\s-(?:e|ec|enc|encodedcomm\w*)\s+([A-Za-z0-9+/=]{40,})", e["CommandLine"], re.I)
        if m:
            enc = (e, m.group(1))
    if not enc:
        raise SystemExit("m01: no encoded PowerShell command found")
    raw = base64.b64decode(enc[1])
    assert raw[1] == 0, "expected UTF-16LE (null high bytes)"
    plain = raw.decode("utf-16-le")
    decoded["stage1-command.txt"] = plain
    url = re.search(r"'(https?://[^']+)'", plain).group(1)
    parent = enc[0]["ParentImage"].split("\\")[-1]
    answers["m01"] = {
        "url": url,
        "encoding": opt(questions, "m01", "encoding", lambda l: l == "UTF-16LE"),
        "parent": parent,
    }

    # ---- m02: obfuscated cradle -----------------------------------------
    script = find_one(bundle, "*/files/Users/*/AppData/Local/Temp/*.ps1.txt").read_text()
    cradle = next(line for line in script.splitlines() if re.search(r"\|\s*iex\b", line, re.I))
    used_vars = re.findall(r"\$\w+", cradle.split("|")[0])
    assigns = dict(re.findall(r"^(\$\w+)\s*=\s*'([^']*)'\s*$", script, re.M))
    host = next(assigns[v] for v in used_vars if v in assigns and not assigns[v].startswith("/"))
    ip = socket.inet_ntoa(socket.inet_aton(host))  # libc numbers-and-dots parser
    decoded["stage2-host.txt"] = f"{host} -> {ip}\n"
    answers["m02"] = {"ip": ip, "action": opt(questions, "m02", "action", lambda l: "in memory" in l)}

    # ---- m03: single-byte XOR config ------------------------------------
    blob = find_one(bundle, "*/files/ProgramData/*/settings.dat").read_bytes()
    key, cfg = None, None
    for k in range(1, 256):
        pt = bytes(b ^ k for b in blob)
        if b"http" in pt:
            try:
                cfg = json.loads(pt.decode("utf-8"))
                key = k
                break
            except (UnicodeDecodeError, ValueError):
                continue
    if key is None:
        raise SystemExit("m03: no key produced a JSON config containing http")
    decoded["settings.dat.decoded.json"] = json.dumps(cfg)
    answers["m03"] = {"key": f"0x{key:02x}", "c2": cfg["c2"]}

    # ---- m05: Mark-of-the-Web -------------------------------------------
    zone_text = find_one(bundle, "*/files/Users/*/Downloads/*_Zone.Identifier").read_text()
    zone = dict(line.split("=", 1) for line in zone_text.splitlines() if "=" in line)
    host_url = zone["HostUrl"]
    zone_names = {"0": "Local machine", "1": "Local intranet", "2": "Trusted sites", "3": "Internet", "4": "Restricted sites"}
    file_name = host_url.rstrip("/").split("/")[-1]
    answers["m05"] = {
        "host": re.match(r"https?://([^/]+)", host_url).group(1),
        "zone": opt(questions, "m05", "zone", lambda l: l.startswith(zone_names[zone["ZoneId"]])),
        "ext": file_name.rsplit(".", 1)[-1],
    }

    # ---- m07: phishing headers ------------------------------------------
    msg = email.message_from_bytes(find_one(bundle, "*/email/*/*.eml").read_bytes(), policy=email.policy.default)
    auth = " ".join(str(msg["Authentication-Results"]).split())
    from_domain = str(msg["From"]).split("@")[-1].strip(">").lower()
    assert f"dmarc=fail" in auth and f"header.from={from_domain}" in auth
    policy = re.search(r"dmarc=fail \(p=(\w+)", auth).group(1).lower()
    reply_to = str(msg["Reply-To"]).split("@")[-1].strip(">").lower()
    answers["m07"] = {
        "indicator": opt(questions, "m07", "indicator", lambda l: l.startswith("dmarc=fail")),
        "replyto": reply_to,
        "delivered": opt(questions, "m07", "delivered", lambda l: f"p={policy}" in l),
    }

    # ---- m11: containment (rules applied to the scenario text) ----------
    brief = find_one(bundle, "briefs/containment-scenario.md").read_text()
    edr_ok = "healthy and reporting" in brief

    def isolate_pred(label: str) -> bool:
        return label.startswith("Use EDR network containment") if edr_ok else label.startswith("Isolate at the network layer")

    answers["m11"] = {
        "isolate": opt(questions, "m11", "isolate", isolate_pred),
        "power": opt(questions, "m11", "power", lambda l: l.startswith("Leave it powered on")),
        "first": opt(questions, "m11", "first", lambda l: l == "A memory image"),
    }

    # ---- m15: collection order (RFC 3227) -------------------------------
    order_labels = ["Memory image", "Live-response snapshot", "Targeted triage"]
    answers["m15"] = {"order": [opt(questions, "m15", "order", lambda l, p=p: l.startswith(p)) for p in order_labels]}

    # ---- case file ------------------------------------------------------
    payload = next(e for e in events if e["id"] == 1 and e["Image"].lower().endswith("\\downloads\\invoice.pdf.exe"))
    answers["case"] = {
        "user": payload["User"].split("\\")[-1],
        "time": payload["UtcTime"][:19],
        "vector": opt(questions, "case", "vector", lambda l: l.startswith("A phishing link")),
        "filehost": answers["m05"]["host"],
        "ip": answers["m02"]["ip"],
        "c2": answers["m03"]["c2"],
        "contain": opt(questions, "case", "contain", isolate_pred),
    }

    # ---- m04: authentication anomaly ------------------------------------
    import ipaddress

    auth_lines = find_one(bundle, "tenant/sso-gateway.log").read_text().splitlines()
    hits = []
    for line in auth_lines:
        f = dict(kv.split("=", 1) for kv in line.split() if "=" in kv)
        if not f:
            continue
        num = int(line.split()[0])
        ok = " auth ok " in f" {line} "
        # Python treats RFC 5737 documentation ranges as "private", so test RFC 1918 explicitly.
        rfc1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
        external = not any(ipaddress.ip_address(f["src"]) in n for n in rfc1918)
        if ok and f["user"].startswith("svc-") and external and f["mfa"] == "no" and f["geo"] != "US":
            hits.append(num)
    assert len(hits) == 1, f"m04: expected one compromise line, got {hits}"
    answers["m04"] = {"line": str(hits[0]), "tell": opt(questions, "m04", "tell", lambda l: l.startswith("A service account"))}

    # ---- m06: DNS tunneling (Zeek dns.log) ------------------------------
    rows = []
    fields = None
    for line in find_one(bundle, "sensors/zeek/dns.log").read_text().splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line and not line.startswith("#"):
            rows.append(dict(zip(fields, line.split("\t"))))
    by_parent: dict = {}
    for r in rows:
        parent = ".".join(r["query"].split(".")[-2:])
        by_parent.setdefault(parent, []).append(r)
    def tunnel_score(rs):
        names = {r["query"] for r in rs}
        txt = sum(r["qtype_name"] == "TXT" for r in rs)
        return (len(names) / len(rs)) * txt
    tunnel_parent = max(by_parent, key=lambda p: tunnel_score(by_parent[p]))
    tun_rows = by_parent[tunnel_parent]
    assert len({r["query"] for r in tun_rows}) / len(tun_rows) > 0.9, "m06: tunnel names not unique enough"
    srcs: dict = {}
    for r in tun_rows:
        srcs[r["id.orig_h"]] = srcs.get(r["id.orig_h"], 0) + 1
    answers["m06"] = {
        "technique": opt(questions, "m06", "technique", lambda l: l.startswith("DNS tunneling")),
        "domain": tunnel_parent,
        "src": max(srcs, key=srcs.get),
    }

    # ---- m08: process-creation telemetry --------------------------------
    sec_events = sysmon_events(find_one(bundle, "*/logs/Security.xml"))
    sec_ids = {e["id"] for e in sec_events}
    sysmon_pc_ids = {e["id"] for e in events if "CommandLine" in e and "ParentCommandLine" in e}
    assert len(sec_ids) == 1 and len(sysmon_pc_ids) == 1
    answers["m08"] = {
        "sysmon": str(sysmon_pc_ids.pop()),
        "security": str(sec_ids.pop()),
        "field": opt(questions, "m08", "field", lambda l: l == "ParentCommandLine"),
        "audit": "yes" if any(e.get("CommandLine") for e in sec_events) else "no",
        "guid": enc[0]["ParentProcessGuid"],
    }

    # ---- m09: discovery burst -------------------------------------------
    attack_map = {  # command -> acceptable ATT&CK technique (first listed)
        "whoami": "T1033", "quser": "T1033", "net group": "T1069.002", "nltest /dclist": "T1018",
        "nltest /domain_trusts": "T1482", "systeminfo": "T1082", "ipconfig": "T1016", "arp": "T1016",
        "net view": "T1135", "tasklist": "T1057", "net user": "T1087.002", "net share": "T1135",
    }
    q9 = next(q for q in questions["modules"]["m09"]["questions"] if q["id"] == "technique")
    asked = re.search(r"`([^`]+)`", q9["prompt"]).group(1)
    tech = next(v for k, v in attack_map.items() if asked.startswith(k))
    answers["m09"] = {
        "activity": opt(questions, "m09", "activity", lambda l: l.startswith("Enumerating")),
        "tactic": "TA0007",
        "technique": tech,
    }

    # ---- m10: process injection -----------------------------------------
    trace = find_one(bundle, "*/live-response/edr-api-trace.txt").read_text()
    inj = sysmon_events(find_one(bundle, "*/logs/Sysmon-injection-events.xml"))
    thread_eid = next(e["id"] for e in inj if "StartAddress" in e)
    access = next(e["GrantedAccess"] for e in inj if "GrantedAccess" in e)
    assert access.lower() == "0x1fffff" and "PAGE_EXECUTE_READWRITE" in trace
    answers["m10"] = {
        "technique": "T1055",
        "giveaway": opt(questions, "m10", "giveaway", lambda l: l.startswith("RWX memory")),
        "access": opt(questions, "m10", "access", lambda l: l.startswith("PROCESS_ALL_ACCESS")),
        "eid": str(thread_eid),
        "pid": re.search(r"dwProcessId=(\d+)", trace).group(1),
    }

    # ---- m12: persistence -----------------------------------------------
    def planted(cmd: str) -> bool:
        return "-WindowStyle Hidden" in cmd and "\\ProgramData\\" in cmd and "VelmoraIT" not in cmd

    found = []
    for e in sysmon_events(find_one(bundle, "*/logs/Security-4698.xml")):
        if planted(e["TaskContent"]):
            found.append(("task", e["TaskName"].lstrip("\\")))
    for e in sysmon_events(find_one(bundle, "*/logs/System-7045.xml")):
        if planted(e["ImagePath"]):
            found.append(("service", e["ServiceName"]))
    for e in sysmon_events(find_one(bundle, "*/logs/Sysmon-WMI-events.xml")):
        if e["id"] == 20 and planted(e["Destination"]):
            found.append(("wmi", e["Name"].strip('"')))
    assert len(found) == 1, f"m12: expected one planted item, got {found}"
    kind, name = found[0]
    where_prefix = {"task": "C:\\Windows\\System32\\Tasks", "service": "HKLM\\SYSTEM", "wmi": "The WMI repository"}[kind]
    kind_label = {"task": "Scheduled task", "service": "Windows service", "wmi": "WMI event subscription"}[kind]
    answers["m12"] = {
        "kind": opt(questions, "m12", "kind", lambda l: l == kind_label),
        "name": name,
        "where": opt(questions, "m12", "where", lambda l: l.startswith(where_prefix)),
    }

    # ---- m13: DLL side-loading (stack counting) -------------------------
    loads = [json.loads(l) for l in find_one(bundle, "fleet/sysmon-image-loads.jsonl").read_text().splitlines() if l]
    combos: dict = {}
    for r in loads:
        d = r["winlog"]["event_data"]
        key = (d["Image"], d["ImageLoaded"], d["Signed"])
        combos.setdefault(key, set()).add(r["host"]["name"])
    rare = [(k, hs) for k, hs in combos.items() if len(hs) == 1 and k[2] == "false"]
    assert len(rare) == 1, f"m13: expected one rare unsigned load, got {len(rare)}"
    (image, loaded, _signed), hosts = rare[0]
    assert loaded.rsplit("\\", 1)[0] == image.rsplit("\\", 1)[0], "m13: DLL not loaded from the program's own folder"
    answers["m13"] = {
        "host": next(iter(hosts)).split(".")[0].upper(),
        "dll": loaded.rsplit("\\", 1)[-1],
        "why": opt(questions, "m13", "why", lambda l: l.startswith("Windows checks")),
    }

    # ---- m14: device-code phishing --------------------------------------
    signins = json.loads(find_one(bundle, "tenant/entra-signins.json").read_text())["value"]
    signins.sort(key=lambda s: s["createdDateTime"])
    phished = []
    for i, s in enumerate(signins):
        if s["authenticationProtocol"] != "deviceCode" or not s["isInteractive"]:
            continue
        after = [x for x in signins[i + 1:] if x["sessionId"] == s["sessionId"] and not x["isInteractive"]]
        new_ips = {x["ipAddress"] for x in after if x["ipAddress"] != s["ipAddress"]}
        if new_ips:
            phished.append((s["userPrincipalName"], new_ips))
    assert len(phished) == 1 and len(phished[0][1]) == 1, f"m14: ambiguous device-code split {phished}"
    answers["m14"] = {
        "user": phished[0][0],
        "ip": next(iter(phished[0][1])),
        "tell": opt(questions, "m14", "tell", lambda l: l.startswith("A deviceCode")),
        "action": opt(questions, "m14", "action", lambda l: l.startswith("Revoke")),
    }

    answers["case"].update({
        "persist": answers["m12"]["name"],
        "exfil": answers["m06"]["domain"],
        "svc": next(l.split("user=")[1].split()[0] for l in auth_lines if l.split() and int(l.split()[0]) == hits[0]),
        "cloudip": answers["m14"]["ip"],
    })

    out_path.write_text(json.dumps(answers, indent=2) + "\n")
    if decoded_dir:
        decoded_dir.mkdir(parents=True, exist_ok=True)
        for name, text in decoded.items():
            (decoded_dir / name).write_text(text)
    print(f"solved {sum(len(v) for v in answers.values())} answers from {bundle}")


if __name__ == "__main__":
    main()
