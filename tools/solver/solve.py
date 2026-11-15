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

    out_path.write_text(json.dumps(answers, indent=2) + "\n")
    if decoded_dir:
        decoded_dir.mkdir(parents=True, exist_ok=True)
        for name, text in decoded.items():
            (decoded_dir / name).write_text(text)
    print(f"solved {sum(len(v) for v in answers.values())} answers from {bundle}")


if __name__ == "__main__":
    main()
