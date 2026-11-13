"""Penulis alert Wazuh untuk demo tanpa manager Wazuh sungguhan.

Menulis baris JSON dengan format yang sama seperti /var/ossec/logs/alerts/alerts.json
(satu alert per baris) ke file yang dibaca NetraGatra lewat env NETRA_WAZUH_ALERTS.
ID rule, grup, dan MITRE mengikuti ruleset bawaan Wazuh 4.x.

Pemakaian (dari folder proyek):
  python simulator/wazuh_alert.py --skenario brute      # brute force SSH ke Server Aplikasi Dinas
  python simulator/wazuh_alert.py --skenario malware    # EICAR terdeteksi VirusTotal di PC Staf Personel
  python simulator/wazuh_alert.py --skenario normal     # alert rendah (login sukses, dll.)
  python simulator/wazuh_alert.py --skenario semua
  python simulator/wazuh_alert.py --contoh sensor-logs/wazuh/contoh-alerts.json   # tulis file contoh statis

Jangan mengedit alerts.json dengan Notepad saat server jalan: Notepad menulis ulang seluruh file.
"""
import argparse
import json
import os
import random
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_FILE = os.path.join(ROOT, "sensor-logs", "wazuh", "alerts.json")

PENYERANG = "10.10.3.66"
MANAGER = {"name": "wazuh-manager"}
AG_SERVER = {"id": "002", "name": "srv-app-dinas", "ip": "10.10.3.10"}
AG_PC_PERSONEL = {"id": "005", "name": "PC-STAF-PERSONEL", "ip": "10.10.3.102"}

EICAR = {"md5": "44d88612fea8a8f36de82e1278abb02f", "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
         "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}


def _ts(t=None):
    t = t or time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)) + f".{int(t % 1 * 1000):03d}" + time.strftime("%z")


def _base(rule, agent, full_log, location, decoder, data=None, t=None):
    t = t or time.time()
    rec = {"timestamp": _ts(t), "rule": rule, "agent": agent, "manager": MANAGER,
           "id": f"{int(t)}.{random.randint(100000, 9999999)}", "full_log": full_log,
           "decoder": decoder, "location": location}
    if data:
        rec["data"] = data
    return rec


def _syslog_time(t=None):
    return time.strftime("%b %d %H:%M:%S", time.localtime(t or time.time()))


def ssh_gagal(user, t=None):
    port = random.randint(40000, 60999)
    log = f"{_syslog_time(t)} srv-app-dinas sshd[{random.randint(1000, 9999)}]: Failed password for invalid user " \
          f"{user} from {PENYERANG} port {port} ssh2"
    rule = {"level": 5, "description": "sshd: Attempt to login using a non-existent user", "id": "5710",
            "mitre": {"id": ["T1110.001", "T1021.004"], "tactic": ["Credential Access", "Lateral Movement"],
                      "technique": ["Password Guessing", "SSH"]},
            "firedtimes": 1, "mail": False,
            "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"],
            "pci_dss": ["10.2.4", "10.2.5", "10.6.1"], "gdpr": ["IV_35.7.d", "IV_32.2"]}
    return _base(rule, AG_SERVER, log, "/var/log/auth.log", {"parent": "sshd", "name": "sshd"},
                 {"srcip": PENYERANG, "srcport": str(port), "srcuser": user}, t)


def ssh_brute(t=None):
    log = f"{_syslog_time(t)} srv-app-dinas sshd[{random.randint(1000, 9999)}]: Failed password for invalid user " \
          f"admin from {PENYERANG} port {random.randint(40000, 60999)} ssh2"
    rule = {"level": 10, "description": "sshd: brute force trying to get access to the system. Non existent user.",
            "id": "5712", "frequency": 8,
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
            "firedtimes": 1, "mail": False, "groups": ["syslog", "sshd", "authentication_failures"],
            "pci_dss": ["11.4", "10.2.4", "10.2.5"], "gdpr": ["IV_35.7.d", "IV_32.2"]}
    return _base(rule, AG_SERVER, log, "/var/log/auth.log", {"parent": "sshd", "name": "sshd"},
                 {"srcip": PENYERANG, "srcuser": "admin"}, t)


def fim_eicar(t=None):
    path = "c:\\users\\staf\\downloads\\laporan_bulanan.pdf.exe"
    rule = {"level": 5, "description": "File added to the system.", "id": "554", "firedtimes": 1, "mail": False,
            "groups": ["ossec", "syscheck", "syscheck_entry_added", "syscheck_file"],
            "pci_dss": ["11.5"], "gdpr": ["II_5.1.f"]}
    rec = _base(rule, AG_PC_PERSONEL, f"File '{path}' added\nMode: realtime\n", "syscheck",
                {"name": "syscheck_new_entry"}, None, t)
    rec["syscheck"] = {"path": path, "mode": "realtime", "size_after": "68", "event": "added",
                       "md5_after": EICAR["md5"], "sha1_after": EICAR["sha1"], "sha256_after": EICAR["sha256"]}
    return rec


def vt_eicar(t=None):
    path = "c:\\users\\staf\\downloads\\laporan_bulanan.pdf.exe"
    rule = {"level": 12, "description": f"VirusTotal: Alert - {path} - 62 engines detected this file",
            "id": "87105", "mitre": {"id": ["T1203"], "tactic": ["Execution"],
                                     "technique": ["Exploitation for Client Execution"]},
            "firedtimes": 1, "mail": True, "groups": ["virustotal"],
            "pci_dss": ["10.6.1", "11.4"], "gdpr": ["IV_35.7.d"]}
    data = {"virustotal": {"found": "1", "malicious": "1", "positives": "62", "total": "67",
                           "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "permalink": f"https://www.virustotal.com/gui/file/{EICAR['sha256']}/detection",
                           "source": {"alert_id": f"{int(time.time())}.1", "file": path, "md5": EICAR["md5"],
                                      "sha1": EICAR["sha1"]}},
            "integration": "virustotal"}
    return _base(rule, AG_PC_PERSONEL, "", "virustotal", {"name": "json"}, data, t)


def login_sukses(t=None):
    log = f"{_syslog_time(t)} srv-app-dinas sshd[{random.randint(1000, 9999)}]: Accepted publickey for " \
          f"admdinas from 10.10.3.101 port {random.randint(40000, 60999)} ssh2"
    rule = {"level": 3, "description": "sshd: authentication success.", "id": "5715",
            "mitre": {"id": ["T1078", "T1021"], "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation",
                                                           "Initial Access", "Lateral Movement"],
                      "technique": ["Valid Accounts", "Remote Services"]},
            "firedtimes": 1, "mail": False, "groups": ["syslog", "sshd", "authentication_success"],
            "pci_dss": ["10.2.5"], "gdpr": ["IV_32.2"]}
    return _base(rule, AG_SERVER, log, "/var/log/auth.log", {"parent": "sshd", "name": "sshd"},
                 {"srcip": "10.10.3.101", "dstuser": "admdinas"}, t)


SKENARIO = {
    "normal": lambda: [login_sukses()],
    "brute": lambda: [ssh_gagal(u) for u in ["admin", "root", "admin", "oracle", "test", "admin", "ubuntu"]]
    + [ssh_brute()],
    "malware": lambda: [fim_eicar(), vt_eicar()],
}


def tulis(path, records, jeda):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    for i, r in enumerate(records):
        # newline="\n": format Wazuh asli, dan sensor membaca per baris
        with open(path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(time.strftime("%H:%M:%S"), f"rule {r['rule']['id']} lvl {r['rule']['level']}:",
              r["rule"]["description"][:70], flush=True)
        if i < len(records) - 1:
            time.sleep(jeda)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=os.environ.get("NETRA_WAZUH_ALERTS") or DEFAULT_FILE)
    ap.add_argument("--skenario", choices=["normal", "brute", "malware", "semua"], default="semua")
    ap.add_argument("--jeda", type=float, default=1.0, help="detik antar alert")
    ap.add_argument("--contoh", metavar="FILE", help="tulis semua contoh alert sekaligus ke FILE lalu keluar")
    a = ap.parse_args()
    if a.contoh:
        recs = SKENARIO["normal"]() + SKENARIO["brute"]() + SKENARIO["malware"]()
        with open(a.contoh, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in recs)
        print(f"{len(recs)} alert contoh ditulis ke {a.contoh}")
        return
    print("menulis ke", os.path.abspath(a.file))
    names = ["normal", "brute", "malware"] if a.skenario == "semua" else [a.skenario]
    for n in names:
        tulis(a.file, SKENARIO[n](), a.jeda)
        if n != names[-1]:
            time.sleep(3)


if __name__ == "__main__":
    main()
