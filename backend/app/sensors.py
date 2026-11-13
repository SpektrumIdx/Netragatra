"""Pembaca log sensor nyata: Suricata eve.json dan Wazuh alerts.json.

Jalur file diatur lewat env NETRA_SURICATA_EVE dan NETRA_WAZUH_ALERTS.
Jika file tidak ada, pembaca menunggu (aman untuk mode demo tanpa sensor).
"""
import json
import os
import threading
import time

from . import engine

SURI_SEV = {1: "tinggi", 2: "sedang", 3: "rendah"}


def _tail(path, handler, stop):
    # File yang sudah ada saat start dibaca dari akhir (alert lama tidak diputar ulang).
    # File yang baru muncul setelah start dibaca dari awal, agar baris pertamanya tidak hilang.
    from_end = bool(path) and os.path.exists(path)
    f, buf = None, ""
    while not stop.is_set():
        if f is None:
            if not path or not os.path.exists(path):
                from_end = False
                time.sleep(2)
                continue
            f = open(path, "r", encoding="utf-8", errors="replace")
            if from_end:
                f.seek(0, os.SEEK_END)
        try:
            if os.path.getsize(path) < f.tell():  # file dikosongkan/diputar ulang: baca dari awal
                f.seek(0)
                buf = ""
        except OSError:  # file dihapus: tunggu sampai muncul lagi
            f.close()
            f, buf = None, ""
            continue
        chunk = f.readline()
        if not chunk:
            time.sleep(0.3)
            continue
        buf += chunk
        if not buf.endswith("\n"):  # baris belum selesai ditulis, tunggu sisanya
            continue
        line, buf = buf.strip().lstrip("\ufeff"), ""
        if not line:
            continue
        try:
            handler(json.loads(line))
        except Exception as ex:  # satu baris rusak tidak boleh menghentikan sensor
            print("sensor error:", ex)


def suricata(rec):
    et = rec.get("event_type")
    if et == "alert":
        a = rec.get("alert", {})
        mitre = None
        meta = a.get("metadata") or {}
        if meta.get("mitre_technique_id"):
            mitre = meta["mitre_technique_id"][0]
        engine.ingest({
            "sumber": "suricata", "jenis": "alert", "src_ip": rec.get("src_ip"), "dst_ip": rec.get("dest_ip"),
            "dst_port": rec.get("dest_port"), "severity": SURI_SEV.get(a.get("severity"), "rendah"),
            "mitre": mitre, "pesan": a.get("signature"), "raw": rec})
    elif et == "dhcp" and rec.get("dhcp", {}).get("client_mac"):
        d = rec["dhcp"]
        engine.device_seen(d["client_mac"], d.get("assigned_ip") or rec.get("src_ip"))


def wazuh(rec):
    rule = rec.get("rule", {})
    groups = set(rule.get("groups", []))
    data = rec.get("data", {})
    # Agen Linux menaruh IP sumber di data.srcip, agen Windows di data.win.eventdata.ipAddress
    src_ip = data.get("srcip") or ((data.get("win") or {}).get("eventdata") or {}).get("ipAddress")
    if src_ip in ("-", "::1", "127.0.0.1"):
        src_ip = None
    agent_ip = rec.get("agent", {}).get("ip")
    mitre = (rule.get("mitre", {}).get("id") or [None])[0]
    lvl = rule.get("level", 0)
    sev = "kritis" if lvl >= 12 else "tinggi" if lvl >= 9 else "sedang" if lvl >= 5 else "rendah"
    jenis = "alert"
    if groups & {"authentication_failed", "authentication_failures", "invalid_login"}:
        jenis = "auth_fail"
    elif groups & {"virustotal", "rootcheck", "malware", "yara"}:
        jenis = "malware"
    engine.ingest({
        "sumber": "wazuh", "jenis": jenis, "src_ip": src_ip, "dst_ip": agent_ip,
        "severity": sev, "mitre": mitre, "pesan": rule.get("description"), "raw": rec})


def start():
    stop = threading.Event()
    for env, h in (("NETRA_SURICATA_EVE", suricata), ("NETRA_WAZUH_ALERTS", wazuh)):
        p = os.environ.get(env)
        if p:
            threading.Thread(target=_tail, args=(p, h, stop), daemon=True).start()
            print(f"sensor aktif: {env}={p}")
    return stop
