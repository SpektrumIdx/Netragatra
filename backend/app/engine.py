"""Normalisasi event dan mesin korelasi NetraGatra.

Semua sumber (Suricata, Wazuh, ANPR, simulator) diubah ke satu bentuk event,
dipasangkan ke aset, lalu diperiksa aturan korelasi yang membentuk insiden.
"""
import time
from collections import defaultdict, deque

from . import db

SEV_ORDER = {"rendah": 1, "sedang": 2, "tinggi": 3, "kritis": 4}

# Jendela waktu dan ambang aturan (detik / jumlah)
BRUTE_WINDOW, BRUTE_MIN = 60, 5
SCAN_WINDOW, SCAN_MIN = 30, 15
CYBERPHYS_WINDOW = 600

_auth_fail = defaultdict(deque)   # aset_id -> deque[(ts, event_id)]
_scan = defaultdict(deque)        # src_ip -> deque[(ts, port, event_id)]
_open_key = {}                    # kunci aturan -> insiden_id (hindari insiden ganda)

listeners = []  # fungsi(kind, payload) untuk push WebSocket


def publish(kind, payload):
    for fn in list(listeners):
        try:
            fn(kind, payload)
        except Exception:
            pass


def _satuan_of(aset, src_ip=None, dst_ip=None):
    if aset:
        return aset["satuan_id"]
    for ip in (dst_ip, src_ip):
        if ip and ip.startswith("10.10."):
            try:
                return int(ip.split(".")[2])
            except ValueError:
                pass
    return None


def ingest(ev):
    """ev: dict dengan kunci sumber, jenis, src_ip, dst_ip, dst_port, severity, mitre, pesan, ts?, raw?"""
    ts = ev.get("ts") or time.time()
    aset = db.aset_by_ip(ev.get("dst_ip")) or db.aset_by_ip(ev.get("src_ip"))
    satuan_id = ev.get("satuan_id") or _satuan_of(aset, ev.get("src_ip"), ev.get("dst_ip"))
    eid = db.x(
        "INSERT INTO event(ts,sumber,jenis,src_ip,dst_ip,dst_port,aset_id,satuan_id,severity,mitre,pesan,raw)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (ts, ev.get("sumber"), ev.get("jenis"), ev.get("src_ip"), ev.get("dst_ip"), ev.get("dst_port"),
         aset["id"] if aset else None, satuan_id, ev.get("severity", "rendah"), ev.get("mitre"),
         ev.get("pesan"), db.dumps(ev.get("raw")) if ev.get("raw") else None),
    )
    row = db.one(
        "SELECT e.*, a.nama aset_nama, a.jenis aset_jenis FROM event e LEFT JOIN aset a ON a.id=e.aset_id WHERE e.id=?",
        (eid,))
    publish("event", row)
    _correlate(row, aset)
    return row


def _new_incident(key, satuan_id, aset_id, judul, severity, mitre, event_ids, korelasi=None):
    if key in _open_key:
        inc = db.one("SELECT * FROM insiden WHERE id=?", (_open_key[key],))
        if inc and inc["status"] != "selesai":
            ids = sorted(set(eval_ids(inc["event_ids"]) + event_ids))
            db.x("UPDATE insiden SET event_ids=?, updated=? WHERE id=?", (db.dumps(ids), time.time(), inc["id"]))
            return inc["id"]
    now = time.time()
    iid = db.x(
        "INSERT INTO insiden(ts,satuan_id,aset_id,judul,severity,mitre,status,korelasi,event_ids,catatan,updated,aturan)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (now, satuan_id, aset_id, judul, severity, mitre, "baru", korelasi, db.dumps(event_ids), "", now,
         key.split(":")[0]))
    _open_key[key] = iid
    db.audit("sistem", "insiden_dibuat", f"#{iid} {judul}")
    publish("insiden", get_incident(iid))
    publish("status", satuan_status())
    return iid


def eval_ids(s):
    import json
    try:
        return json.loads(s or "[]")
    except ValueError:
        return []


def _correlate(e, aset):
    now = e["ts"]
    sev_aset = "kritis" if aset and aset["kritis"] >= 3 else "tinggi"

    # Aturan 1: brute force ke satu aset
    if e["jenis"] == "auth_fail" and e["aset_id"]:
        d = _auth_fail[e["aset_id"]]
        d.append((now, e["id"]))
        while d and now - d[0][0] > BRUTE_WINDOW:
            d.popleft()
        if len(d) >= BRUTE_MIN:
            _new_incident(f"brute:{e['aset_id']}", e["satuan_id"], e["aset_id"],
                          f"Brute force login ke {aset['nama']} dari {e['src_ip']}", sev_aset, "T1110",
                          [i for _, i in d])

    # Aturan 2: port scan dari satu sumber
    if e["jenis"] == "conn" and e["src_ip"]:
        d = _scan[e["src_ip"]]
        d.append((now, e["dst_port"], e["id"]))
        while d and now - d[0][0] > SCAN_WINDOW:
            d.popleft()
        if len({p for _, p, _ in d}) >= SCAN_MIN:
            _new_incident(f"scan:{e['src_ip']}", e["satuan_id"], e["aset_id"],
                          f"Port scan dari {e['src_ip']} ke jaringan markas", "sedang", "T1046",
                          [i for _, _, i in d])

    # Alert Suricata yang sudah bertanda scan
    if e["sumber"] == "suricata" and e["jenis"] == "alert" and "SCAN" in (e["pesan"] or "").upper():
        _new_incident(f"scan:{e['src_ip']}", e["satuan_id"], e["aset_id"],
                      f"Port scan dari {e['src_ip']} (Suricata)", "sedang", "T1046", [e["id"]])

    # Aturan 5: malware di endpoint
    if e["jenis"] == "malware":
        _new_incident(f"mal:{e['aset_id']}:{int(now // 3600)}", e["satuan_id"], e["aset_id"],
                      f"Malware terdeteksi di {aset['nama'] if aset else e['src_ip']}", "tinggi",
                      e["mitre"] or "T1204", [e["id"]])

    # Aturan 3 + 4: perangkat tak dikenal (+ korelasi siber-fisik)
    if e["jenis"] == "device_new":
        gate = db.one(
            "SELECT * FROM gerbang WHERE satuan_id=? AND terdaftar=0 AND arah='masuk' AND ts>=? ORDER BY ts DESC",
            (e["satuan_id"], now - CYBERPHYS_WINDOW))
        if gate:
            menit = max(1, round((now - gate["ts"]) / 60))
            _new_incident(
                f"cyphy:{e['src_ip']}", e["satuan_id"], None,
                f"Korelasi siber-fisik: kendaraan tak terdaftar {gate['plat']} masuk, "
                f"{menit} menit kemudian perangkat tak dikenal {e['src_ip']} muncul di jaringan",
                "kritis", "T1200", [e["id"]],
                korelasi=db.dumps({"gerbang_id": gate["id"], "plat": gate["plat"], "selisih_menit": menit}))
        else:
            _new_incident(f"dev:{e['src_ip']}", e["satuan_id"], None,
                          f"Perangkat tak dikenal {e['src_ip']} muncul di jaringan markas", "tinggi", "T1200",
                          [e["id"]])


def gate_event(plat, satuan_id, arah="masuk", kamera="CCTV Gerbang Utama", confidence=0.9, ts=None):
    ts = ts or time.time()
    k = db.one("SELECT * FROM kendaraan WHERE plat=?", (plat,))
    gid = db.x("INSERT INTO gerbang(ts,satuan_id,plat,arah,terdaftar,pemilik,kamera,confidence) VALUES(?,?,?,?,?,?,?,?)",
               (ts, satuan_id, plat, arah, 1 if k else 0, k["pemilik"] if k else None, kamera, confidence))
    row = db.one("SELECT * FROM gerbang WHERE id=?", (gid,))
    publish("gerbang", row)
    if not k and arah == "masuk":
        ingest({"sumber": "anpr", "jenis": "vehicle_unknown", "satuan_id": satuan_id, "severity": "sedang",
                "pesan": f"Kendaraan tak terdaftar {plat} masuk melalui {kamera}", "ts": ts})
    return row


def device_seen(mac, ip, satuan_id=None):
    """Dipanggil oleh sensor penemuan perangkat (ARP/DHCP/Suricata). Memicu event jika MAC baru."""
    known = db.one("SELECT * FROM perangkat_dikenal WHERE mac=?", (mac,))
    if known:
        return None
    db.x("INSERT INTO perangkat_dikenal VALUES(?,?,?,0)", (mac, ip, time.time()))
    return ingest({"sumber": "netdisc", "jenis": "device_new", "src_ip": ip, "satuan_id": satuan_id,
                   "severity": "tinggi", "mitre": "T1200", "pesan": f"Perangkat baru MAC {mac} IP {ip}"})


# ---------- Telemetri IoT lingkungan (suhu & kelembapan) ----------
# (batas atas suhu °C, batas atas kelembapan %, batas bawah kelembapan %) per level 1..3
IOT_BATAS = {1: (40, 90, None), 2: (35, 85, 15), 3: (30, 80, 25)}
IOT_LONJAKAN = (5.0, 300)   # naik >= 5 °C dalam 5 menit: kemungkinan kebakaran atau sensor dimanipulasi
_iot_level = {}             # ip -> level bacaan terakhir (hanya buat event saat kondisi memburuk)
_iot_lonjak = {}            # ip -> waktu peringatan lonjakan terakhir (maks. 1 per 5 menit)


def iot_level(suhu, kelembapan):
    for lvl in (1, 2, 3):
        t, h_atas, h_bawah = IOT_BATAS[lvl]
        if (suhu is not None and suhu >= t) or (kelembapan is not None and (
                kelembapan >= h_atas or (h_bawah is not None and kelembapan <= h_bawah))):
            return lvl
    return 4


def telemetri(ip, suhu=None, kelembapan=None, ts=None):
    ts = ts or time.time()
    aset = db.aset_by_ip(ip)
    satuan_id = _satuan_of(aset, ip)
    db.x("INSERT INTO telemetri(ts,ip,aset_id,satuan_id,suhu,kelembapan) VALUES(?,?,?,?,?,?)",
         (ts, ip, aset["id"] if aset else None, satuan_id, suhu, kelembapan))
    nama = aset["nama"] if aset else ip
    lvl = iot_level(suhu, kelembapan)
    sev = {1: "kritis", 2: "tinggi", 3: "sedang"}.get(lvl)
    nilai = f"suhu {suhu} °C, kelembapan {kelembapan} %"
    ev_ids = []
    if sev and lvl < _iot_level.get(ip, 4):
        ev_ids = [ingest({"sumber": "iot", "jenis": "telemetri", "dst_ip": ip, "severity": sev, "ts": ts,
                "pesan": f"{nama} di luar batas aman: {nilai}"})["id"]]
    _iot_level[ip] = lvl
    if suhu is not None:
        lalu = db.one("SELECT MIN(suhu) s FROM telemetri WHERE ip=? AND ts>=? AND ts<?", (ip, ts - IOT_LONJAKAN[1], ts))
        if (lalu and lalu["s"] is not None and suhu - lalu["s"] >= IOT_LONJAKAN[0]
                and ts - _iot_lonjak.get(ip, 0) > IOT_LONJAKAN[1]):
            _iot_lonjak[ip] = ts
            ingest({"sumber": "iot", "jenis": "telemetri", "dst_ip": ip, "severity": "tinggi", "ts": ts,
                    "pesan": f"Lonjakan suhu {nama}: {lalu['s']} → {suhu} °C dalam 5 menit"})
    if lvl == 1:
        _new_incident(f"iot:{ip}", satuan_id, aset["id"] if aset else None,
                      f"Kondisi kritis di {nama}: {nilai}", "kritis", None, ev_ids)
    return {"level": lvl}


def get_incident(iid):
    r = db.one("SELECT i.*, a.nama aset_nama, s.nama satuan_nama FROM insiden i LEFT JOIN aset a ON a.id=i.aset_id "
               "LEFT JOIN satuan s ON s.id=i.satuan_id WHERE i.id=?", (iid,))
    if r:
        r["jumlah_event"] = len(eval_ids(r["event_ids"]))
    return r


def reset_situasi(pengguna, catatan):
    """Komandan menyatakan situasi tertangani. Event, insiden, dan audit TIDAK dihapus:
    insiden terbuka ditutup dengan catatan, lalu jendela deteksi dimulai dari nol."""
    now = time.time()
    rows = db.q("SELECT id, catatan FROM insiden WHERE status!='selesai'")
    baris = f"[{time.strftime('%H:%M')}] {pengguna} (situasi tertangani): {catatan}"
    for r in rows:
        db.x("UPDATE insiden SET status='selesai', catatan=?, updated=? WHERE id=?",
             ((r["catatan"] + "\n" if r["catatan"] else "") + baris, now, r["id"]))
    _auth_fail.clear()
    _scan.clear()
    _open_key.clear()
    _iot_level.clear()
    _iot_lonjak.clear()
    ids = ",".join(f"#{r['id']}" for r in rows) or "-"
    db.audit(pengguna, "situasi_reset", f"{len(rows)} insiden ditutup ({ids}). {catatan}"[:1000])
    publish("status", satuan_status())
    publish("reset", {"ts": now, "pengguna": pengguna, "ditutup": len(rows)})
    return {"ditutup": len(rows), "ts": now}


# Level siaga 4 tingkat: 1 Awas (merah), 2 Siaga (oranye), 3 Waspada (kuning), 4 Normal (hijau)
LEVEL_WARNA = {1: "merah", 2: "oranye", 3: "kuning", 4: "hijau"}
SEV_LEVEL = {"kritis": 1, "tinggi": 2, "sedang": 3, "rendah": 4}


def sev_level(severity):
    return SEV_LEVEL.get(severity, 4)


def satuan_status():
    out = []
    for s in db.q("SELECT * FROM satuan ORDER BY id"):
        open_inc = db.q("SELECT severity FROM insiden WHERE satuan_id=? AND status!='selesai'", (s["id"],))
        lvl = min([sev_level(i["severity"]) for i in open_inc], default=4)
        out.append({**s, "level": lvl, "status": LEVEL_WARNA[lvl], "insiden_terbuka": len(open_inc)})
    # status induk mengikuti anak terburuk (level terkecil)
    by_id = {s["id"]: s for s in out}
    for s in sorted(out, key=lambda s: -s["id"]):
        p = by_id.get(s["parent_id"])
        if p and s["level"] < p["level"]:
            p["level"], p["status"] = s["level"], s["status"]
    return out
