"""Panel lampu siaga: satu lampu per fitur, 4 tingkat, dihitung dari data nyata.

Level: 1 Awas (merah), 2 Siaga (oranye), 3 Waspada (kuning), 4 Normal (hijau), 0 Nonaktif (abu-abu,
fitur belum dibangun; sengaja tidak dihijaukan agar panel tidak berbohong).

Daftar fitur mengikuti dokumen "Rencana Coverage Cyber Ops Dashboard": 8 fitur wajib, modul ANPR,
2 fitur dari tabel kebutuhan IT/OT, dan 4 fitur opsional.
"""
import json
import time

from . import db
from .engine import CYBERPHYS_WINDOW, LEVEL_WARNA, iot_level, satuan_status, sev_level

LEVEL_NAMA = {0: "Nonaktif", 1: "Awas", 2: "Siaga", 3: "Waspada", 4: "Normal"}

# Ambang yang bisa disetel
PRA_BRUTE = 2          # gagal login ke satu aset dalam 60 detik sebelum ambang insiden (5)
PRA_SCAN = 8           # port berbeda dari satu sumber dalam 30 detik sebelum ambang insiden (15)
SENSOR_SENYAP = 900    # detik tanpa event sensor = pos pantau buta
SLA_TRIASE = (300, 900)  # kritis belum ditriase > 5 menit = Awas; insiden apa pun > 15 menit = Siaga
SITREP_TELAT = 600
IOT_SENYAP = 300       # sensor IoT yang berhenti melapor > 5 menit
IOT_PORTS = (23, 2323, 554, 8554, 1883, 502, 37777)  # telnet, RTSP, MQTT, Modbus, DVR     # insiden kritis tanpa sitrep > 10 menit = Awas


def _aturan(i):
    if i.get("aturan"):
        return i["aturan"]
    if i.get("korelasi"):
        return "cyphy"
    if (i.get("judul") or "").startswith("Kondisi kritis di"):
        return "iot"
    return {"T1110": "brute", "T1046": "scan", "T1200": "dev"}.get(i.get("mitre"), "mal")


def _terburuk(items, alasan_fn):
    """items: [(level, teks)] -> (level terburuk, teks) atau (4, None)."""
    items = [x for x in items if x[0]]
    if not items:
        return 4, None
    lvl = min(x[0] for x in items)
    return lvl, alasan_fn([t for l, t in items if l == lvl])


def _gabung(teks):
    teks = list(dict.fromkeys(teks))
    return "; ".join(teks[:2]) + (f" (+{len(teks) - 2} lagi)" if len(teks) > 2 else "")


def _dari_insiden(rows, kosong):
    if not rows:
        return 4, kosong
    lvl = min(sev_level(r["severity"]) for r in rows)
    terburuk = [r for r in rows if sev_level(r["severity"]) == lvl]
    return lvl, f"{len(rows)} insiden terbuka, terburuk #{terburuk[0]['id']} {terburuk[0]['judul']}"


def hitung():
    now = time.time()
    inc = db.q("SELECT i.*, a.jenis aset_jenis, a.kategori aset_kategori, a.nama aset_nama FROM insiden i "
               "LEFT JOIN aset a ON a.id=i.aset_id WHERE i.status!='selesai' ORDER BY i.id")
    for i in inc:
        i["_aturan"] = _aturan(i)
    # Titik reset "situasi tertangani": sinyal berbasis jendela waktu hanya menghitung event sesudahnya
    reset = db.one("SELECT ts, pengguna, detail FROM audit WHERE aksi='situasi_reset' ORDER BY id DESC LIMIT 1")
    base = reset["ts"] if reset else 0

    def sejak(detik):
        return max(now - detik, base)

    out = []

    def lampu(fid, nama, wajib, level, alasan, sumber):
        out.append({"id": fid, "nama": nama, "wajib": wajib, "level": level,
                    "warna": LEVEL_WARNA.get(level, "mati"), "label": LEVEL_NAMA[level],
                    "alasan": alasan, "sumber": sumber})

    # ---------- 8 fitur wajib ----------
    # W1 Ingest sensor: severity event sensor 15 menit terakhir + deteksi sensor senyap
    sens = db.q("SELECT sumber, severity, COUNT(*) n, MAX(ts) t FROM event WHERE ts>? AND sumber IN "
                "('suricata','wazuh','netflow','netdisc') GROUP BY sumber, severity", (sejak(SENSOR_SENYAP),))
    terakhir = db.one("SELECT MAX(ts) t FROM event WHERE sumber IN ('suricata','wazuh','netflow','netdisc')")["t"]
    items = [(sev_level(r["severity"]) if r["severity"] != "rendah" else 4,
              f"{r['n']} event {r['severity']} dari {r['sumber']}") for r in sens]
    if terakhir is None:
        items.append((3, "Belum ada data dari sensor"))
    elif now - terakhir > SENSOR_SENYAP:
        items.append((2, f"Sensor senyap {int((now - terakhir) // 60)} menit, pos pantau buta"))
    lvl, why = _terburuk(items, _gabung)
    lampu("ingest", "Ingest sensor Suricata + Wazuh", True, lvl,
          why or f"{sum(r['n'] for r in sens)} event normal dalam 15 menit", "event 15 menit terakhir")

    # W2 Inventaris aset IT/OT: insiden pada aset terdaftar + perangkat di luar inventaris
    pada_aset = [i for i in inc if i["aset_id"]]
    liar = [i for i in inc if i["_aturan"] in ("dev", "cyphy")]
    items = [(sev_level(i["severity"]), f"{i['aset_nama']} ({i['aset_jenis']}) diserang") for i in pada_aset]
    items += [(min(2, sev_level(i["severity"])), "Perangkat di luar inventaris aktif di jaringan") for i in liar]
    lvl, why = _terburuk(items, _gabung)
    n_aset = db.one("SELECT COUNT(*) n FROM aset")["n"]
    lampu("aset", "Inventaris aset IT/OT", True, lvl, why or f"{n_aset} aset terdaftar, tidak ada yang diserang",
          "insiden terbuka per aset")

    # W3 Deteksi + korelasi MITRE: insiden aturan 1-5, plus peringatan dini sebelum ambang
    items = [(sev_level(i["severity"]), f"{i['mitre'] + ' ' if i['mitre'] else ''}{i['judul']}") for i in inc]
    for r in db.q("SELECT a.nama, COUNT(*) n FROM event e JOIN aset a ON a.id=e.aset_id WHERE e.jenis='auth_fail' "
                  "AND e.ts>? GROUP BY e.aset_id HAVING n>=?", (sejak(60), PRA_BRUTE)):
        items.append((3, f"Pra-ambang brute force: {r['n']}/5 gagal login ke {r['nama']}"))
    for r in db.q("SELECT src_ip, COUNT(DISTINCT dst_port) n FROM event WHERE jenis='conn' AND ts>? "
                  "GROUP BY src_ip HAVING n>=?", (sejak(30), PRA_SCAN)):
        items.append((3, f"Pra-ambang port scan: {r['n']}/15 port dari {r['src_ip']}"))
    lvl, why = _terburuk(items, _gabung)
    lampu("deteksi", "Deteksi + korelasi MITRE ATT&CK", True, lvl, why or "Tidak ada pola serangan",
          "aturan korelasi 1-5 + pra-ambang")

    # W4 Alur insiden: SLA triase
    items = []
    for i in inc:
        if i["status"] != "baru":
            continue
        umur = now - i["ts"]
        menit = int(umur // 60)
        if i["severity"] == "kritis" and umur > SLA_TRIASE[0]:
            items.append((1, f"#{i['id']} kritis belum ditriase {menit} menit"))
        elif umur > SLA_TRIASE[1]:
            items.append((2, f"#{i['id']} belum ditriase {menit} menit"))
        else:
            items.append((3, f"#{i['id']} menunggu triase"))
    lvl, why = _terburuk(items, _gabung)
    lampu("alur", "Alur insiden triase-eskalasi-selesai", True, lvl,
          why or ("Semua insiden terbuka sudah ditangani" if inc else "Tidak ada insiden terbuka"), "SLA triase")

    # W5 Tampilan komandan: satuan terburuk
    sat = satuan_status()
    lvl = min((s["level"] for s in sat), default=4)
    buruk = [s["nama"] for s in sat if s["level"] == lvl]
    lampu("komandan", "Status satuan (tampilan komandan)", True, lvl,
          f"{_gabung(buruk)} berstatus {LEVEL_NAMA[lvl].lower()}" if lvl < 4 else f"{len(sat)} satuan aman",
          "hirarki satuan")

    # W6 Sitrep berjenjang: insiden kritis/eskalasi harus didistribusikan ke atas dan diakui penerima
    dist = {r["insiden_id"]: r for r in db.q(
        "SELECT insiden_id, MAX(jenjang) j, MIN(ts) ts, SUM(diakui_ts IS NOT NULL) diakui FROM distribusi "
        "WHERE jenjang=(SELECT MAX(jenjang) FROM distribusi d2 WHERE d2.insiden_id=distribusi.insiden_id) "
        "GROUP BY insiden_id")}
    items = []
    for i in inc:
        d = dist.get(i["id"])
        umur = now - i["ts"]
        if not d:
            if i["severity"] == "kritis":
                items.append((1 if umur > SITREP_TELAT else 2, f"#{i['id']} kritis belum dilaporkan ke atas"))
            elif i["status"] == "eskalasi":
                items.append((3, f"#{i['id']} dieskalasi tanpa sitrep"))
        elif not d["diakui"]:
            tunggu = int((now - d["ts"]) // 60)
            items.append((2 if i["severity"] == "kritis" else 3,
                          f"#{i['id']} sitrep jenjang {d['j']} belum diakui ({tunggu} menit)"))
    lvl, why = _terburuk(items, _gabung)
    lampu("sitrep", "Sitrep berjenjang (PDF)", True, lvl, why or "Semua sitrep sudah diakui penerima",
          "distribusi + pengakuan")

    # W7 Akses dan peran: percobaan login gagal ke NetraGatra sendiri
    n = db.one("SELECT COUNT(*) n FROM audit WHERE aksi='login_gagal' AND ts>?", (sejak(300),))["n"]
    lvl = 1 if n >= 15 else 2 if n >= 5 else 3 if n >= 1 else 4
    lampu("akses", "Login berperan + jejak audit", True, lvl,
          f"{n} login gagal ke NetraGatra dalam 5 menit" if n else "Tidak ada percobaan login gagal",
          "audit login_gagal 5 menit")

    # W8 Simulasi/replay: kesegaran data (risiko terbesar: link juri kosong)
    t = db.one("SELECT MAX(ts) t FROM event")["t"]
    if t is None:
        lvl, why = 3, "Belum ada data. Jalankan simulator skenario latar --loop"
    else:
        m = (now - t) / 60
        lvl = 4 if m <= 2 else 3 if m <= 10 else 2 if m <= 30 else 1
        why = f"Event terakhir {int(m)} menit lalu" + ("" if lvl == 4 else ", replay/simulator kemungkinan berhenti")
    lampu("replay", "Simulasi serangan + mode replay", True, lvl, why, "umur event terakhir")

    # ---------- 7 fitur tambahan ----------
    # T1 ANPR + korelasi siber-fisik
    cy = [i for i in inc if i["_aturan"] == "cyphy"]
    if cy:
        lvl, why = 1, cy[-1]["judul"]
    else:
        g = db.q("SELECT plat, ts FROM gerbang WHERE terdaftar=0 AND arah='masuk' AND ts>? ORDER BY ts DESC",
                 (sejak(3600),))
        aktif = [x for x in g if now - x["ts"] <= CYBERPHYS_WINDOW]
        if aktif:
            sisa = int((CYBERPHYS_WINDOW - (now - aktif[0]["ts"])) // 60)
            lvl, why = 2, f"{aktif[0]['plat']} tak terdaftar di dalam markas, jendela korelasi {sisa} menit lagi"
        elif g:
            lvl, why = 3, f"{len(g)} kendaraan tak terdaftar masuk dalam 1 jam"
        else:
            lvl, why = 4, "Semua kendaraan masuk terdaftar"
    lampu("anpr", "ANPR gerbang + korelasi siber-fisik", False, lvl, why, "log gerbang + aturan 4")

    # T2 Layanan publik, T3 OT pendukung: insiden + event non-rendah 15 menit terakhir per kategori aset
    for fid, nama, kat in (("publik", "Layanan publik (website satuan)", "Layanan publik"),
                           ("ot_pendukung", "OT pendukung (UPS, genset, listrik)", "Pendukung markas")):
        rows = [i for i in inc if i["aset_kategori"] == kat]
        if rows:
            lvl, why = _dari_insiden(rows, "")
        else:
            ev = db.q("SELECT e.severity, a.nama FROM event e JOIN aset a ON a.id=e.aset_id WHERE a.kategori=? "
                      "AND e.ts>? AND e.severity!='rendah'", (kat, sejak(900)))
            lvl = min((max(3, sev_level(e["severity"])) for e in ev), default=4)
            why = f"{len(ev)} alert ke {ev[0]['nama']} dalam 15 menit" if ev else "Tidak ada alert"
        lampu(fid, nama, False, lvl, why, f"aset kategori {kat}")

    # T4 Ancaman IoT lingkungan: bacaan sensor suhu/kelembapan + serangan siber ke sensor
    items = [(sev_level(i["severity"]), f"#{i['id']} {i['judul']}") for i in inc
             if i["_aturan"] == "iot" or i["aset_kategori"] == "IoT lingkungan"]
    for r in db.q("SELECT t.ip, t.ts, t.suhu, t.kelembapan, a.nama FROM telemetri t LEFT JOIN aset a ON a.id=t.aset_id "
                  "WHERE t.id IN (SELECT MAX(id) FROM telemetri GROUP BY ip)"):
        nama = r["nama"] or r["ip"]
        if now - r["ts"] > IOT_SENYAP:
            items.append((3, f"{nama} tidak mengirim data {int((now - r['ts']) // 60)} menit"))
        elif r["ts"] > base:
            lv = iot_level(r["suhu"], r["kelembapan"])
            if lv < 4:
                items.append((lv, f"{nama}: {r['suhu']} °C, {r['kelembapan']} %"))
    pr = db.q("SELECT a.nama, COUNT(*) n FROM event e JOIN aset a ON a.id=e.aset_id WHERE a.kategori='IoT lingkungan' "
              f"AND e.sumber!='iot' AND e.ts>? AND (e.severity!='rendah' OR e.jenis='auth_fail' OR e.dst_port IN "
              f"({','.join(map(str, IOT_PORTS))})) GROUP BY a.id", (sejak(900),))
    items += [(2 if r["n"] >= 10 else 3, f"{r['n']} percobaan akses ke {r['nama']}") for r in pr]
    lvl, why = _terburuk(items, _gabung)
    n_sensor = db.one("SELECT COUNT(DISTINCT ip) n FROM telemetri WHERE ts>?", (now - IOT_SENYAP,))["n"]
    lampu("iot", "Ancaman IoT (sensor suhu & kelembapan)", False, lvl,
          why or (f"{n_sensor} sensor melapor, semua dalam batas aman" if n_sensor else "Belum ada data sensor IoT"),
          "telemetri IoT + serangan ke sensor")

    for fid, nama in (("llm", "Ringkasan insiden LLM lokal"), ("multi", "Sinkronisasi multi-satuan"),
                      ("respons", "Respons otomatis (blokir IP)"), ("misp", "Threat intel MISP")):
        lampu(fid, nama, False, 0, "Belum dibangun", "-")

    aktif = [x["level"] for x in out if x["level"]]
    total = min(aktif, default=4)
    return {"ts": now, "level": total, "warna": LEVEL_WARNA[total], "label": LEVEL_NAMA[total], "lampu": out,
            "reset": {"ts": reset["ts"], "pengguna": reset["pengguna"]} if reset else None}



# ---------- Halaman detail per fitur ----------
SENSOR = "('suricata','wazuh','netflow','netdisc')"

CARA = {
    "ingest": "Severity tertinggi event Suricata/Wazuh/netflow 15 menit terakhir. Siaga juga jika sensor senyap > 15 menit.",
    "aset": "Insiden terbuka pada aset terdaftar (mengikuti severity), Siaga jika ada perangkat di luar inventaris.",
    "deteksi": "Insiden aturan korelasi 1-5. Waspada lebih awal saat gagal login >= 2/5 atau port >= 8/15 (pra-ambang).",
    "alur": "Awas jika insiden kritis belum ditriase > 5 menit, Siaga jika insiden apa pun > 15 menit, Waspada jika menunggu.",
    "komandan": "Satuan terburuk di hirarki. Satuan induk mengikuti bawahan terburuk.",
    "sitrep": "Awas jika insiden kritis belum didistribusikan ke atas > 10 menit, Siaga jika < 10 menit atau sitrep kritis belum "
              "diakui penerima, Waspada jika eskalasi tanpa sitrep atau sitrep non-kritis belum diakui. Normal jika sudah diakui.",
    "akses": "Login gagal ke NetraGatra dalam 5 menit: 1-4 Waspada, 5-14 Siaga (batas kunci), >= 15 Awas.",
    "replay": "Umur event terakhir: <= 2 menit Normal, <= 10 Waspada, <= 30 Siaga, lebih dari itu Awas (link juri kosong).",
    "anpr": "Awas saat korelasi siber-fisik terjadi, Siaga selama jendela 10 menit kendaraan tak terdaftar, Waspada < 1 jam.",
    "publik": "Insiden atau alert non-rendah pada aset kategori Layanan publik.",
    "ot_pendukung": "Insiden atau alert non-rendah pada aset kategori Pendukung markas.",
    "iot": "Bacaan terakhir tiap sensor: suhu >= 30/35/40 °C atau kelembapan >= 80/85/90 % (atau terlalu kering) = "
           "Waspada/Siaga/Awas. Waspada jika sensor berhenti melapor > 5 menit, Siaga/Waspada jika sensor diserang.",
}


# Isi "aktivitas" per lampu: apa yang dihitung di grafik (satuan) dan baris detailnya (ts, k, sumber, obj, teks).
_EV = ("SELECT e.ts, e.severity k, e.sumber, COALESCE(a.nama, e.src_ip, '-') obj, e.pesan teks FROM event e "
       "LEFT JOIN aset a ON a.id=e.aset_id ")
_INC = ("SELECT i.ts, i.severity k, 'insiden #' || i.id sumber, COALESCE(s.nama, '-') obj, "
        "i.judul || ' (' || UPPER(i.status) || ')' teks FROM insiden i LEFT JOIN satuan s ON s.id=i.satuan_id ")
AKTIVITAS = {
    "ingest": ("event sensor (Suricata/Wazuh/netflow/netdisc)", _EV + f"WHERE e.sumber IN {SENSOR} AND e.ts>?"),
    "aset": ("event yang mengenai aset terdaftar", _EV + "WHERE e.aset_id IS NOT NULL AND e.ts>?"),
    "deteksi": ("event dari semua sumber yang diperiksa aturan korelasi", _EV + "WHERE e.ts>?"),
    "alur": ("insiden dibuat atau diselesaikan",
             _INC.replace("i.severity k", "'dibuat' k") + "WHERE i.ts>? UNION ALL "
             + _INC.replace("SELECT i.ts, i.severity k", "SELECT i.updated ts, 'selesai' k") + "WHERE i.status='selesai' AND i.updated>?"),
    "komandan": ("insiden yang memengaruhi status satuan", _INC + "WHERE i.ts>?"),
    "sitrep": ("sitrep didistribusikan, diakui, dan insiden kritis",
               "SELECT d.ts, 'dikirim' k, d.pengirim sumber, s.nama obj, 'Sitrep #' || d.insiden_id || ' jenjang ' || d.jenjang "
               "|| ' ke ' || d.penerima teks FROM distribusi d JOIN satuan s ON s.id=d.satuan_id WHERE d.ts>? UNION ALL "
               "SELECT d.diakui_ts, 'diakui', d.diakui_oleh, s.nama, 'Sitrep #' || d.insiden_id || ' diakui untuk ' || d.penerima "
               "FROM distribusi d JOIN satuan s ON s.id=d.satuan_id WHERE d.diakui_ts>? UNION ALL "
               + _INC.replace("i.severity k", "'insiden kritis' k") + "WHERE i.severity='kritis' AND i.ts>?"),
    "akses": ("percobaan login ke NetraGatra",
              "SELECT ts, aksi k, pengguna sumber, '-' obj, COALESCE(detail, '') teks FROM audit "
              "WHERE aksi IN ('login','login_gagal') AND ts>?"),
    "replay": ("event dari semua sumber (termasuk simulator)", _EV + "WHERE e.ts>?"),
    "anpr": ("kendaraan terbaca kamera gerbang",
             "SELECT ts, CASE terdaftar WHEN 1 THEN 'terdaftar' ELSE 'tak terdaftar' END k, kamera sumber, plat obj, "
             "UPPER(arah) || COALESCE(' · ' || pemilik, ' · tidak ada di daftar kendaraan') || "
             "' · keyakinan ' || CAST(ROUND(confidence * 100) AS INT) || '%' teks FROM gerbang WHERE ts>?"),
}
for _f, _k in (("publik", "Layanan publik"), ("ot_pendukung", "Pendukung markas"), ("iot", "IoT lingkungan")):
    AKTIVITAS[_f] = (f"event pada aset kategori {_k}", _EV + f"WHERE a.kategori='{_k}' AND e.ts>?")


def _seri(fid):
    """(sql deret waktu -> ts, k) , (sql rincian -> label, n), filter insiden, jenis chart."""
    sev = "SELECT e.ts, e.severity k FROM event e "
    if fid == "ingest":
        return (sev + f"WHERE e.sumber IN {SENSOR} AND e.ts>?",
                f"SELECT sumber label, COUNT(*) n FROM event WHERE sumber IN {SENSOR} AND ts>? GROUP BY sumber",
                lambda i: True)
    if fid == "aset":
        return (sev + "WHERE e.aset_id IS NOT NULL AND e.ts>?",
                "SELECT a.nama label, COUNT(*) n FROM event e JOIN aset a ON a.id=e.aset_id WHERE e.ts>? GROUP BY a.id",
                lambda i: i["aset_id"] or i["_aturan"] in ("dev", "cyphy"))
    if fid == "deteksi":
        return (sev + "WHERE e.ts>?",
                "SELECT COALESCE(mitre,'tanpa MITRE') label, COUNT(*) n FROM insiden WHERE ts>? GROUP BY mitre",
                lambda i: True)
    if fid == "alur":
        return ("SELECT ts, 'dibuat' k FROM insiden WHERE ts>? UNION ALL "
                "SELECT updated, 'selesai' FROM insiden WHERE status='selesai' AND updated>?",
                "SELECT status label, COUNT(*) n FROM insiden WHERE ts>? GROUP BY status", lambda i: True)
    if fid == "komandan":
        return ("SELECT ts, severity k FROM insiden WHERE ts>?",
                "SELECT s.nama label, COUNT(*) n FROM insiden i JOIN satuan s ON s.id=i.satuan_id WHERE i.ts>? "
                "GROUP BY s.id", lambda i: True)
    if fid == "sitrep":
        return ("SELECT ts, 'dikirim' k FROM distribusi WHERE ts>? UNION ALL "
                "SELECT diakui_ts, 'diakui' FROM distribusi WHERE diakui_ts>? UNION ALL "
                "SELECT ts, 'insiden kritis' FROM insiden WHERE severity='kritis' AND ts>?",
                "SELECT s.nama || ' (jenjang ' || d.jenjang || ')' label, COUNT(*) n FROM distribusi d "
                "JOIN satuan s ON s.id=d.satuan_id WHERE d.ts>? GROUP BY d.satuan_id",
                lambda i: i["severity"] == "kritis" or i["status"] == "eskalasi")
    if fid == "akses":
        return ("SELECT ts, aksi k FROM audit WHERE aksi IN ('login','login_gagal') AND ts>?",
                "SELECT aksi label, COUNT(*) n FROM audit WHERE ts>? GROUP BY aksi", lambda i: False)
    if fid == "replay":
        return ("SELECT ts, sumber k FROM event WHERE ts>?",
                "SELECT sumber label, COUNT(*) n FROM event WHERE ts>? GROUP BY sumber", lambda i: True)
    if fid == "anpr":
        return ("SELECT ts, CASE terdaftar WHEN 1 THEN 'terdaftar' ELSE 'tak terdaftar' END k FROM gerbang WHERE ts>?",
                "SELECT plat label, COUNT(*) n FROM gerbang WHERE ts>? GROUP BY plat",
                lambda i: i["_aturan"] == "cyphy")
    if fid in ("publik", "ot_pendukung", "iot"):
        kat = {"publik": "Layanan publik", "ot_pendukung": "Pendukung markas", "iot": "IoT lingkungan"}[fid]
        k = kat.replace("'", "")
        return (sev + f"JOIN aset a ON a.id=e.aset_id WHERE a.kategori='{k}' AND e.ts>?",
                f"SELECT a.nama label, COUNT(*) n FROM event e JOIN aset a ON a.id=e.aset_id WHERE a.kategori='{k}' "
                "AND e.ts>? GROUP BY a.id",
                lambda i: i["aset_kategori"] == kat or (fid == "iot" and i["_aturan"] == "iot"))
    return None


def detail(fid, menit=60):
    menit = {60: 60, 360: 360, 1440: 1440}.get(menit, 60)
    now = time.time()
    panel = hitung()
    lamp = next((x for x in panel["lampu"] if x["id"] == fid), None)
    seri = _seri(fid)
    if not lamp or not seri:
        return None
    sql_seri, sql_rinci, filt = seri
    langkah = {60: 60, 360: 600, 1440: 3600}[menit]
    awal = now - menit * 60
    n = menit * 60 // langkah
    rows = db.q(sql_seri, (awal,) * sql_seri.count("?"))
    buckets = [{"t": awal + i * langkah, "n": {}} for i in range(n)]
    for r in rows:
        i = int((r["ts"] - awal) // langkah)
        if 0 <= i < n:
            b = buckets[i]["n"]
            b[r["k"] or "-"] = b.get(r["k"] or "-", 0) + 1
    rinci = sorted(db.q(sql_rinci, (awal,)), key=lambda r: -r["n"])[:8]
    inc = db.q("SELECT i.*, a.jenis aset_jenis, a.kategori aset_kategori, a.nama aset_nama, s.nama satuan_nama "
               "FROM insiden i LEFT JOIN aset a ON a.id=i.aset_id LEFT JOIN satuan s ON s.id=i.satuan_id "
               "ORDER BY i.id DESC LIMIT 300")
    for i in inc:
        i["_aturan"] = _aturan(i)
        i["jumlah_event"] = len(json.loads(i["event_ids"] or "[]"))
    terkait = [i for i in inc if filt(i)]
    out = {"lampu": lamp, "cara": CARA.get(fid, ""), "menit": menit, "langkah": langkah, "seri": buckets,
           "rincian": rinci, "insiden": [{k: v for k, v in i.items() if not k.startswith("_")} for i in terkait[:6]],
           "insiden_terbuka": sum(1 for i in terkait if i["status"] != "selesai"), "total": len(rows)}
    satuan, sql_akt = AKTIVITAS.get(fid, ("aktivitas", None))
    out["satuan"] = satuan
    out["aktivitas"] = db.q(f"SELECT * FROM ({sql_akt}) ORDER BY ts DESC LIMIT 500",
                            (awal,) * sql_akt.count("?")) if sql_akt else []
    if fid == "iot":
        out["telemetri"] = db.q(
            "SELECT t.ts, t.ip, t.suhu, t.kelembapan, COALESCE(a.nama, t.ip) nama FROM telemetri t "
            "LEFT JOIN aset a ON a.id=t.aset_id WHERE t.ts>? ORDER BY t.ts", (awal,))
    if fid == "akses":
        out["log"] = db.q("SELECT ts, pengguna, aksi, detail FROM audit WHERE aksi IN ('login','login_gagal',"
                          "'situasi_reset') ORDER BY id DESC LIMIT 6")
    return out
