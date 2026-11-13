"""Eskalasi berjenjang dan distribusi sitrep (di dalam aplikasi, offline).

Jenjang mengikuti hirarki satuan: jenjang 1 = satuan induk (mis. Korem), jenjang 2 = induk dari induk (Kodam), dst.
Penerima per tingkat satuan dan batas waktu pengakuan diatur di data/distribusi.json (bisa diedit, dibaca ulang otomatis).
Setiap kiriman = satu baris per penerima, berisi file sitrep PDF, waktu kirim, dan status diakui/belum.
Jika kiriman ke jenjang N belum diakui melewati batas waktu severity-nya, sistem otomatis meneruskan ke jenjang N+1.
"""
import json
import os
import threading
import time

from . import arsip, db

FILE = os.path.join(arsip.DATA_DIR, "distribusi.json")
DEFAULT = {
    "_catatan": "Data fiktif. Penerima per tingkat satuan tujuan; batas_menit = waktu tunggu pengakuan sebelum "
                "otomatis diteruskan ke jenjang berikutnya (null = tidak diteruskan otomatis).",
    "penerima": {
        "Korem": ["Danrem (u.p. Kasrem)", "Kasiintel Korem", "Perwira Siber Korem"],
        "Kodam": ["Pangdam (u.p. Asintel Kasdam)", "Kartika CSIRT Kodam"],
        "Kodim": ["Dandim", "Pasi Intel Kodim"],
        "Batalyon": ["Danyon", "Pasi Intel Yon"],
    },
    "batas_menit": {"kritis": 10, "tinggi": 30, "sedang": None, "rendah": None},
}
_cfg, _mtime, _lock = DEFAULT, None, threading.RLock()
listeners = []


def cfg():
    global _cfg, _mtime
    with _lock:
        if not os.path.exists(FILE):
            os.makedirs(os.path.dirname(FILE), exist_ok=True)
            with open(FILE, "w", encoding="utf-8") as f:
                json.dump(DEFAULT, f, ensure_ascii=False, indent=2)
        m = os.path.getmtime(FILE)
        if m != _mtime:
            try:
                with open(FILE, encoding="utf-8-sig") as f:
                    c = json.load(f)
                if not isinstance(c.get("penerima"), dict):
                    raise ValueError("kunci 'penerima' wajib berupa objek")
                _cfg = {**DEFAULT, **c}
            except (OSError, ValueError) as ex:
                print("distribusi.json tidak valid, memakai pengaturan sebelumnya:", ex)
                db.audit("sistem", "distribusi_file_tidak_valid", str(ex)[:300])
            _mtime = m
        return _cfg


def rantai(satuan_id):
    """Daftar satuan di atas satuan_id: [induk, induk dari induk, ...]."""
    out, s, seen = [], db.one("SELECT * FROM satuan WHERE id=?", (satuan_id,)), set()
    while s and s.get("parent_id") and s["parent_id"] not in seen:
        seen.add(s["parent_id"])
        s = db.one("SELECT * FROM satuan WHERE id=?", (s["parent_id"],))
        if s:
            out.append(s)
    return out


def jenjang_terakhir(iid):
    r = db.one("SELECT MAX(jenjang) j FROM distribusi WHERE insiden_id=?", (iid,))
    return r["j"] or 0


def kirim(iid, pengirim, jenjang=None, cara="manual"):
    """Kirim sitrep insiden ke jenjang berikutnya (atau jenjang tertentu). Mengembalikan baris yang dibuat."""
    inc = db.one("SELECT * FROM insiden WHERE id=?", (iid,))
    if not inc:
        raise ValueError("Insiden tidak ditemukan")
    ch = rantai(inc["satuan_id"])
    j = jenjang or jenjang_terakhir(iid) + 1
    if j < 1 or j > len(ch):
        raise ValueError("Sudah di jenjang tertinggi" if ch else "Satuan ini tidak punya satuan induk")
    tujuan = ch[j - 1]
    penerima = cfg()["penerima"].get(tujuan["tingkat"]) or [f"Komandan {tujuan['nama']}"]
    from . import sitrep
    kepada = f"{tujuan['nama']}: " + "; ".join(penerima)
    pdf = sitrep.build(iid, pengirim, kepada)
    nama = f"sitrep-{iid:04d}-jenjang{j}-{time.strftime('%Y%m%d-%H%M%S')}.pdf"
    os.makedirs(os.path.join(arsip.ARSIP, "sitrep"), exist_ok=True)
    with open(os.path.join(arsip.ARSIP, "sitrep", nama), "wb") as f:
        f.write(pdf)
    now = time.time()
    ids = [db.x("INSERT INTO distribusi(insiden_id,ts,jenjang,satuan_id,penerima,sitrep,pengirim,cara) VALUES(?,?,?,?,?,?,?,?)",
                (iid, now, j, tujuan["id"], p, nama, pengirim, cara)) for p in penerima]
    db.audit(pengirim, "sitrep_didistribusikan" if cara == "manual" else "eskalasi_otomatis",
             f"#{iid} jenjang {j} ke {tujuan['nama']} ({len(penerima)} penerima): {nama}")
    if inc["status"] in ("baru", "triase"):
        db.x("UPDATE insiden SET status='eskalasi', updated=? WHERE id=?", (now, iid))
    _umumkan(iid)
    return db.q(f"SELECT * FROM distribusi WHERE id IN ({','.join('?' * len(ids))})", ids)


def akui(did, pengguna, catatan=""):
    r = db.one("SELECT * FROM distribusi WHERE id=?", (did,))
    if not r:
        raise ValueError("Distribusi tidak ditemukan")
    if r["diakui_ts"]:
        raise ValueError(f"Sudah diakui oleh {r['diakui_oleh']}")
    db.x("UPDATE distribusi SET diakui_ts=?, diakui_oleh=?, catatan=? WHERE id=?",
         (time.time(), pengguna, catatan[:300], did))
    db.audit(pengguna, "sitrep_diakui", f"#{r['insiden_id']} jenjang {r['jenjang']} {r['penerima']}")
    _umumkan(r["insiden_id"])
    return db.one("SELECT * FROM distribusi WHERE id=?", (did,))


def ringkas(iid):
    """Status distribusi per insiden: jenjang terakhir, satuan tujuan, jumlah penerima, jumlah diakui."""
    r = db.one("SELECT d.jenjang, s.nama satuan, COUNT(*) n, SUM(d.diakui_ts IS NOT NULL) diakui, MIN(d.ts) ts "
               "FROM distribusi d JOIN satuan s ON s.id=d.satuan_id WHERE d.insiden_id=? "
               "GROUP BY d.jenjang ORDER BY d.jenjang DESC LIMIT 1", (iid,))
    if r:
        r["maks"] = len(rantai((db.one("SELECT satuan_id FROM insiden WHERE id=?", (iid,)) or {}).get("satuan_id")))
    return r


def daftar(limit=300):
    return db.q("SELECT d.*, s.nama satuan_nama, s.tingkat, i.judul, i.severity, i.status insiden_status "
                "FROM distribusi d JOIN satuan s ON s.id=d.satuan_id JOIN insiden i ON i.id=d.insiden_id "
                "ORDER BY d.id DESC LIMIT ?", (limit,))


def _umumkan(iid):
    for fn in listeners:
        try:
            fn(iid)
        except Exception as ex:
            print("distribusi listener:", ex)


def periksa_eskalasi(now=None):
    """Teruskan otomatis kiriman yang belum diakui satu pun penerimanya melewati batas waktu."""
    now = now or time.time()
    batas = cfg().get("batas_menit") or {}
    naik = []
    for r in db.q("SELECT d.insiden_id, d.jenjang, MIN(d.ts) ts, SUM(d.diakui_ts IS NOT NULL) diakui, i.severity "
                  "FROM distribusi d JOIN insiden i ON i.id=d.insiden_id WHERE i.status!='selesai' "
                  "GROUP BY d.insiden_id, d.jenjang"):
        m = batas.get(r["severity"])
        if not m or r["diakui"] or now - r["ts"] < m * 60 or r["jenjang"] != jenjang_terakhir(r["insiden_id"]):
            continue
        try:
            kirim(r["insiden_id"], "sistem", cara="otomatis")
            naik.append(r["insiden_id"])
        except ValueError:
            pass  # sudah di jenjang tertinggi
    return naik


def mulai(interval=20):
    def loop():
        while True:
            time.sleep(interval)
            try:
                periksa_eskalasi()
            except Exception as ex:
                print("eskalasi otomatis:", ex)
    threading.Thread(target=loop, daemon=True).start()
