"""Penyimpanan berbasis direktori: aset (aset.json yang bisa diedit tangan) dan arsip insiden/audit/sitrep.

Struktur di folder data (sebelah netragatra.db):
  aset.json                         daftar aset + koordinat GPS; boleh diedit langsung, dibaca ulang otomatis
  arsip/insiden/insiden-0003.json   satu file per insiden, ditulis ulang setiap insiden berubah
  arsip/audit/audit-2026-11-12.jsonl  jejak audit harian, satu baris JSON per aksi (hanya ditambah)
  arsip/sitrep/sitrep-0003-20261112-180512.pdf  setiap sitrep yang diunduh
"""
import json
import os
import re
import threading
import time

from . import db

DATA_DIR = os.path.dirname(os.path.abspath(db.DB_PATH))
ASET_FILE = os.path.join(DATA_DIR, "aset.json")
ARSIP = os.path.join(DATA_DIR, "arsip")
JENIS = ("insiden", "audit", "sitrep")
FIELD = ("id", "satuan_id", "nama", "jenis", "kategori", "ip", "mac", "kritis", "lat", "lon", "foto")
FOTO_DIR = os.path.join(DATA_DIR, "foto")
_lock = threading.RLock()
_NAMA_FOTO = re.compile(r"^(stok/)?[A-Za-z0-9._-]{1,80}\.(jpg|jpeg|png|webp)$", re.I)
_mtime = None


def _foto_list(v):
    """Kolom/isian foto -> daftar 4 slot (nama file di data/foto atau None)."""
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            v = [v]
    v = [x if isinstance(x, str) and _NAMA_FOTO.match(x) else None for x in (v or [])][:4]
    return v + [None] * (4 - len(v)) if any(v) else []


def _tulis_atomik(path, teks):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(teks)
    os.replace(tmp, path)


# ---------- Aset ----------
def ekspor_aset():
    global _mtime
    with _lock:
        rows = db.q(f"SELECT {','.join(FIELD)} FROM aset ORDER BY satuan_id, id")
        for r in rows:
            r["foto"] = _foto_list(r["foto"])
        _tulis_atomik(ASET_FILE, json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
        _mtime = os.path.getmtime(ASET_FILE)


def _bersih(a):
    out = {k: a.get(k) for k in FIELD}
    for k in ("lat", "lon"):
        out[k] = float(out[k]) if out[k] not in (None, "") else None
    if out["lat"] is not None and not -90 <= out["lat"] <= 90:
        raise ValueError(f"lat di luar -90..90: {out['nama']}")
    if out["lon"] is not None and not -180 <= out["lon"] <= 180:
        raise ValueError(f"lon di luar -180..180: {out['nama']}")
    out["kritis"] = max(1, min(3, int(out["kritis"] or 2)))
    foto = _foto_list(out["foto"])
    out["foto"] = json.dumps(foto, ensure_ascii=False) if foto else None
    out["satuan_id"] = int(out["satuan_id"])
    if not out["nama"] or not out["ip"]:
        raise ValueError("nama dan ip wajib diisi")
    return out


def muat_aset(paksa=False):
    """Baca aset.json ke database jika file berubah. Kunci: id (jika ada), lalu ip.
    Aset yang dihapus dari file ikut dihapus dari daftar aset (event lamanya tetap ada)."""
    global _mtime
    with _lock:
        if not os.path.exists(ASET_FILE):
            ekspor_aset()
            return {"dimuat": False}
        m = os.path.getmtime(ASET_FILE)
        if not paksa and m == _mtime:
            return {"dimuat": False}
        try:
            with open(ASET_FILE, encoding="utf-8-sig") as f:
                data = [_bersih(a) for a in json.load(f)]
        except (ValueError, TypeError, KeyError) as ex:
            _mtime = m  # jangan coba ulang file rusak yang sama terus-menerus
            print("aset.json tidak valid, diabaikan:", ex)
            db.audit("sistem", "aset_file_tidak_valid", str(ex)[:300])
            return {"dimuat": False, "galat": str(ex)}
        simpan = set()
        for a in data:
            ada = (db.one("SELECT id FROM aset WHERE id=?", (a["id"],)) if a["id"] else None) or \
                db.one("SELECT id FROM aset WHERE ip=?", (a["ip"],))
            vals = tuple(a[k] for k in FIELD[1:])
            if ada:
                db.x("UPDATE aset SET satuan_id=?,nama=?,jenis=?,kategori=?,ip=?,mac=?,kritis=?,lat=?,lon=?,foto=? WHERE id=?",
                     vals + (ada["id"],))
                simpan.add(ada["id"])
            else:
                simpan.add(db.x("INSERT INTO aset(satuan_id,nama,jenis,kategori,ip,mac,kritis,lat,lon,foto) "
                                "VALUES(?,?,?,?,?,?,?,?,?,?)", vals))
            if a["mac"]:
                db.x("INSERT OR IGNORE INTO perangkat_dikenal VALUES(?,?,?,1)", (a["mac"].lower(), a["ip"], time.time()))
        for r in db.q("SELECT id FROM aset"):
            if r["id"] not in simpan:
                db.x("DELETE FROM aset WHERE id=?", (r["id"],))
        db.audit("sistem", "aset_dimuat_dari_file", f"{len(data)} aset dari aset.json")
        ekspor_aset()  # tulis ulang dengan id agar suntingan berikutnya stabil
        return {"dimuat": True, "jumlah": len(data)}


def simpan_aset(a, aid=None):
    if aid and "foto" not in a:  # form UI tidak mengirim foto: pertahankan yang ada
        a = {**a, "foto": (db.one("SELECT foto FROM aset WHERE id=?", (aid,)) or {}).get("foto")}
    a = _bersih({**a, "id": aid})
    vals = tuple(a[k] for k in FIELD[1:])
    with _lock:
        if aid:
            db.x("UPDATE aset SET satuan_id=?,nama=?,jenis=?,kategori=?,ip=?,mac=?,kritis=?,lat=?,lon=?,foto=? WHERE id=?",
                 vals + (aid,))
        else:
            aid = db.x("INSERT INTO aset(satuan_id,nama,jenis,kategori,ip,mac,kritis,lat,lon,foto) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       vals)
        if a["mac"]:
            db.x("INSERT OR IGNORE INTO perangkat_dikenal VALUES(?,?,?,1)", (a["mac"].lower(), a["ip"], time.time()))
        ekspor_aset()
    return aid


def pantau_aset(interval=3):
    def loop():
        while True:
            time.sleep(interval)
            try:
                muat_aset()
            except Exception as ex:  # pemantau tidak boleh mati
                print("pantau aset:", ex)
    threading.Thread(target=loop, daemon=True).start()


# ---------- Arsip insiden / audit / sitrep ----------
def simpan_insiden(iid):
    inc = db.one("SELECT i.*, a.nama aset_nama, s.nama satuan_nama FROM insiden i LEFT JOIN aset a ON a.id=i.aset_id "
                 "LEFT JOIN satuan s ON s.id=i.satuan_id WHERE i.id=?", (iid,))
    if not inc:
        return
    try:
        ids = json.loads(inc["event_ids"] or "[]")
    except ValueError:
        ids = []
    inc["event_ids"] = ids
    inc["korelasi"] = json.loads(inc["korelasi"]) if (inc["korelasi"] or "").startswith("{") else inc["korelasi"]
    inc["event"] = db.q(f"SELECT id, ts, sumber, jenis, src_ip, dst_ip, dst_port, severity, mitre, pesan FROM event "
                        f"WHERE id IN ({','.join('?' * len(ids))}) ORDER BY ts", ids) if ids else []
    inc["waktu"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(inc["ts"]))
    inc["diarsipkan"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _tulis_atomik(os.path.join(ARSIP, "insiden", f"insiden-{iid:04d}.json"),
                  json.dumps(inc, ensure_ascii=False, indent=2) + "\n")


_sitrep_status = {}  # insiden_id -> status terakhir yang sudah dibuatkan sitrep otomatis


def sitrep_otomatis(iid, status):
    """Simpan sitrep PDF otomatis saat insiden baru muncul dan setiap statusnya berubah.
    Tidak dihitung sebagai 'sudah dilaporkan' (lampu Sitrep tetap menunggu operator mengunduh/mengirim)."""
    if _sitrep_status.get(iid) == status:
        return None
    from . import sitrep  # impor di sini untuk menghindari impor melingkar
    pdf = sitrep.build(iid, "sistem (otomatis)")
    if not pdf:
        return None
    _sitrep_status[iid] = status
    nama = f"sitrep-{iid:04d}-otomatis-{status}-{time.strftime('%Y%m%d-%H%M%S')}.pdf"
    os.makedirs(os.path.join(ARSIP, "sitrep"), exist_ok=True)
    with open(os.path.join(ARSIP, "sitrep", nama), "wb") as f:
        f.write(pdf)
    db.audit("sistem", "sitrep_otomatis", nama)
    return nama


def on_publish(kind, payload):
    """Pendengar engine.publish: setiap insiden dibuat/berubah ditulis ulang ke arsip + sitrep otomatis."""
    try:
        if kind == "insiden" and payload and payload.get("id"):
            simpan_insiden(payload["id"])
            sitrep_otomatis(payload["id"], payload.get("status") or "baru")
        elif kind == "reset":
            for r in db.q("SELECT id, status FROM insiden WHERE updated>=?", (payload["ts"] - 1,)):
                simpan_insiden(r["id"])
                sitrep_otomatis(r["id"], r["status"])
    except Exception as ex:
        print("arsip insiden:", ex)


def tulis_audit(row):
    try:
        path = os.path.join(ARSIP, "audit", time.strftime("audit-%Y-%m-%d.jsonl", time.localtime(row["ts"])))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        row = {**row, "waktu": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["ts"]))}
        with _lock, open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError as ex:
        print("arsip audit:", ex)


def simpan_sitrep(iid, pdf):
    nama = f"sitrep-{iid:04d}-{time.strftime('%Y%m%d-%H%M%S')}.pdf"
    path = os.path.join(ARSIP, "sitrep", nama)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(pdf)
    return nama


def sinkron_awal():
    """Isi arsip untuk data yang sudah ada sebelum fitur arsip dipasang (sekali, saat start)."""
    # Ingat status yang sudah punya sitrep otomatis agar restart server tidak membuat salinan ganda.
    d = os.path.join(ARSIP, "sitrep")
    if os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            m = re.match(r"sitrep-(\d+)-otomatis-([a-z]+)-", f)
            if m:
                _sitrep_status[int(m.group(1))] = m.group(2)
    for r in db.q("SELECT id FROM insiden"):
        if not os.path.exists(os.path.join(ARSIP, "insiden", f"insiden-{r['id']:04d}.json")):
            simpan_insiden(r["id"])
    d = os.path.join(ARSIP, "audit")
    if not os.path.isdir(d) or not os.listdir(d):
        for r in db.q("SELECT * FROM audit ORDER BY id"):
            tulis_audit(r)


def tampil_path(p):
    """Path relatif terhadap folder data, untuk ditampilkan di UI."""
    return "data/" + os.path.relpath(p, DATA_DIR).replace(os.sep, "/")


def daftar():
    out = {"folder": tampil_path(ARSIP), "aset_file": tampil_path(ASET_FILE)}
    for j in JENIS:
        d = os.path.join(ARSIP, j)
        files = sorted((f for f in os.listdir(d) if not f.endswith(".tmp")), reverse=True) if os.path.isdir(d) else []
        items = []
        for f in files[:300]:
            p = os.path.join(d, f)
            st = os.stat(p)
            it = {"nama": f, "ukuran": st.st_size, "diubah": st.st_mtime}
            if j == "insiden":
                try:
                    with open(p, encoding="utf-8") as fh:
                        inc = json.load(fh)
                    it.update({k: inc.get(k) for k in ("id", "judul", "severity", "status", "ts", "satuan_nama", "mitre")})
                except (OSError, ValueError):
                    pass
            elif j == "audit":
                with open(p, encoding="utf-8") as fh:
                    it["baris"] = sum(1 for _ in fh)
            items.append(it)
        out[j] = items
    return out


_NAMA = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


def path_file(jenis, nama):
    if jenis not in JENIS or not _NAMA.match(nama) or nama.startswith("."):
        return None
    p = os.path.join(ARSIP, jenis, nama)
    return p if os.path.isfile(p) else None


# ---------- Foto aset ----------
# Slot kosong memakai foto contoh per kategori dari data/foto/stok/<kategori>-<n>.jpg (lihat tools/unduh_foto_unsplash.py),
# dengan kredit fotografer di data/foto/stok/kredit.json. Foto asli diunggah lewat UI atau ditaruh di data/foto/
# lalu namanya ditulis di aset.json ("foto": ["cctv-gerbang-1.jpg", null, null, null]).
def slug(teks):
    return re.sub(r"[^a-z0-9]+", "-", (teks or "").lower()).strip("-") or "umum"


def _kredit():
    try:
        with open(os.path.join(FOTO_DIR, "stok", "kredit.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def foto_aset(aid):
    a = db.one("SELECT id, kategori, foto FROM aset WHERE id=?", (aid,))
    if not a:
        return None
    asli, kredit, out = _foto_list(a["foto"]) or [None] * 4, _kredit(), []
    for i in range(4):
        nama, sumber = asli[i], "asli"
        if not nama or not os.path.isfile(os.path.join(FOTO_DIR, nama)):
            nama, sumber = None, "kosong"
            for kat in (slug(a["kategori"]), "umum"):
                for ext in ("jpg", "jpeg", "png", "webp"):
                    c = f"stok/{kat}-{i + 1}.{ext}"
                    if os.path.isfile(os.path.join(FOTO_DIR, c)):
                        nama, sumber = c, "contoh"
                        break
                if nama:
                    break
        out.append({"slot": i + 1, "nama": nama, "sumber": sumber, "kredit": kredit.get(nama) if nama else None})
    return out


def path_foto(nama):
    if not _NAMA_FOTO.match(nama or ""):
        return None
    p = os.path.join(FOTO_DIR, nama)
    return p if os.path.isfile(p) else None


def simpan_foto(aid, slot, data, ext):
    a = db.one("SELECT foto FROM aset WHERE id=?", (aid,))
    if not a:
        return None
    nama = f"aset-{aid}-{slot}-{int(time.time())}.{ext}"
    os.makedirs(FOTO_DIR, exist_ok=True)
    with open(os.path.join(FOTO_DIR, nama), "wb") as f:
        f.write(data)
    with _lock:
        foto = _foto_list(a["foto"]) or [None] * 4
        foto[slot - 1] = nama
        db.x("UPDATE aset SET foto=? WHERE id=?", (json.dumps(foto), aid))
        ekspor_aset()
    return nama


def hapus_foto(aid, slot):
    """Kosongkan slot (kembali ke foto contoh). File lama tidak dihapus dari disk."""
    a = db.one("SELECT foto FROM aset WHERE id=?", (aid,))
    if not a:
        return False
    with _lock:
        foto = _foto_list(a["foto"]) or [None] * 4
        foto[slot - 1] = None
        db.x("UPDATE aset SET foto=? WHERE id=?", (json.dumps(foto) if any(foto) else None, aid))
        ekspor_aset()
    return True
