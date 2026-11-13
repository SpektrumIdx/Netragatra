"""Penyimpanan SQLite sederhana untuk NetraGatra (offline, satu file)."""
import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get("NETRA_DB", os.path.join(os.path.dirname(__file__), "..", "..", "data", "netragatra.db"))
_lock = threading.RLock()
_conn = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS satuan(
  id INTEGER PRIMARY KEY, nama TEXT, tingkat TEXT, parent_id INTEGER);
CREATE TABLE IF NOT EXISTS aset(
  id INTEGER PRIMARY KEY, satuan_id INTEGER, nama TEXT, jenis TEXT, kategori TEXT,
  ip TEXT, mac TEXT, kritis INTEGER);
CREATE TABLE IF NOT EXISTS kendaraan(
  plat TEXT PRIMARY KEY, pemilik TEXT, satuan_id INTEGER);
CREATE TABLE IF NOT EXISTS perangkat_dikenal(
  mac TEXT PRIMARY KEY, ip TEXT, first_seen REAL, dikenal INTEGER);
CREATE TABLE IF NOT EXISTS event(
  id INTEGER PRIMARY KEY, ts REAL, sumber TEXT, jenis TEXT, src_ip TEXT, dst_ip TEXT,
  dst_port INTEGER, aset_id INTEGER, satuan_id INTEGER, severity TEXT, mitre TEXT, pesan TEXT, raw TEXT);
CREATE TABLE IF NOT EXISTS gerbang(
  id INTEGER PRIMARY KEY, ts REAL, satuan_id INTEGER, plat TEXT, arah TEXT, terdaftar INTEGER,
  pemilik TEXT, kamera TEXT, confidence REAL);
CREATE TABLE IF NOT EXISTS insiden(
  id INTEGER PRIMARY KEY, ts REAL, satuan_id INTEGER, aset_id INTEGER, judul TEXT, severity TEXT,
  mitre TEXT, status TEXT, korelasi TEXT, event_ids TEXT, catatan TEXT, updated REAL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts REAL, pengguna TEXT, aksi TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS telemetri(
  id INTEGER PRIMARY KEY, ts REAL, ip TEXT, aset_id INTEGER, satuan_id INTEGER, suhu REAL, kelembapan REAL);
CREATE TABLE IF NOT EXISTS distribusi(
  id INTEGER PRIMARY KEY, insiden_id INTEGER, ts REAL, jenjang INTEGER, satuan_id INTEGER, penerima TEXT,
  sitrep TEXT, pengirim TEXT, cara TEXT, diakui_ts REAL, diakui_oleh TEXT, catatan TEXT);
CREATE INDEX IF NOT EXISTS ix_distribusi_ins ON distribusi(insiden_id);
CREATE INDEX IF NOT EXISTS ix_telemetri_ts ON telemetri(ts);
CREATE INDEX IF NOT EXISTS ix_event_ts ON event(ts);
CREATE INDEX IF NOT EXISTS ix_gerbang_ts ON gerbang(ts);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
"""


def conn():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        # Migrasi: kolom 'aturan' (brute/scan/dev/cyphy/mal) untuk panel lampu. DB lama tetap jalan.
        cols = {r[1] for r in _conn.execute("PRAGMA table_info(insiden)")}
        if "aturan" not in cols:
            _conn.execute("ALTER TABLE insiden ADD COLUMN aturan TEXT")
        # Migrasi: koordinat GPS aset (peta).
        cols = {r[1] for r in _conn.execute("PRAGMA table_info(aset)")}
        for c in ("lat", "lon"):
            if c not in cols:
                _conn.execute(f"ALTER TABLE aset ADD COLUMN {c} REAL")
        # Nama satuan lama berlabel "Contoh" diganti nama fiktif baru (database dari versi sebelumnya).
        for lama, baru in (("Kodam Contoh I", "Kodam Satria Nusa"), ("Korem 011/Contoh", "Korem 011/Satria Wira")):
            _conn.execute("UPDATE satuan SET nama=? WHERE nama=?", (baru, lama))
        _conn.execute("UPDATE kendaraan SET pemilik='Serma Budi (staf)' WHERE pemilik='Serma Contoh (staf)'")
        if "foto" not in cols:  # daftar nama file foto aset (JSON), maks 4
            _conn.execute("ALTER TABLE aset ADD COLUMN foto TEXT")
        if "lat" not in cols:  # database lama: beri koordinat demo agar peta langsung terisi
            gps = _gps_demo()
            for aid, sid in _conn.execute("SELECT id, satuan_id FROM aset ORDER BY id").fetchall():
                _conn.execute("UPDATE aset SET lat=?, lon=? WHERE id=?", gps(sid) + (aid,))
        _conn.commit()
    return _conn


def q(sql, args=()):
    with _lock:
        return [dict(r) for r in conn().execute(sql, args).fetchall()]


def one(sql, args=()):
    r = q(sql, args)
    return r[0] if r else None


def x(sql, args=()):
    with _lock:
        c = conn().execute(sql, args)
        conn().commit()
        return c.lastrowid


audit_hooks = []  # fungsi(row) dipanggil setiap baris audit baru (arsip harian di direktori)


def audit(pengguna, aksi, detail=""):
    ts = time.time()
    aid = x("INSERT INTO audit(ts,pengguna,aksi,detail) VALUES(?,?,?,?)", (ts, pengguna, aksi, detail))
    for fn in audit_hooks:
        fn({"id": aid, "ts": ts, "pengguna": pengguna, "aksi": aksi, "detail": detail})


def _gps_demo():
    """Koordinat GPS FIKTIF: diletakkan di area publik (bukan lokasi markas sungguhan) hanya untuk demo peta.
    Jangan pernah menaruh koordinat markas asli di repo atau link publik."""
    pusat = {3: (-6.21820, 106.80230), 4: (-6.59760, 106.79960), 5: (-6.30250, 106.89520)}
    off = {}

    def gps(sid):
        if sid not in pusat:
            return None, None
        n = off.get(sid, 0)
        off[sid] = n + 1
        la, lo = pusat[sid]
        return round(la + (n % 3 - 1) * 0.0006, 6), round(lo + (n // 3 - 1) * 0.0007, 6)
    return gps


def seed_if_empty():
    """Data contoh fiktif. Nama satuan dan aset sengaja fiktif, bukan data TNI AD sungguhan."""
    if one("SELECT COUNT(*) n FROM satuan")["n"]:
        return
    satuan = [
        (1, "Kodam Satria Nusa", "Kodam", None),
        (2, "Korem 011/Satria Wira", "Korem", 1),
        (3, "Kodim 0101/Alfa", "Kodim", 2),
        (4, "Kodim 0102/Bravo", "Kodim", 2),
        (5, "Yonif 100/Charlie", "Batalyon", 2),
    ]
    for s in satuan:
        x("INSERT INTO satuan VALUES(?,?,?,?)", s)
    gps = _gps_demo()
    aset = [
        # satuan_id, nama, jenis, kategori, ip, mac, kritis(1-3)
        (3, "CCTV Gerbang Utama", "OT", "Pengamanan fisik", "10.10.3.21", "aa:bb:cc:03:00:21", 3),
        (3, "Kontrol Akses Gerbang", "OT", "Pengamanan fisik", "10.10.3.22", "aa:bb:cc:03:00:22", 3),
        (3, "UPS Ruang Server", "OT", "Pendukung markas", "10.10.3.30", "aa:bb:cc:03:00:30", 2),
        (3, "Server Aplikasi Dinas", "IT", "Server", "10.10.3.10", "aa:bb:cc:03:00:10", 3),
        (3, "PC Staf Intel", "IT", "Endpoint", "10.10.3.101", "aa:bb:cc:03:01:01", 2),
        (3, "PC Staf Personel", "IT", "Endpoint", "10.10.3.102", "aa:bb:cc:03:01:02", 2),
        (3, "Gateway Radio", "OT", "Komunikasi", "10.10.3.40", "aa:bb:cc:03:00:40", 3),
        (4, "CCTV Gerbang Utama", "OT", "Pengamanan fisik", "10.10.4.21", "aa:bb:cc:04:00:21", 3),
        (4, "Server Aplikasi Dinas", "IT", "Server", "10.10.4.10", "aa:bb:cc:04:00:10", 3),
        (5, "CCTV Gudang", "OT", "Pengamanan fisik", "10.10.5.21", "aa:bb:cc:05:00:21", 3),
        (5, "Sensor Suhu Gudang", "OT", "IoT lingkungan", "10.10.5.50", "aa:bb:cc:05:00:50", 2),
        (3, "Sensor Suhu & Kelembapan Ruang Server", "OT", "IoT lingkungan", "10.10.3.51", "aa:bb:cc:03:00:51", 3),
        (5, "Sensor Kelembapan Gudang Logistik", "OT", "IoT lingkungan", "10.10.5.51", "aa:bb:cc:05:00:51", 2),
        (5, "Website Satuan", "IT", "Layanan publik", "10.10.5.80", "aa:bb:cc:05:00:80", 2),
    ]
    for a in aset:
        x("INSERT INTO aset(satuan_id,nama,jenis,kategori,ip,mac,kritis,lat,lon) VALUES(?,?,?,?,?,?,?,?,?)", a + gps(a[0]))
        x("INSERT OR IGNORE INTO perangkat_dikenal VALUES(?,?,?,1)", (a[5], a[4], time.time()))
    for plat, pemilik, sid in [
        ("B 1234 TNI", "Kendaraan Dinas Dandim", 3),
        ("B 5678 ABC", "Serma Budi (staf)", 3),
        ("D 4321 XYZ", "Kendaraan logistik", 3),
    ]:
        x("INSERT INTO kendaraan VALUES(?,?,?)", (plat, pemilik, sid))


def aset_by_ip(ip):
    return one("SELECT * FROM aset WHERE ip=?", (ip,)) if ip else None


def dumps(o):
    return json.dumps(o, ensure_ascii=False)
