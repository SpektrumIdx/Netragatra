"""NetraGatra: Pos Pantau Siber Markas Terpadu (purwarupa)."""
import asyncio
import hashlib
import hmac
import os
import secrets
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import arsip, db, distribusi, engine, lampu, sensors, sitrep

STATIC = os.path.join(os.path.dirname(__file__), "..", "static")
DATA_DIR = os.path.dirname(os.path.abspath(db.DB_PATH))

app = FastAPI(title="NetraGatra", docs_url=None, redoc_url=None)

# ---------- Kredensial: tidak ada password default ----------
USERS = {}      # username -> (salt, hash, peran)
TOKENS = {}     # token -> (username, peran, kedaluwarsa)
INGEST_KEY = os.environ.get("NETRA_INGEST_KEY") or ""


def _hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)


def _load_users():
    global INGEST_KEY
    spec = os.environ.get("NETRA_USERS", "")
    generated = []
    if not spec:
        for u, role in (("operator", "operator"), ("komandan", "komandan")):
            pw = secrets.token_urlsafe(9)
            generated.append(f"{u}:{pw}:{role}")
        spec = ",".join(generated)
    for item in spec.split(","):
        u, pw, role = item.split(":")
        salt = secrets.token_bytes(16)
        USERS[u] = (salt, _hash(pw, salt), role)
    if not INGEST_KEY:
        INGEST_KEY = secrets.token_urlsafe(24)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, "ingest.key"), "w") as f:
        f.write(INGEST_KEY)
    if generated:
        path = os.path.join(DATA_DIR, "kredensial-awal.txt")
        with open(path, "w") as f:
            f.write("\n".join(generated) + "\n")
        os.chmod(path, 0o600)
        print(f"Kredensial acak dibuat di {path}")


def current_user(authorization: str = Header(default="")):
    tok = authorization.removeprefix("Bearer ").strip()
    s = TOKENS.get(tok)
    if not s or s[2] < time.time():
        raise HTTPException(401, "Sesi tidak valid")
    return {"username": s[0], "peran": s[1]}


def require_operator(u=Depends(current_user)):
    if u["peran"] != "operator":
        raise HTTPException(403, "Hanya operator")
    return u


def require_komandan(u=Depends(current_user)):
    if u["peran"] != "komandan":
        raise HTTPException(403, "Hanya komandan")
    return u


def require_ingest(x_netra_key: str = Header(default="")):
    if not hmac.compare_digest(x_netra_key, INGEST_KEY):
        raise HTTPException(401, "Kunci ingest salah")


# ---------- WebSocket broadcast ----------
_clients = set()
_loop = None


def _push(kind, payload):
    if _loop is None:
        return
    for q in list(_clients):
        _loop.call_soon_threadsafe(q.put_nowait, {"kind": kind, "data": payload})


engine.listeners.append(_push)
engine.listeners.append(arsip.on_publish)
db.audit_hooks.append(arsip.tulis_audit)


def _distribusi_berubah(iid):
    engine.publish("insiden", engine.get_incident(iid))
    engine.publish("status", engine.satuan_status())
    engine.publish("distribusi", {"insiden_id": iid})


distribusi.listeners.append(_distribusi_berubah)

# Peta dasar: default OpenStreetMap (butuh internet). Untuk markas offline, arahkan ke server tile lokal,
# mis. NETRA_TILE_URL=http://10.10.3.5:8080/tile/{z}/{x}/{y}.png  (kosongkan = tanpa peta dasar, pin tetap tampil)
TILE_URL = os.environ.get("NETRA_TILE_URL", "https://tile.openstreetmap.org/{z}/{x}/{y}.png")
TILE_ATTR = os.environ.get("NETRA_TILE_ATTR", "© OpenStreetMap contributors")
_tile_origin = "/".join(TILE_URL.split("/")[:3]) if TILE_URL.startswith("http") else ""


@app.on_event("startup")
async def startup():
    global _loop
    _loop = asyncio.get_running_loop()
    db.conn()
    db.seed_if_empty()
    _load_users()
    arsip.muat_aset(paksa=True)
    arsip.sinkron_awal()
    arsip.pantau_aset()
    distribusi.cfg()
    distribusi.mulai()
    sensors.start()


# ---------- Auth ----------
class Login(BaseModel):
    username: str
    password: str


_fails = {}


@app.post("/api/login")
def login(body: Login, request: Request):
    ip = request.client.host if request.client else "?"
    n, t0 = _fails.get(ip, (0, time.time()))
    if n >= 5 and time.time() - t0 < 300:
        raise HTTPException(429, "Terlalu banyak percobaan, tunggu 5 menit")
    u = USERS.get(body.username)
    if not u or not hmac.compare_digest(_hash(body.password, u[0]), u[1]):
        _fails[ip] = (n + 1, t0 if n else time.time())
        db.audit(body.username[:32], "login_gagal", ip)
        raise HTTPException(401, "Username atau password salah")
    _fails.pop(ip, None)
    tok = secrets.token_urlsafe(32)
    TOKENS[tok] = (body.username, u[2], time.time() + 8 * 3600)
    db.audit(body.username, "login", ip)
    return {"token": tok, "peran": u[2], "username": body.username}


# ---------- Data ----------
@app.get("/api/satuan")
def satuan(u=Depends(current_user)):
    return engine.satuan_status()


@app.get("/api/lampu")
def panel_lampu(u=Depends(current_user)):
    return lampu.hitung()


class Reset(BaseModel):
    catatan: str


@app.post("/api/situasi/reset")
def situasi_reset(body: Reset, u=Depends(require_komandan)):
    catatan = body.catatan.strip()[:500]
    if len(catatan) < 5:
        raise HTTPException(400, "Catatan wajib diisi (minimal 5 karakter): dasar menyatakan situasi tertangani")
    return engine.reset_situasi(u["username"], catatan)


@app.get("/api/lampu/{fid}")
def panel_detail(fid: str, menit: int = 60, u=Depends(current_user)):
    d = lampu.detail(fid, menit)
    if not d:
        raise HTTPException(404, "Fitur tidak ditemukan atau belum aktif")
    return d


@app.get("/api/aset")
def aset(u=Depends(current_user)):
    arsip.muat_aset()  # ambil suntingan terbaru dari aset.json bila ada
    return db.q("""SELECT a.*, s.nama satuan_nama,
                   (SELECT COUNT(*) FROM event e WHERE e.aset_id=a.id AND e.ts>?) event_24j,
                   (SELECT MIN(CASE severity WHEN 'kritis' THEN 1 WHEN 'tinggi' THEN 2 WHEN 'sedang' THEN 3 ELSE 4 END)
                      FROM insiden i WHERE i.aset_id=a.id AND i.status!='selesai') level
                   FROM aset a JOIN satuan s ON s.id=a.satuan_id ORDER BY a.satuan_id, a.kritis DESC""",
                (time.time() - 86400,))


@app.get("/api/config")
def config(u=Depends(current_user)):
    return {"tile_url": TILE_URL, "tile_attr": TILE_ATTR}


class AsetIn(BaseModel):
    satuan_id: int
    nama: str
    jenis: str = "OT"
    kategori: str = "Pengamanan fisik"
    ip: str
    mac: str | None = None
    kritis: int = 2
    lat: float | None = None
    lon: float | None = None


def _aset_ok(a: AsetIn, aid=None):
    if not db.one("SELECT id FROM satuan WHERE id=?", (a.satuan_id,)):
        raise HTTPException(400, "Satuan tidak dikenal")
    dup = db.one("SELECT id FROM aset WHERE ip=? AND id IS NOT ?", (a.ip.strip(), aid))
    if dup:
        raise HTTPException(400, f"IP {a.ip} sudah dipakai aset lain")
    try:
        return arsip.simpan_aset({**a.model_dump(), "nama": a.nama.strip()[:120], "ip": a.ip.strip()}, aid)
    except ValueError as ex:
        raise HTTPException(400, str(ex))


@app.post("/api/aset")
def aset_tambah(a: AsetIn, u=Depends(require_operator)):
    aid = _aset_ok(a)
    db.audit(u["username"], "aset_ditambah", f"#{aid} {a.nama} {a.ip} ({a.lat}, {a.lon})")
    return db.one("SELECT * FROM aset WHERE id=?", (aid,))


@app.put("/api/aset/{aid}")
def aset_ubah(aid: int, a: AsetIn, u=Depends(require_operator)):
    if not db.one("SELECT id FROM aset WHERE id=?", (aid,)):
        raise HTTPException(404)
    _aset_ok(a, aid)
    db.audit(u["username"], "aset_diubah", f"#{aid} {a.nama} {a.ip} ({a.lat}, {a.lon})")
    return db.one("SELECT * FROM aset WHERE id=?", (aid,))


FOTO_TIPE = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp"}


@app.get("/api/aset/{aid}/foto")
def aset_foto(aid: int, u=Depends(current_user)):
    f = arsip.foto_aset(aid)
    if f is None:
        raise HTTPException(404)
    return f


@app.get("/api/foto/{nama:path}")
def foto_file(nama: str, u=Depends(current_user)):
    p = arsip.path_foto(nama)
    if not p:
        raise HTTPException(404)
    return FileResponse(p, headers={"Cache-Control": "private, max-age=300"})


@app.put("/api/aset/{aid}/foto/{slot}")
async def aset_foto_unggah(aid: int, slot: int, request: Request, u=Depends(require_operator)):
    if not 1 <= slot <= 4:
        raise HTTPException(400, "Slot foto 1-4")
    ext = FOTO_TIPE.get(request.headers.get("content-type", "").split(";")[0].strip())
    if not ext:
        raise HTTPException(400, "Format foto harus JPG, PNG, atau WEBP")
    data = await request.body()
    if not data or len(data) > 8 * 1024 * 1024:
        raise HTTPException(400, "Ukuran foto maksimal 8 MB")
    sig = {"jpg": (b"\xff\xd8",), "png": (b"\x89PNG",), "webp": (b"RIFF",)}[ext]
    if not data.startswith(sig):
        raise HTTPException(400, "Isi file bukan gambar " + ext.upper())
    nama = arsip.simpan_foto(aid, slot, data, ext)
    if not nama:
        raise HTTPException(404)
    db.audit(u["username"], "foto_aset_diganti", f"aset #{aid} slot {slot}: {nama}")
    return arsip.foto_aset(aid)


@app.delete("/api/aset/{aid}/foto/{slot}")
def aset_foto_hapus(aid: int, slot: int, u=Depends(require_operator)):
    if not 1 <= slot <= 4 or not arsip.hapus_foto(aid, slot):
        raise HTTPException(404)
    db.audit(u["username"], "foto_aset_dikosongkan", f"aset #{aid} slot {slot}")
    return arsip.foto_aset(aid)


@app.post("/api/insiden/{iid}/kirim")
def kirim_sitrep(iid: int, u=Depends(require_operator)):
    try:
        return distribusi.kirim(iid, u["username"])
    except ValueError as ex:
        raise HTTPException(400, str(ex))


@app.get("/api/distribusi")
def distribusi_daftar(u=Depends(current_user)):
    c = distribusi.cfg()
    return {"daftar": distribusi.daftar(), "batas_menit": c.get("batas_menit"), "file": arsip.tampil_path(distribusi.FILE)}


class Akui(BaseModel):
    catatan: str = ""


@app.post("/api/distribusi/{did}/akui")
def distribusi_akui(did: int, body: Akui, u=Depends(require_komandan)):
    try:
        return distribusi.akui(did, u["username"], body.catatan)
    except ValueError as ex:
        raise HTTPException(400, str(ex))


@app.get("/api/arsip")
def arsip_daftar(u=Depends(current_user)):
    return arsip.daftar()


@app.get("/api/arsip/{jenis}/{nama}")
def arsip_unduh(jenis: str, nama: str, u=Depends(current_user)):
    p = arsip.path_file(jenis, nama)
    if not p:
        raise HTTPException(404, "File arsip tidak ditemukan")
    mt = {"insiden": "application/json", "audit": "application/x-ndjson", "sitrep": "application/pdf"}[jenis]
    return FileResponse(p, media_type=mt, filename=nama)


@app.get("/api/satuan-daftar")
def satuan_daftar(u=Depends(current_user)):
    return db.q("SELECT id, nama FROM satuan ORDER BY id")


@app.get("/api/event")
def events(limit: int = 100, u=Depends(current_user)):
    return db.q("SELECT e.*, a.nama aset_nama, a.jenis aset_jenis FROM event e LEFT JOIN aset a ON a.id=e.aset_id "
                "ORDER BY e.id DESC LIMIT ?", (min(limit, 500),))


@app.get("/api/insiden")
def insiden(u=Depends(current_user)):
    rows = db.q("SELECT id FROM insiden ORDER BY CASE status WHEN 'selesai' THEN 1 ELSE 0 END, id DESC LIMIT 200")
    return [{**engine.get_incident(r["id"]), "distribusi": distribusi.ringkas(r["id"])} for r in rows]


@app.get("/api/gerbang")
def gerbang(q: str = "", u=Depends(current_user)):
    return db.q("SELECT * FROM gerbang WHERE plat LIKE ? ORDER BY id DESC LIMIT 200", (f"%{q.upper()}%",))


@app.get("/api/ringkasan")
def ringkasan(u=Depends(current_user)):
    since = time.time() - 86400
    return {
        "event_24j": db.one("SELECT COUNT(*) n FROM event WHERE ts>?", (since,))["n"],
        "insiden_terbuka": db.one("SELECT COUNT(*) n FROM insiden WHERE status!='selesai'")["n"],
        "kritis_terbuka": db.one("SELECT COUNT(*) n FROM insiden WHERE status!='selesai' AND severity='kritis'")["n"],
        "kendaraan_24j": db.one("SELECT COUNT(*) n FROM gerbang WHERE ts>?", (since,))["n"],
        "tak_terdaftar_24j": db.one("SELECT COUNT(*) n FROM gerbang WHERE ts>? AND terdaftar=0", (since,))["n"],
        "mitre": db.q("SELECT mitre, COUNT(*) n FROM insiden WHERE mitre IS NOT NULL GROUP BY mitre ORDER BY n DESC"),
    }


class Aksi(BaseModel):
    status: str
    catatan: str = ""


ALUR = {"baru": {"triase"}, "triase": {"eskalasi", "selesai"}, "eskalasi": {"selesai"}}


@app.post("/api/insiden/{iid}/status")
def ubah_status(iid: int, body: Aksi, u=Depends(require_operator)):
    inc = db.one("SELECT * FROM insiden WHERE id=?", (iid,))
    if not inc:
        raise HTTPException(404)
    if body.status not in ALUR.get(inc["status"], set()):
        raise HTTPException(400, f"Tidak bisa dari {inc['status']} ke {body.status}")
    catatan = (inc["catatan"] + "\n" if inc["catatan"] else "") + (
        f"[{time.strftime('%H:%M')}] {u['username']} ({body.status}): {body.catatan[:500]}" if body.catatan else "")
    db.x("UPDATE insiden SET status=?, catatan=?, updated=? WHERE id=?", (body.status, catatan, time.time(), iid))
    db.audit(u["username"], f"insiden_{body.status}", f"#{iid}")
    if body.status == "eskalasi" and not distribusi.jenjang_terakhir(iid):
        try:  # eskalasi = sitrep langsung dikirim ke jenjang 1 (satuan induk)
            distribusi.kirim(iid, u["username"])
        except ValueError:
            pass
    out = engine.get_incident(iid)
    engine.publish("insiden", out)
    engine.publish("status", engine.satuan_status())
    return out


@app.get("/api/insiden/{iid}/sitrep.pdf")
def unduh_sitrep(iid: int, u=Depends(current_user)):
    pdf = sitrep.build(iid, u["username"])
    if not pdf:
        raise HTTPException(404)
    nama = arsip.simpan_sitrep(iid, pdf)
    db.audit(u["username"], "sitrep_dibuat", f"#{iid}")
    db.audit(u["username"], "sitrep_diarsipkan", nama)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="sitrep-{iid:04d}.pdf"'})


@app.get("/api/audit")
def audit(u=Depends(current_user)):
    return db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 200")


# ---------- Ingest (sensor, ANPR, simulator) ----------
class EventIn(BaseModel):
    sumber: str
    jenis: str
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    satuan_id: int | None = None
    severity: str = "rendah"
    mitre: str | None = None
    pesan: str = ""
    ts: float | None = None


@app.post("/api/ingest/event", dependencies=[Depends(require_ingest)])
def ingest_event(ev: EventIn):
    return engine.ingest(ev.model_dump())


class GateIn(BaseModel):
    plat: str
    satuan_id: int
    arah: str = "masuk"
    kamera: str = "CCTV Gerbang Utama"
    confidence: float = 0.9


@app.post("/api/ingest/gerbang", dependencies=[Depends(require_ingest)])
def ingest_gate(g: GateIn):
    return engine.gate_event(g.plat.upper().strip(), g.satuan_id, g.arah, g.kamera, g.confidence)


class DeviceIn(BaseModel):
    mac: str
    ip: str
    satuan_id: int | None = None


@app.post("/api/ingest/perangkat", dependencies=[Depends(require_ingest)])
def ingest_device(d: DeviceIn):
    return engine.device_seen(d.mac.lower(), d.ip, d.satuan_id) or {"dikenal": True}


class TelemetriIn(BaseModel):
    ip: str
    suhu: float | None = None
    kelembapan: float | None = None


@app.post("/api/ingest/telemetri", dependencies=[Depends(require_ingest)])
def ingest_telemetri(t: TelemetriIn):
    return engine.telemetri(t.ip, t.suhu, t.kelembapan)


@app.websocket("/ws")
async def ws(sock: WebSocket):
    tok = sock.query_params.get("token", "")
    s = TOKENS.get(tok)
    if not s or s[2] < time.time():
        await sock.close(code=4401)
        return
    await sock.accept()
    q = asyncio.Queue()
    _clients.add(q)
    try:
        while True:
            await sock.send_json(await q.get())
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        _clients.discard(q)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; connect-src 'self' ws: wss:; "
                                               f"img-src 'self' data: blob: {_tile_origin}".strip())
    return resp


@app.get("/")
def index():
    # Tambah ?v=<waktu ubah> pada app.js/style.css agar browser tidak memakai versi lama setelah update.
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
        html = f.read()
    for nama in ("app.js", "style.css"):
        v = int(os.path.getmtime(os.path.join(STATIC, nama)))
        html = html.replace(f"/static/{nama}\"", f"/static/{nama}?v={v}\"")
    return Response(html, media_type="text/html", headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")
