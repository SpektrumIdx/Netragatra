"""Simulator skenario serangan NetraGatra (mode replay/demo).

Pemakaian:
  python simulate.py --url http://localhost:8000 --key <isi data/ingest.key> --skenario demo
  python simulate.py ... --skenario latar --loop      # lalu lintas normal terus-menerus untuk link juri
  python simulate.py --skenario scan                  # hanya port scan
  python simulate.py --skenario perangkat             # hanya perangkat tak dikenal (MAC acak)
  python simulate.py --skenario iot                   # probe IoT + suhu ruang server naik sampai kritis
  python simulate.py --skenario jenjang --op-pass X   # insiden kritis -> sitrep ke Korem -> naik otomatis ke Kodam

Skenario 'demo' (sekitar 2-3 menit, cocok untuk video dan panggung final):
  1. Lalu lintas normal + kendaraan terdaftar masuk
  2. Port scan dari IP penyerang di jaringan Kodim 0101/Alfa
  3. Brute force login ke CCTV Gerbang Utama
  4. Kendaraan tak terdaftar masuk gerbang
  5. Perangkat tak dikenal muncul di jaringan  -> insiden kritis korelasi siber-fisik
  6. Malware uji (EICAR) di PC Staf Personel
"""
import argparse
import json
import os
import random
import time
import urllib.request

ATT = "10.10.3.66"


class Client:
    def __init__(self, url, key, speed):
        self.url, self.key, self.speed = url.rstrip("/"), key, speed

    def post(self, path, body):
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", "X-Netra-Key": self.key})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read() or b"null")

    def ev(self, **kw):
        return self.post("/api/ingest/event", kw)

    def wait(self, s):
        time.sleep(s / self.speed)


def say(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


SENSOR_IOT = {"10.10.3.51": (24.5, 55), "10.10.5.50": (27, 60), "10.10.5.51": (28, 65)}


SENSOR_ASLI = set()  # IP aset yang sudah diisi sensor asli (ESP32): simulator tidak ikut mengirim data palsu


def iot_normal(c):
    for ip, (t, h) in SENSOR_IOT.items():
        if ip in SENSOR_ASLI:
            continue
        try:
            c.post("/api/ingest/telemetri", {"ip": ip, "suhu": round(t + random.uniform(-0.6, 0.6), 1),
                                             "kelembapan": round(h + random.uniform(-2, 2), 1)})
        except Exception as ex:  # server lama tanpa endpoint telemetri: lalu lintas lain tetap jalan
            say(f"telemetri IoT dilewati: {ex}")
            return


def iot(c):
    say("IoT: probe telnet ke sensor ruang server, lalu suhu ruang server naik (AC dimatikan)")
    for p in (23, 2323, 23, 23, 1883):
        c.ev(sumber="suricata", jenis="alert", src_ip=ATT, dst_ip="10.10.3.51", dst_port=p, severity="sedang",
             pesan=f"ET SCAN Telnet/MQTT probe ke perangkat IoT port {p}")
        c.wait(0.5)
    suhu = 25.0
    while suhu < 43:
        suhu += random.uniform(1.2, 2.0)
        c.post("/api/ingest/telemetri", {"ip": "10.10.3.51", "suhu": round(suhu, 1),
                                         "kelembapan": round(52 - (suhu - 25) * 0.8, 1)})
        say(f"   suhu ruang server {suhu:.1f} °C")
        c.wait(4)


def latar(c, n=6):
    iot_normal(c)
    for _ in range(n):
        src = random.choice(["10.10.3.101", "10.10.3.102", "10.10.4.10", "10.10.5.80"])
        c.ev(sumber="suricata", jenis="alert", src_ip=src, dst_ip="10.10.3.10", dst_port=443, severity="rendah",
             pesan=random.choice(["ET INFO TLS connection to dinas app", "ET POLICY DNS query to external resolver",
                                  "ET INFO HTTP request internal app"]))
        c.wait(random.uniform(0.5, 1.5))


def demo(c):
    say("1) Aktivitas normal dan kendaraan dinas masuk")
    c.post("/api/ingest/gerbang", {"plat": "B 1234 TNI", "satuan_id": 3})
    latar(c, 5)

    say("2) Port scan dari penyerang " + ATT)
    ports = random.sample(range(20, 9000), 25)
    for p in ports:
        c.ev(sumber="netflow", jenis="conn", src_ip=ATT, dst_ip=random.choice(["10.10.3.21", "10.10.3.10", "10.10.3.40"]),
             dst_port=p, severity="rendah", pesan=f"Koneksi SYN ke port {p}")
        c.wait(0.2)
    c.wait(4)

    say("3) Brute force login ke CCTV Gerbang Utama")
    for u in ["admin", "admin", "root", "admin", "operator", "admin", "user"]:
        c.ev(sumber="wazuh", jenis="auth_fail", src_ip=ATT, dst_ip="10.10.3.21", severity="sedang",
             pesan=f"Login gagal ke antarmuka web kamera, user '{u}'")
        c.wait(1.2)
    c.wait(5)

    say("4) Kendaraan tak terdaftar masuk gerbang")
    c.post("/api/ingest/gerbang", {"plat": "F 9087 QZ", "satuan_id": 3, "confidence": 0.87})
    latar(c, 3)
    c.wait(6)

    say("5) Perangkat tak dikenal muncul di jaringan markas")
    c.post("/api/ingest/perangkat", {"mac": "de:ad:be:ef:10:66", "ip": "10.10.3.77", "satuan_id": 3})
    c.wait(5)

    say("6) Malware uji EICAR di PC Staf Personel")
    c.ev(sumber="wazuh", jenis="malware", src_ip="10.10.3.102", dst_ip="10.10.3.102", severity="tinggi",
         mitre="T1204", pesan="File EICAR-Test-File terdeteksi di C:\\Users\\staf\\Downloads")
    say("Selesai. Buka tampilan Komandan untuk melihat status satuan.")


def scan(c):
    say("Port scan dari penyerang " + ATT)
    for p in random.sample(range(20, 9000), 25):
        c.ev(sumber="netflow", jenis="conn", src_ip=ATT, dst_ip=random.choice(["10.10.3.21", "10.10.3.10", "10.10.3.40"]),
             dst_port=p, severity="rendah", pesan=f"Koneksi SYN ke port {p}")
        c.wait(0.2)


def perangkat(c):
    # MAC acak agar bisa diulang tanpa reset database (MAC yang sudah pernah terlihat dianggap dikenal)
    mac = "de:ad:be:ef:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255))
    say(f"Perangkat tak dikenal {mac} muncul di 10.10.3.77")
    c.post("/api/ingest/perangkat", {"mac": mac, "ip": "10.10.3.77", "satuan_id": 3})


def _login(c, user, pw):
    req = urllib.request.Request(c.url + "/api/login", data=json.dumps({"username": user, "password": pw}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())["token"]


def _api(c, tok, path, body=None):
    req = urllib.request.Request(c.url + path, data=None if body is None else json.dumps(body).encode(),
                                 method="GET" if body is None else "POST",
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + tok})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"null")


def jenjang(c, a):
    """Insiden kritis -> operator triase -> sitrep ke Korem (jenjang 1) -> belum diakui -> naik otomatis ke Kodam (jenjang 2)."""
    if not a.op_pass:
        raise SystemExit("Skenario jenjang butuh password operator: --op-pass ... (dan opsional --kom-pass ... untuk pengakuan)")
    say("1) Brute force SSH ke Server Aplikasi Dinas Kodim 0102/Bravo (aset kritis)")
    src = "10.10.4.%d" % random.randint(150, 250)
    for u in ["root", "admin", "root", "dinas", "admin", "root"]:
        c.ev(sumber="wazuh", jenis="auth_fail", src_ip=src, dst_ip="10.10.4.10", severity="sedang", mitre="T1110",
             pesan=f"sshd: authentication failure for user {u}")
        c.wait(1)
    c.wait(2)
    op = _login(c, a.op_user, a.op_pass)
    inc = next((i for i in _api(c, op, "/api/insiden") if i["status"] != "selesai" and i["mitre"] == "T1110"
                and i["satuan_id"] == 4 and i.get("aset_nama") == "Server Aplikasi Dinas"), None)
    if not inc:
        raise SystemExit("Insiden brute force tidak terbentuk; cek server")
    say(f"   insiden #{inc['id']} {inc['severity'].upper()}: {inc['judul']}")
    if inc.get("distribusi"):
        raise SystemExit(f"Insiden #{inc['id']} sudah pernah didistribusikan. Tandai Selesai dulu, atau jalankan -Reset.")
    if inc["status"] == "baru":
        say("2) Operator triase")
        _api(c, op, f"/api/insiden/{inc['id']}/status", {"status": "triase", "catatan": "Sumber dari LAN Kodim, cek port switch"})
        c.wait(3)
    say("3) Operator kirim sitrep ke jenjang 1 (Korem)")
    for r in _api(c, op, f"/api/insiden/{inc['id']}/kirim", {}):
        say(f"   -> {r['penerima']}")
    if a.manual:
        c.wait(5)
        say("4) Operator meneruskan sitrep ke jenjang 2 (Kodam)")
        _api(c, op, f"/api/insiden/{inc['id']}/kirim", {})
    else:
        d = _api(c, op, "/api/distribusi")
        m = (d.get("batas_menit") or {}).get(inc["severity"])
        say(f"4) Menunggu eskalasi otomatis: belum ada yang mengakui dalam {m} menit "
            f"(ubah \"{inc['severity']}\" di {d['file']} untuk mempercepat)")
        t0 = time.time()
        while time.time() - t0 < (m or 0) * 60 + 90:
            if any(r["insiden_id"] == inc["id"] and r["jenjang"] == 2 for r in _api(c, op, "/api/distribusi")["daftar"]):
                say("   sitrep otomatis diteruskan ke jenjang 2 (Kodam)")
                break
            time.sleep(5)
    if a.kom_pass:
        c.wait(5)
        kom = _login(c, a.kom_user, a.kom_pass)
        r = next(r for r in _api(c, kom, "/api/distribusi")["daftar"] if r["insiden_id"] == inc["id"] and not r["diakui_ts"])
        _api(c, kom, f"/api/distribusi/{r['id']}/akui", {"catatan": "Diterima, tim siber Kodam menuju lokasi"})
        say(f"5) Komandan mengakui sitrep jenjang {r['jenjang']} untuk {r['penerima']}")
    else:
        say("5) Selesai. Login komandan > tab Distribusi > tekan 'Akui' untuk menutup rantai pelaporan.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--key", help="isi data/ingest.key", default=None)
    ap.add_argument("--keyfile", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "ingest.key"))
    ap.add_argument("--skenario", choices=["demo", "latar", "scan", "perangkat", "iot", "jenjang"], default="demo")
    ap.add_argument("--op-user", default="operator")
    ap.add_argument("--op-pass", help="skenario jenjang: password operator")
    ap.add_argument("--kom-user", default="komandan")
    ap.add_argument("--kom-pass", help="skenario jenjang: password komandan (opsional, untuk pengakuan otomatis)")
    ap.add_argument("--manual", action="store_true", help="skenario jenjang: operator meneruskan sendiri tanpa menunggu batas waktu")
    ap.add_argument("--speed", type=float, default=1.0, help="2 = dua kali lebih cepat")
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--sensor-asli", action="append", default=[], metavar="IP",
                    help="IP aset yang datanya dari ESP32 asli; simulator tidak mengirim telemetri palsu untuknya")
    a = ap.parse_args()
    key = a.key or open(a.keyfile).read().strip()
    c = Client(a.url, key, a.speed)
    SENSOR_ASLI.update(a.sensor_asli)
    while True:
        if a.skenario == "jenjang":
            jenjang(c, a)
        else:
            {"demo": demo, "latar": latar, "scan": scan, "perangkat": perangkat, "iot": iot}[a.skenario](c)
        if not a.loop:
            break
        c.wait(30)


if __name__ == "__main__":
    main()
