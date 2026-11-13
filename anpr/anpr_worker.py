"""Worker ANPR: membaca CCTV gerbang (RTSP atau file video), mengenali plat, kirim ke NetraGatra.

Mode:
  --source rtsp://user:pass@10.10.3.21/stream1     kamera IP (RTSP)
  --source http://192.168.1.5:8080/video           HP Android dengan aplikasi IP Webcam
  --source 0                                       webcam laptop
  --source rekaman_gerbang.mp4                     rekaman (cadangan demo)
  --manual                                         ketik plat di terminal (untuk uji alur tanpa kamera)

Pengenalan plat memakai paket open source `fast-alpr` (detektor YOLO + OCR plat).
  pip install "fast-alpr[onnx]"
  (tanpa [onnx], onnxruntime tidak ikut terpasang dan import fast_alpr gagal)
Model diunduh dari GitHub saat pertama jalan: jalankan sekali dengan internet sebelum demo.
Akurasi plat Indonesia harus diuji di malam hari dan sudut miring sebelum demo.
"""
import argparse
import json
import os
import re
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PLAT_RE = re.compile(r"^([A-Z]{1,2})(\d{1,4})([A-Z]{0,3})$")


def normalisasi(teks):
    t = re.sub(r"[^A-Z0-9]", "", (teks or "").upper())
    m = PLAT_RE.match(t)
    return " ".join(p for p in m.groups() if p) if m else None


def kirim(url, key, plat, satuan_id, conf, kamera, arah):
    body = {"plat": plat, "satuan_id": satuan_id, "confidence": round(conf, 2), "kamera": kamera, "arah": arah}
    req = urllib.request.Request(url.rstrip("/") + "/api/ingest/gerbang", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "X-Netra-Key": key})
    try:
        urllib.request.urlopen(req, timeout=5).read()
        print(time.strftime("%H:%M:%S"), "terkirim", plat, f"{conf:.0%}", flush=True)
    except Exception as ex:  # server mati sebentar tidak boleh menghentikan worker
        print(time.strftime("%H:%M:%S"), "GAGAL kirim", plat, "-", ex, flush=True)


class StreamTerbaru:
    """Membaca stream live di thread terpisah dan hanya menyimpan frame terbaru.

    Tanpa ini, frame menumpuk di buffer saat OCR lambat dan plat baru muncul puluhan detik terlambat.
    Jika stream putus (Wi-Fi, HP terkunci), sambung ulang otomatis.
    """

    def __init__(self, source):
        import cv2
        self.cv2, self.source = cv2, source
        self.frame, self.lock = None, threading.Lock()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            cap = self.cv2.VideoCapture(self.source)
            if not cap.isOpened():
                print("kamera belum bisa dibuka, coba lagi 2 detik:", self.source, flush=True)
                time.sleep(2)
                continue
            print("kamera tersambung:", self.source, flush=True)
            while True:
                ok, frame = cap.read()
                if not ok:
                    print("stream putus, sambung ulang...", flush=True)
                    break
                with self.lock:
                    self.frame = frame
            cap.release()
            time.sleep(1)

    def read(self):
        with self.lock:
            f, self.frame = self.frame, None
        return f


def _confidence(c):
    if isinstance(c, (list, tuple)):  # fast-alpr 0.4 memberi confidence per karakter
        return min(c) if c else 0.0
    return float(c or 0.0)


def jalan_kamera(a, key):
    import cv2
    from fast_alpr import ALPR
    alpr = ALPR(detector_model="yolo-v9-t-384-license-plate-end2end",
                ocr_model="global-plates-mobile-vit-v2-model")
    src = int(a.source) if a.source.isdigit() else a.source
    live = isinstance(src, int) or "://" in a.source
    stream = StreamTerbaru(src) if live else None
    cap = None if live else cv2.VideoCapture(src)
    if cap is not None and not cap.isOpened():
        raise SystemExit(f"file video tidak bisa dibuka: {a.source}")
    terakhir = {}  # plat -> waktu terkirim (hindari duplikat saat mobil berhenti di depan kamera)
    n = 0
    while True:
        if live:
            frame = stream.read()
            if frame is None:
                time.sleep(0.05)
                continue
        else:
            ok, frame = cap.read()
            if not ok:
                break
            n += 1
            if n % a.every:
                continue
        for r in alpr.predict(frame):
            ocr = getattr(r, "ocr", None)
            if not ocr or not ocr.text:
                continue
            conf = _confidence(ocr.confidence)
            plat = normalisasi(ocr.text)
            if a.verbose:
                print("  terbaca:", ocr.text, f"{conf:.0%}", "->", plat or "format tidak cocok", flush=True)
            if not plat or conf < a.min_conf:
                continue
            if time.time() - terakhir.get(plat, 0) < a.dedup:
                continue
            terakhir[plat] = time.time()
            kirim(a.url, key, plat, a.satuan, conf, a.kamera, a.arah)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--keyfile", default=os.path.join(ROOT, "data", "ingest.key"))
    ap.add_argument("--source")
    ap.add_argument("--manual", action="store_true")
    ap.add_argument("--satuan", type=int, default=3)
    ap.add_argument("--kamera", default="CCTV Gerbang Utama")
    ap.add_argument("--arah", default="masuk", choices=["masuk", "keluar"])
    ap.add_argument("--every", type=int, default=5, help="file video: proses 1 dari N frame")
    ap.add_argument("--min-conf", type=float, default=0.6)
    ap.add_argument("--dedup", type=int, default=60, help="detik sebelum plat yang sama dicatat lagi")
    ap.add_argument("--verbose", action="store_true", help="tampilkan semua hasil OCR, untuk menyetel kamera")
    a = ap.parse_args()
    if not a.manual and not a.source:
        ap.error("pilih --source atau --manual")
    key = open(a.keyfile).read().strip()
    if a.manual:
        print("Ketik plat (contoh: B 1234 ABC), Ctrl+C untuk keluar")
        while True:
            try:
                plat = normalisasi(input("> "))
            except (EOFError, KeyboardInterrupt):
                break
            if plat:
                kirim(a.url, key, plat, a.satuan, 1.0, a.kamera, a.arah)
            else:
                print("format plat tidak dikenali")
    else:
        try:
            jalan_kamera(a, key)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
