"""Jembatan USB serial: ESP32 + DHT22 -> NetraGatra (tanpa Wi-Fi, tanpa cloud).

ESP32 mencetak baris JSON {"suhu": 27.4, "kelembapan": 61.2} lewat USB. Skrip ini meneruskannya ke
POST /api/ingest/telemetri sebagai aset tertentu (default Sensor Suhu & Kelembapan Ruang Server, 10.10.3.51).

Pakai (dari folder proyek, venv aktif, server sudah jalan):
    pip install pyserial
    python tools\\jembatan_serial.py                      # cari port ESP32 otomatis
    python tools\\jembatan_serial.py --port COM5 --aset-ip 10.10.3.51
Jika ESP32 dicabut, skrip menunggu dan menyambung lagi. Lampu IoT menjadi Waspada bila sensor senyap > 5 menit.
"""
import argparse
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cari_port():
    from serial.tools import list_ports
    kandidat = [p for p in list_ports.comports()
                if any(k in f"{p.description} {p.manufacturer or ''}".upper() for k in ("CP210", "CH340", "CH910", "USB", "UART", "SILICON"))]
    return (kandidat or list_ports.comports() or [None])[0]


def kirim(url, key, aset_ip, suhu, hum):
    body = json.dumps({"ip": aset_ip, "suhu": suhu, "kelembapan": hum}).encode()
    req = urllib.request.Request(url.rstrip("/") + "/api/ingest/telemetri", data=body,
                                 headers={"Content-Type": "application/json", "X-Netra-Key": key})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def olah_baris(baris, a, key):
    baris = baris.strip()
    if not baris.startswith("{"):
        return None
    try:
        d = json.loads(baris)
    except ValueError:
        return None
    if "info" in d:
        print(time.strftime("%H:%M:%S"), "ESP32:", d["info"], flush=True)
        return None
    if "suhu" not in d:
        return None
    suhu, hum = float(d["suhu"]), float(d.get("kelembapan")) if d.get("kelembapan") is not None else None
    hasil = kirim(a.url, key, a.aset_ip, suhu, hum)
    lv = {1: "AWAS", 2: "SIAGA", 3: "WASPADA", 4: "normal"}.get(hasil.get("level"), "?")
    print(f"{time.strftime('%H:%M:%S')}  {suhu:5.1f} °C  {hum if hum is not None else '-':>5} %  -> {a.aset_ip}  [{lv}]", flush=True)
    return hasil


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", help="mis. COM5 (Windows) atau /dev/ttyUSB0; kosong = cari otomatis")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--aset-ip", default="10.10.3.51", help="IP aset NetraGatra yang diwakili sensor ini")
    ap.add_argument("--key", default=None)
    ap.add_argument("--keyfile", default=os.path.join(ROOT, "data", "ingest.key"))
    a = ap.parse_args()
    try:
        import serial
    except ImportError:
        sys.exit("pyserial belum terpasang: pip install pyserial")
    key = a.key or open(a.keyfile).read().strip()
    while True:
        port = a.port
        if not port:
            p = cari_port()
            port = p.device if p else None
            if port:
                print("Port ESP32:", port, "-", p.description)
        if not port:
            print("ESP32 belum terdeteksi. Colok USB (pakai kabel data, bukan kabel charger saja)...")
            time.sleep(3)
            continue
        try:
            with serial.Serial(port, a.baud, timeout=2) as s:
                print(f"Tersambung {port}. Meneruskan ke {a.url} sebagai aset {a.aset_ip}. Ctrl+C untuk berhenti.")
                while True:
                    b = s.readline()
                    if b:
                        try:
                            olah_baris(b.decode("utf-8", "replace"), a, key)
                        except OSError as ex:
                            print("Server NetraGatra tidak bisa dihubungi:", ex)
        except serial.SerialException as ex:
            print("Port terputus/tidak bisa dibuka:", ex, "- mencoba lagi dalam 3 detik")
            time.sleep(3)
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
