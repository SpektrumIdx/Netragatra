"""Unduh foto contoh aset dari Unsplash (gratis, lisensi Unsplash) ke data/foto/stok/.

Jalankan SEKALI di laptop yang terhubung internet, dari folder proyek:
    python tools/unduh_foto_unsplash.py
    python tools/unduh_foto_unsplash.py --key ACCESS_KEY     # lebih stabil: API resmi (daftar gratis di unsplash.com/developers)

Hasil: data/foto/stok/<kategori>-1..4.jpg dan kredit.json (nama fotografer + tautan, ditampilkan di bawah foto).
Setelah itu NetraGatra jalan offline seperti biasa. Foto contoh dipakai untuk slot yang belum diisi foto asli.
Tanpa --key, skrip memakai endpoint pencarian publik situs Unsplash yang tidak resmi dan bisa berubah sewaktu-waktu.
"""
import argparse
import json
import os
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KATEGORI = {  # slug kategori aset -> kata kunci pencarian
    "pengamanan-fisik": "cctv security camera",
    "pendukung-markas": "electrical generator room",
    "server": "server rack data center",
    "endpoint": "office computer desk",
    "komunikasi": "radio antenna tower",
    "iot-lingkungan": "temperature sensor",
    "layanan-publik": "website laptop screen",
    "umum": "military base gate",
}
UA = {"User-Agent": "netragatra-demo/1.0", "Accept-Version": "v1"}


def ambil(url, headers=None):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def cari(q, key):
    qs = urllib.parse.urlencode({"query": q, "per_page": 10, "orientation": "landscape", "content_filter": "high"})
    if key:
        data = json.loads(ambil("https://api.unsplash.com/search/photos?" + qs, {"Authorization": "Client-ID " + key}))
    else:
        data = json.loads(ambil("https://unsplash.com/napi/search/photos?" + qs))
    return [p for p in data.get("results", []) if not p.get("premium") and not p.get("plus")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", default=os.environ.get("UNSPLASH_ACCESS_KEY"))
    ap.add_argument("--data", default=os.path.join(ROOT, "data"))
    a = ap.parse_args()
    out = os.path.join(a.data, "foto", "stok")
    os.makedirs(out, exist_ok=True)
    kp = os.path.join(out, "kredit.json")
    kredit = json.load(open(kp, encoding="utf-8")) if os.path.exists(kp) else {}
    for slug, q in KATEGORI.items():
        try:
            hasil = cari(q, a.key)[:4]
        except Exception as ex:
            print(f"[{slug}] gagal mencari: {ex}")
            continue
        for i, p in enumerate(hasil, 1):
            nama = f"{slug}-{i}.jpg"
            url = p["urls"]["raw"] + "&w=1000&q=75&fm=jpg&fit=crop&ar=4:3"
            try:
                img = ambil(url)
                with open(os.path.join(out, nama), "wb") as f:
                    f.write(img)
                if a.key and p.get("links", {}).get("download_location"):  # pedoman API: laporkan unduhan
                    ambil(p["links"]["download_location"], {"Authorization": "Client-ID " + a.key})
                u = p.get("user", {})
                kredit["stok/" + nama] = {"teks": f"Foto: {u.get('name', '?')} / Unsplash",
                                          "link": p.get("links", {}).get("html", "https://unsplash.com")}
                print(f"[{slug}] {nama}  {u.get('name')}")
            except Exception as ex:
                print(f"[{slug}] gagal unduh {nama}: {ex}")
            time.sleep(0.4)
    with open(kp, "w", encoding="utf-8") as f:
        json.dump(kredit, f, ensure_ascii=False, indent=2)
    print("Selesai. Foto di", out)


if __name__ == "__main__":
    main()
