# Komponen dan data pihak ketiga

| Komponen | Dipakai untuk | Lisensi | Catatan |
| --- | --- | --- | --- |
| [Leaflet 1.9.4](https://leafletjs.com) | Peta aset | BSD 2-Clause | Disertakan di `backend/static/vendor/leaflet/` beserta `LICENSE`-nya |
| [OpenStreetMap](https://www.openstreetmap.org/copyright) tiles | Peta dasar (online) | Data ODbL, © OpenStreetMap contributors | Tidak disertakan di repo, diambil saat runtime. Atribusi tampil di peta. Untuk pemakaian berat, pakai server tile sendiri (`NETRA_TILE_URL`) sesuai [kebijakan tile OSM](https://operations.osmfoundation.org/policies/tiles/) |
| [Unsplash](https://unsplash.com/license) | Foto contoh aset (opsional) | Lisensi Unsplash | **Tidak disertakan di repo.** `tools/unduh_foto_unsplash.py` mengunduhnya ke `data/foto/stok/` beserta `kredit.json`; nama fotografer tampil di bawah tiap foto |
| [FastAPI](https://fastapi.tiangolo.com), [Uvicorn](https://www.uvicorn.org) | Server web | MIT / BSD-3 | Dipasang lewat `pip` |
| [ReportLab](https://www.reportlab.com) | Sitrep PDF | BSD | Dipasang lewat `pip` |
| [fast-alpr](https://github.com/ankandrew/fast-alpr) | Pengenalan plat (opsional) | MIT | Dipasang terpisah, model diunduh saat pertama dipakai |
| Adafruit DHT sensor library | Firmware ESP32 | MIT | Dipasang lewat Arduino Library Manager |

Pola loreng di `backend/static/loreng.svg` dibuat sendiri oleh `tools/buat_loreng.py` (orisinal, bukan salinan motif resmi).
Sampel `sensor-logs/wazuh/contoh-alerts.json` dihasilkan oleh `simulator/wazuh_alert.py` (fiktif, bukan log asli).
