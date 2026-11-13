"""Generator laporan situasi (sitrep) insiden siber dalam PDF."""
import io
import json
import time
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from . import db, engine


def _t(ts):
    return time.strftime("%d-%m-%Y %H:%M:%S", time.localtime(ts)) if ts else "-"


# Tindakan awal yang disarankan per aturan korelasi (acuan operator, bukan perintah otomatis)
TINDAKAN = {
    "brute": [
        "Blokir sementara IP sumber di firewall/switch markas.",
        "Ganti kata sandi akun pada aset sasaran; nonaktifkan akun bawaan pabrik.",
        "Batasi akses login aset hanya dari VLAN admin.",
    ],
    "scan": [
        "Identifikasi pemilik dan lokasi fisik IP sumber (tabel DHCP/ARP, port switch).",
        "Isolasi perangkat sumber jika bukan perangkat dinas yang dikenal.",
        "Periksa aset yang dipindai untuk port terbuka yang tidak diperlukan.",
    ],
    "dev": [
        "Lacak port switch tempat perangkat tersambung, matikan port jika tidak dikenal.",
        "Konfirmasi ke bagian terkait apakah perangkat ini perangkat dinas baru.",
        "Daftarkan ke inventaris aset bila sah.",
    ],
    "cyphy": [
        "Perintahkan regu jaga mencari kendaraan dengan plat tersebut dan memeriksa penumpangnya.",
        "Matikan port switch tempat perangkat tak dikenal tersambung.",
        "Amankan rekaman CCTV gerbang dan log jaringan sebagai barang bukti.",
        "Cocokkan dengan buku tamu: jika tamu resmi, catat perangkatnya dan tutup insiden.",
    ],
    "mal": [
        "Cabut kabel jaringan PC terdampak; jangan matikan daya sebelum bukti diamankan.",
        "Pindai ulang PC dan PC lain di subnet yang sama.",
        "Telusuri asal file (unduhan, USB, email) dan peringatkan staf terkait.",
    ],
    "iot": [
        "Kirim personel memeriksa ruangan secara fisik (AC, sumber panas, tanda kebakaran).",
        "Siapkan pemindahan beban/pemadaman terkendali perangkat kritis bila suhu terus naik.",
        "Periksa sensor dari manipulasi jika tidak ada penyebab fisik.",
    ],
}


def _aturan(inc):
    if inc.get("aturan"):
        return inc["aturan"]
    if inc.get("korelasi"):
        return "cyphy"
    return {"T1110": "brute", "T1046": "scan", "T1200": "dev"}.get(inc.get("mitre"), "mal")


def _korelasi_teks(raw):
    try:
        k = json.loads(raw)
    except (TypeError, ValueError):
        return escape(str(raw))
    if not isinstance(k, dict):
        return escape(str(raw))
    g = db.one("SELECT * FROM gerbang WHERE id=?", (k.get("gerbang_id"),)) or {}
    bagian = [f"Kendaraan tak terdaftar <b>{escape(str(k.get('plat', '-')))}</b> masuk"]
    if g:
        bagian.append(f"melalui {escape(g.get('kamera') or '-')} pada {_t(g.get('ts'))}")
    bagian.append(f"dan selang {k.get('selisih_menit', '?')} menit perangkat tak dikenal muncul di jaringan markas.")
    return " ".join(bagian)


def build(insiden_id, pelapor, kepada=None):
    inc = engine.get_incident(insiden_id)
    if not inc:
        return None
    ids = engine.eval_ids(inc["event_ids"])
    events = db.q(f"SELECT * FROM event WHERE id IN ({','.join('?' * len(ids))}) ORDER BY ts", ids) if ids else []
    satuan = db.one("SELECT * FROM satuan WHERE id=?", (inc["satuan_id"],)) or {}
    induk = db.one("SELECT * FROM satuan WHERE id=?", (satuan.get("parent_id"),)) or {}

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.5 * cm)
    st = getSampleStyleSheet()
    el = [
        Paragraph("LAPORAN SITUASI INSIDEN SIBER (SITREP)", st["Title"]),
        Paragraph(f"Nomor: SITREP/{inc['id']:04d}/{time.strftime('%m/%Y')} &nbsp;&nbsp; Klasifikasi: TERBATAS", st["Normal"]),
        Spacer(1, 10),
    ]
    rows = [
        ["Satuan pelapor", satuan.get("nama", "-")],
        ["Kepada", Paragraph(escape(kepada), st["Normal"]) if kepada else f"{induk.get('nama', '-')} u.p. Kartika CSIRT"],
        ["Waktu kejadian", _t(inc["ts"])],
        ["Waktu laporan", _t(time.time())],
        ["Judul insiden", Paragraph(escape(inc["judul"]), st["Normal"])],
        ["Tingkat", inc["severity"].upper()],
        ["Teknik MITRE ATT&CK", inc["mitre"] or "-"],
        ["Aset terdampak", inc.get("aset_nama") or "-"],
        ["Status penanganan", inc["status"].upper()],
        ["Pelapor", pelapor],
    ]
    t = Table(rows, colWidths=[5 * cm, 11 * cm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                           ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    el += [t, Spacer(1, 12)]
    if inc["korelasi"]:
        el += [Paragraph("Korelasi siber-fisik", st["Heading3"]), Paragraph(_korelasi_teks(inc["korelasi"]), st["Normal"]),
               Spacer(1, 8)]
    langkah = TINDAKAN.get(_aturan(inc), [])
    if langkah:
        el += [Paragraph("Tindakan yang disarankan", st["Heading3"])]
        el += [Paragraph(f"{n}. {escape(t)}", st["Normal"]) for n, t in enumerate(langkah, 1)]
        el += [Spacer(1, 8)]
    if inc["catatan"]:
        el += [Paragraph("Catatan operator", st["Heading3"]), Paragraph(escape(inc["catatan"]).replace("\n", "<br/>"), st["Normal"]), Spacer(1, 8)]
    el.append(Paragraph(f"Kronologi ({len(events)} event)", st["Heading3"]))
    kr = [["Waktu", "Sumber", "Asal", "Keterangan"]] + [
        [_t(e["ts"]), e["sumber"], e["src_ip"] or "-", Paragraph(escape((e["pesan"] or "")[:140]), st["BodyText"])]
        for e in events[:40]]
    k = Table(kr, colWidths=[3.6 * cm, 2 * cm, 2.6 * cm, 7.8 * cm], repeatRows=1)
    k.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                           ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    el += [k, Spacer(1, 12),
           Paragraph("Dibuat otomatis oleh NetraGatra. Data dalam purwarupa ini fiktif.", st["Italic"])]
    doc.build(el)
    return buf.getvalue()
