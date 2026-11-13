// NetraGatra UI. Semua teks dari event dirender dengan textContent (aman dari XSS).
"use strict";
let TOKEN = null, ME = null, ws = null;
const $ = (s) => document.querySelector(s);

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
const fmt = (ts) => new Date(ts * 1000).toLocaleString("id-ID", { hour12: false });
const sev = (s) => h("span", { class: "sev " + s }, s);

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", Authorization: "Bearer " + TOKEN, ...(opts.headers || {}) } });
  if (r.status === 401) { logout(); throw new Error("401"); }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r;
}
const getJ = async (p) => (await api(p)).json();

// ---------- Login ----------
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const r = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: f.get("username"), password: f.get("password") }) });
  if (!r.ok) { $("#loginErr").textContent = (await r.json()).detail; return; }
  const j = await r.json();
  TOKEN = j.token; ME = j;
  sessionStorage.setItem("netra", JSON.stringify(j));
  start();
});
// Latar loreng: bisa dimatikan per browser (disimpan di localStorage bila tersedia).
(function () {
  let on = true;
  try { on = localStorage.getItem("netra-loreng") !== "0"; } catch (_) {}
  const set = (v) => {
    on = v; document.body.classList.toggle("loreng", v);
    const b = $("#lorengBtn"); b.textContent = "Loreng: " + (v ? "ON" : "OFF"); b.setAttribute("aria-pressed", String(v));
    try { localStorage.setItem("netra-loreng", v ? "1" : "0"); } catch (_) {}
  };
  set(on);
  $("#lorengBtn").addEventListener("click", () => set(!on));
})();
function logout() { sessionStorage.removeItem("netra"); location.reload(); }
$("#logout").addEventListener("click", logout);

// ---------- Tabs ----------
document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => { if (b.dataset.view === "aset") ASET_PILIH = null; if (b.dataset.view === "distribusi") DIST_FOKUS = null; show(b.dataset.view); }));
function show(v) {
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.view === v));
  FITUR = null; $(".lampu-panel").classList.remove("hidden");
  document.querySelectorAll(".view").forEach((el) => el.classList.toggle("hidden", el.id !== "view-" + v));
  ({ operator: loadOperator, komandan: loadKomandan, gerbang: loadGate, aset: loadAset, audit: loadAudit, arsip: loadArsip, distribusi: loadDistribusi })[v]();
}

// ---------- Operator ----------
async function loadOperator() {
  const [k, inc, ev] = await Promise.all([getJ("/api/ringkasan"), getJ("/api/insiden"), getJ("/api/event?limit=80")]);
  renderKpi(k);
  renderIncidents($("#incList"), inc, ME.peran === "operator");
  const feed = $("#feed"); feed.replaceChildren(...ev.map((e) => feedRow(e)));
}
function renderKpi(k) {
  const tile = (label, val, cls) => h("div", { class: "card" }, h("span", { class: "muted small" }, label), h("b", { class: cls || "" }, val));
  $("#kpi").replaceChildren(
    tile("Event 24 jam", k.event_24j),
    tile("Insiden terbuka", k.insiden_terbuka, k.insiden_terbuka ? "bad" : "ok"),
    tile("Kritis terbuka", k.kritis_terbuka, k.kritis_terbuka ? "bad" : "ok"),
    tile("Kendaraan 24 jam", k.kendaraan_24j),
    tile("Kendaraan tak terdaftar", k.tak_terdaftar_24j, k.tak_terdaftar_24j ? "bad" : "ok"));
}
function feedRow(e, isNew) {
  return h("div", { class: isNew ? "new" : "" },
    fmt(e.ts).split(" ")[1] || fmt(e.ts), " ", sev(e.severity), " ",
    h("span", { class: "tag" }, e.sumber), " ", e.aset_nama ? "[" + e.aset_nama + "] " : "",
    e.pesan || e.jenis, e.src_ip ? "  src=" + e.src_ip : "");
}
function renderIncidents(box, list, canAct) {
  if (!list.length) { box.replaceChildren(h("p", { class: "muted" }, "Belum ada insiden.")); return; }
  box.replaceChildren(...list.map((i) => incCard(i, canAct)));
}
function incCard(i, canAct) {
  const next = { baru: ["triase"], triase: ["eskalasi", "selesai"], eskalasi: ["selesai"] }[i.status] || [];
  const label = { triase: "Triase", eskalasi: "Eskalasi ke atas", selesai: "Selesai" };
  let cy = null;
  if (i.korelasi) { try { const c = JSON.parse(i.korelasi); cy = h("span", { class: "cyphy" }, "Siber-fisik: plat " + c.plat + ", selisih " + c.selisih_menit + " menit"); } catch (_) {} }
  return h("div", { class: "inc " + i.severity, id: "inc-" + i.id },
    h("div", { class: "t" }, sev(i.severity), " #" + i.id + " " + i.judul),
    h("div", { class: "m" }, (i.satuan_nama || "-") + " · ",
      i.aset_id && i.aset_nama ? h("a", { href: "#aset-" + i.aset_id, class: "aset-link", title: "Lihat aset di peta",
        onclick: (ev) => { ev.preventDefault(); bukaAset(i.aset_id); } }, "📍 " + i.aset_nama) : (i.aset_nama || "jaringan"), " · ",
      h("span", { class: "tag" }, i.mitre || "-"), " · " + i.jumlah_event + " event · status: " + i.status.toUpperCase(), " ", cy),
    i.catatan ? h("div", { class: "note" }, i.catatan) : null,
    distBaris(i),
    h("div", { class: "act" },
      canAct ? next.map((s) => h("button", { class: "sm", onclick: () => act(i.id, s) }, label[s])) : null,
      canAct && i.status !== "selesai" && (!i.distribusi || i.distribusi.jenjang < i.distribusi.maks)
        ? h("button", { class: "sm warnbtn", onclick: () => kirimSitrep(i) }, i.distribusi ? "Teruskan sitrep ke jenjang " + (i.distribusi.jenjang + 1) : "Kirim sitrep ke atas") : null,
      h("button", { class: "sm ghost", onclick: () => sitrep(i.id) }, "Sitrep PDF")));
}
function distBaris(i) {
  const d = i.distribusi; if (!d) return null;
  const ok = d.diakui > 0;
  return h("div", { class: "dist " + (ok ? "ok" : "tunggu") },
    h("span", {}, "Sitrep jenjang " + d.jenjang + "/" + d.maks + " → " + d.satuan + " · "),
    h("b", {}, ok ? d.diakui + "/" + d.n + " penerima mengakui" : "menunggu pengakuan (" + Math.max(0, Math.floor((Date.now() / 1000 - d.ts) / 60)) + " menit)"),
    " ", h("a", { href: "#distribusi", onclick: (ev) => { ev.preventDefault(); DIST_FOKUS = i.id; show("distribusi"); } }, "lihat distribusi"));
}
async function kirimSitrep(i) {
  const ke = i.distribusi ? "jenjang " + (i.distribusi.jenjang + 1) : "satuan induk (jenjang 1)";
  if (!confirm("Kirim sitrep insiden #" + i.id + " ke " + ke + "?")) return;
  try { await api("/api/insiden/" + i.id + "/kirim", { method: "POST" }); } catch (e) { alert(e.message); }
  loadOperator();
}
async function act(id, status) {
  const catatan = prompt("Catatan untuk langkah " + status + " (opsional):") || "";
  try { await api("/api/insiden/" + id + "/status", { method: "POST", body: JSON.stringify({ status, catatan }) }); }
  catch (e) { alert(e.message); }
  loadOperator();
}
async function sitrep(id) {
  const r = await api("/api/insiden/" + id + "/sitrep.pdf");
  const url = URL.createObjectURL(await r.blob());
  const a = h("a", { href: url, download: "sitrep-" + id + ".pdf" }); document.body.append(a); a.click(); a.remove();
}

// ---------- Panel lampu siaga ----------
let LAMPU = null, lampuPilih = null;
async function loadLampu() {
  try { LAMPU = await getJ("/api/lampu"); } catch (_) { return; }
  alarm.update(LAMPU.level);
  $(".lampu-panel").classList.toggle("awas", LAMPU.level === 1);
  $("#resetBtn").classList.toggle("hidden", ME.peran !== "komandan");
  $("#lpReset").textContent = LAMPU.reset ? "Reset terakhir " + fmt(LAMPU.reset.ts) + " oleh " + LAMPU.reset.pengguna : "";
  const t = $("#lpTotal");
  t.className = "lens big l" + LAMPU.level; t.firstChild.textContent = "L" + LAMPU.level;
  $("#lpTotalLabel").textContent = "Level " + LAMPU.level + " · " + LAMPU.label.toUpperCase();
  const lamp = (x, n) => h("button", { type: "button", class: "lamp " + (x.wajib ? "wajib" : "tambahan") + " b" + x.level + (lampuPilih === x.id ? " sel" : ""),
      title: x.level ? "Klik untuk membuka halaman detail" : "Fitur belum dibangun",
      "aria-label": x.nama + ": " + (x.level ? "level " + x.level + " " : "") + x.label + ". " + x.alasan,
      onclick: () => { if (x.level) openFitur(x.id); else { lampuPilih = lampuPilih === x.id ? null : x.id; loadLampuRender(); } } },
    h("span", { class: "lens l" + x.level }, h("span", {}, x.level ? "L" + x.level : "-")),
    h("span", { class: "nm" }, n + ". " + x.nama), h("span", { class: "lv t" + x.level }, x.label));
  const w = LAMPU.lampu.filter((x) => x.wajib), o = LAMPU.lampu.filter((x) => !x.wajib);
  $("#lpWajib").replaceChildren(...w.map((x, i) => lamp(x, i + 1)));
  $("#lpTambahan").replaceChildren(...o.map((x, i) => lamp(x, w.length + i + 1)));
  const aktif = LAMPU.lampu.filter((x) => x.level);
  const d = LAMPU.lampu.find((x) => x.id === lampuPilih) ||
    aktif.reduce((a, b) => (b.level < a.level ? b : a), aktif[0] || LAMPU.lampu[0]);
  $("#lpDetail").replaceChildren(h("span", { class: "lens mini l" + d.level }), h("b", {}, d.nama), " · ",
    h("span", { class: "t" + d.level }, d.label), " · ", d.alasan, h("span", { class: "muted small" }, "  sumber: " + d.sumber));
}
function loadLampuRender() { loadLampu(); }

// Alarm "red alert" dengan Web Audio (tanpa file suara, jalan offline). Browser menahan suara sampai
// pengguna klik/tekan tombol sekali di halaman, jadi konteks audio dibuat pada interaksi pertama.
const alarm = {
  ctx: null, timer: null, level: 4,
  on: (() => { try { return localStorage.getItem("netra-alarm") !== "mati"; } catch (_) { return true; } })(),
  unlock() {
    try {
      if (!this.ctx) this.ctx = new (window.AudioContext || window.webkitAudioContext)();
      if (this.ctx.state === "suspended") this.ctx.resume();
    } catch (_) {}
    this.update(this.level);
  },
  siren() {
    const c = this.ctx; if (!c || c.state !== "running") return;
    const t = c.currentTime, o = c.createOscillator(), g = c.createGain();
    o.type = "sawtooth";
    o.frequency.setValueAtTime(520, t); o.frequency.linearRampToValueAtTime(1100, t + 0.55);
    o.frequency.linearRampToValueAtTime(520, t + 1.1);
    g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(0.18, t + 0.05);
    g.gain.setValueAtTime(0.18, t + 1.0); g.gain.exponentialRampToValueAtTime(0.0001, t + 1.15);
    o.connect(g).connect(c.destination); o.start(t); o.stop(t + 1.2);
  },
  update(level) {
    this.level = level;
    const bunyi = this.on && level === 1;
    if (bunyi && !this.timer) { this.siren(); this.timer = setInterval(() => this.siren(), 1400); }
    if (!bunyi && this.timer) { clearInterval(this.timer); this.timer = null; }
    const b = $("#alarmBtn"); if (!b) return;
    const terkunci = bunyi && (!this.ctx || this.ctx.state !== "running");
    b.textContent = !this.on ? "Alarm: MATI" : terkunci ? "Klik untuk aktifkan suara alarm" : "Alarm: NYALA";
    b.setAttribute("aria-pressed", String(this.on));
    b.classList.toggle("warn", (!this.on || terkunci) && level === 1);
  },
  toggle() {
    this.on = !this.on;
    try { localStorage.setItem("netra-alarm", this.on ? "nyala" : "mati"); } catch (_) {}
    this.unlock();
  },
};
document.addEventListener("pointerdown", () => alarm.unlock(), { once: true });
document.addEventListener("keydown", () => alarm.unlock(), { once: true });
$("#alarmBtn").addEventListener("click", () => alarm.toggle());

$("#resetBtn").addEventListener("click", async () => {
  if (!confirm("Nyatakan SITUASI TERTANGANI?\n\nSemua insiden terbuka akan ditutup dan lampu kembali dihitung dari nol. " +
    "Event, insiden, dan jejak audit TIDAK dihapus. Alert baru sesudah ini tetap menaikkan level.")) return;
  const catatan = prompt("Dasar keputusan (wajib, tercatat di audit):", "");
  if (catatan === null) return;
  try {
    const r = await (await api("/api/situasi/reset", { method: "POST", body: JSON.stringify({ catatan }) })).json();
    alert(r.ditutup + " insiden ditutup. Lampu dihitung ulang.");
  } catch (e) { alert(e.message); }
  loadLampu(); show(document.querySelector("#tabs button.active").dataset.view);
});

// ---------- Halaman detail fitur ----------
let FITUR = null, FMENIT = 60, FBUCKET = null;  // FBUCKET: awal interval yang dipilih (klik batang/puncak)
const LVL = { 1: "#e2504a", 2: "#ef8a3c", 3: "#e0b23a", 4: "#3fb06f", 0: "#5b676b" };
const WARNA_K = { rendah: "#6f8a96", sedang: "#e0b23a", tinggi: "#ef8a3c", kritis: "#e2504a", dibuat: "#ef8a3c",
  selesai: "#3fb06f", "sitrep dibuat": "#5aa9e6", "insiden kritis": "#e2504a", login: "#3fb06f", login_gagal: "#e2504a",
  terdaftar: "#3fb06f", "tak terdaftar": "#e2504a", suricata: "#5aa9e6", wazuh: "#b48ae6", netflow: "#4fb38a",
  netdisc: "#e6c35a", iot: "#e68a5a", anpr: "#d6a35a" };
const PALET = ["#5aa9e6", "#b48ae6", "#4fb38a", "#e6c35a", "#e68a5a", "#7fd1d1", "#e67fb4", "#a3c45a"];
const URUT_SEV = ["rendah", "sedang", "tinggi", "kritis"];
const warnaK = (k, i) => WARNA_K[k] || PALET[i % PALET.length];
const NS = "http://www.w3.org/2000/svg";
function sv(tag, attrs, ...kids) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  for (const c of kids.flat()) if (c != null) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
const jam = (ts, langkah) => new Date(ts * 1000).toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit", hour12: false });

function openFitur(fid) {
  FITUR = fid; FBUCKET = null;
  document.querySelectorAll(".view").forEach((el) => el.classList.toggle("hidden", el.id !== "view-fitur"));
  $(".lampu-panel").classList.add("hidden");
  window.scrollTo(0, 0);
  loadFitur();
}
document.querySelectorAll("#fdRange button").forEach((b) => b.addEventListener("click", () => { FMENIT = +b.dataset.menit; FBUCKET = null; loadFitur(); }));

async function loadFitur() {
  const fid = FITUR; if (!fid) return;
  let d; try { d = await getJ("/api/lampu/" + encodeURIComponent(fid) + "?menit=" + FMENIT); } catch (e) { return; }
  if (FITUR !== fid) return;
  const L = d.lampu, c = LVL[L.level];
  document.querySelectorAll("#fdRange button").forEach((b) => b.classList.toggle("on", +b.dataset.menit === d.menit));
  $("#fdHead").className = "card fd-head l" + L.level;
  $("#fdHead").replaceChildren(
    h("button", { type: "button", class: "sm ghost", onclick: () => show(document.querySelector("#tabs button.active").dataset.view) }, "← Kembali ke panel"),
    h("div", { class: "fd-title" }, h("span", { class: "lens big l" + L.level }, h("span", {}, "L" + L.level)),
      h("div", {}, h("span", { class: "muted small" }, (L.wajib ? "Fungsi inti" : "Modul lanjutan")),
        h("h1", {}, L.nama), h("b", { class: "t" + L.level }, "Level " + L.level + " · " + L.label.toUpperCase()))),
    h("p", { class: "fd-why" }, L.alasan),
    h("p", { class: "muted small" }, "Cara lampu dihitung: " + d.cara));

  // KPI
  const tot = d.seri.map((b) => Object.values(b.n).reduce((a, x) => a + x, 0));
  const puncak = Math.max(0, ...tot), iP = tot.indexOf(puncak);
  const last = d.insiden[0];
  const sevMax = URUT_SEV.slice().reverse().find((k) => d.seri.some((b) => b.n[k]));
  const lvSev = { kritis: 1, tinggi: 2, sedang: 3, rendah: 4 };
  const tile = (label, val, sub, lv) => h("div", { class: "card tile b" + lv }, h("span", { class: "muted small" }, label),
    h("b", { class: "t" + lv }, val), h("span", { class: "muted small" }, sub));
  const rentang = { 60: "60 menit", 360: "6 jam", 1440: "24 jam" }[d.menit];
  const intv = d.langkah >= 3600 ? "1 jam" : d.langkah / 60 + " menit";
  const pilih = (t) => { FBUCKET = FBUCKET === t ? null : t; loadFitur(); };
  const tPuncak = tile("Puncak per interval", puncak, puncak ? "dalam " + intv + ", pukul " + jam(d.seri[iP].t) + "–" +
      jam(d.seri[iP].t + d.langkah) + " · klik untuk rincian" : "tidak ada aktivitas", puncak >= 10 ? 2 : puncak ? 3 : 4);
  if (puncak) { tPuncak.classList.add("klik"); tPuncak.onclick = () => pilih(d.seri[iP].t); }
  const tTotal = tile("Total aktivitas", d.total, d.satuan + " · " + rentang + " terakhir", d.total ? 3 : 4);
  if (d.total) { tTotal.classList.add("klik"); tTotal.onclick = () => { FBUCKET = null; loadFitur(); $("#fdAkt").scrollIntoView({ behavior: "smooth" }); }; }
  $("#fdKpi").replaceChildren(
    tile("Tingkat saat ini", "L" + L.level, L.label, L.level),
    tTotal,
    tPuncak,
    tile("Severity tertinggi", sevMax ? sevMax.toUpperCase() : "-", "dalam rentang ini", sevMax ? lvSev[sevMax] : 4),
    tile("Insiden terkait terbuka", d.insiden_terbuka, last ? "terakhir #" + last.id + " " + fmt(last.ts).split(" ")[1] : "belum ada insiden", d.insiden_terbuka ? Math.min(...d.insiden.filter((i) => i.status !== "selesai").map((i) => lvSev[i.severity] || 4)) : 4));

  // Chart
  if (fid === "iot" && d.telemetri) {
    $("#fdChartTitle").textContent = "Suhu sensor IoT (°C)";
    $("#fdChart").replaceChildren(lineChart(d.telemetri, "suhu", d, [[30, 3], [35, 2], [40, 1]], "°C"));
    $("#fdChart2").replaceChildren(h("h2", { class: "fd-sub" }, "Kelembapan (%)"), lineChart(d.telemetri, "kelembapan", d, [[80, 3], [85, 2], [90, 1]], "%"));
    const nama = [...new Set(d.telemetri.map((t) => t.nama))];
    $("#fdLegend").replaceChildren(...nama.map((n, i) => { const sw = h("i", { class: "sw" }); sw.style.background = PALET[i % PALET.length]; return h("span", {}, sw, n); }),
      h("span", { class: "muted" }, "garis putus = batas Waspada / Siaga / Awas"));
  } else {
    $("#fdChartTitle").textContent = "Deret waktu (" + rentang + ", per " + (d.langkah >= 3600 ? "jam" : d.langkah / 60 + " menit") + ")";
    const keys = [...new Set(d.seri.flatMap((b) => Object.keys(b.n)))].sort((a, b) => (URUT_SEV.indexOf(a) + 1 || 9) - (URUT_SEV.indexOf(b) + 1 || 9));
    $("#fdChart").replaceChildren(barChart(d.seri, keys, d.langkah, c, pilih));
    $("#fdChart2").replaceChildren();
    $("#fdLegend").replaceChildren(...keys.map((k, i) => h("span", {}, h("i", { class: "sw", "data-k": k }), k + " (" +
      d.seri.reduce((a, b) => a + (b.n[k] || 0), 0) + ")")),
      h("span", { class: "muted" }, "garis putus = rata-rata bergerak · klik batang untuk rincian"));
    document.querySelectorAll("#fdLegend i[data-k]").forEach((el, i) => { el.style.background = warnaK(el.dataset.k, i); });
  }

  // Rincian
  const maxR = Math.max(1, ...d.rincian.map((r) => r.n));
  $("#fdRinci").replaceChildren(d.rincian.length ? h("div", { class: "hbars" }, d.rincian.map((r, i) => {
    const bar = h("i", {}); bar.style.width = (r.n / maxR * 100) + "%"; bar.style.background = warnaK(r.label, i);
    return h("div", { class: "hb" }, h("span", { class: "lb" }, r.label), h("span", { class: "tr" }, bar), h("b", {}, r.n));
  })) : h("p", { class: "muted" }, "Tidak ada data dalam rentang ini."));

  // Insiden
  $("#fdLast").replaceChildren(last ? incCard(last, ME.peran === "operator")
    : h("div", { class: "ok-box" }, h("span", { class: "lens mini l4" }), "Tidak ada insiden terkait fitur ini. Kondisi normal."));
  if (d.log) {
    $("#fdListTitle").textContent = "Log akses terakhir";
    $("#fdList").replaceChildren(...d.log.map((a) => h("div", { class: "fd-row" }, fmt(a.ts), " · ", h("b", { class: a.aksi === "login_gagal" ? "t1" : "t4" }, a.aksi), " · ", a.pengguna, " · ", a.detail || "")));
  } else {
    $("#fdListTitle").textContent = "Riwayat insiden terkait";
    $("#fdList").replaceChildren(...(d.insiden.length ? d.insiden.map((i) => h("div", { class: "fd-row" }, sev(i.severity), " #" + i.id + " " + i.judul,
      h("span", { class: "muted small" }, " · " + fmt(i.ts) + " · " + i.status.toUpperCase()))) : [h("p", { class: "muted" }, "Belum ada riwayat insiden.")]));
  }
  renderAktivitas(d, intv);
}

function renderAktivitas(d, intv) {
  const rows = FBUCKET == null ? d.aktivitas : d.aktivitas.filter((r) => r.ts >= FBUCKET && r.ts < FBUCKET + d.langkah);
  const MAX = 60;
  $("#fdAktTitle").textContent = FBUCKET == null ? "Rincian aktivitas (" + d.aktivitas.length + ")" :
    "Rincian aktivitas pukul " + jam(FBUCKET) + "–" + jam(FBUCKET + d.langkah) + " (" + rows.length + ")";
  $("#fdAktKet").textContent = "Yang dihitung sebagai aktivitas di lampu ini: " + d.satuan + ". " +
    (FBUCKET == null ? "Terbaru di atas." : "Interval " + intv + " yang dipilih dari grafik.") +
    (rows.length > MAX ? " Menampilkan " + MAX + " terbaru." : "");
  $("#fdAktCtl").replaceChildren(...(FBUCKET == null ? [] : [h("button", { type: "button", class: "sm ghost", onclick: () => { FBUCKET = null; loadFitur(); } }, "Tampilkan semua")]));
  const tag = (k) => URUT_SEV.includes(k) ? sev(k) : h("span", { class: "tag" }, k || "-");
  $("#fdAkt").replaceChildren(...(rows.length ? rows.slice(0, MAX).map((r) => h("div", { class: "fd-row akt" },
    h("span", { class: "muted" }, fmt(r.ts)), tag(r.k), h("span", { class: "tag" }, r.sumber || "-"),
    h("b", {}, r.obj || "-"), h("span", {}, r.teks || ""))) : [h("p", { class: "muted" }, "Tidak ada aktivitas dalam rentang ini.")]));
}

function barChart(seri, keys, langkah, aksen, onPilih) {
  const W = 720, H = 240, P = { l: 34, r: 10, t: 22, b: 26 }, n = seri.length;
  const tot = seri.map((b) => keys.reduce((a, k) => a + (b.n[k] || 0), 0));
  const maxV = Math.max(4, ...tot), y = (v) => H - P.b - v / maxV * (H - P.t - P.b);
  const bw = (W - P.l - P.r) / n, g = sv("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": "Grafik deret waktu" });
  for (let i = 0; i <= 4; i++) {
    const v = Math.round(maxV * i / 4), yy = y(v);
    g.append(sv("line", { x1: P.l, x2: W - P.r, y1: yy, y2: yy, stroke: "#26333a", "stroke-width": 1 }),
      sv("text", { x: P.l - 6, y: yy + 4, "text-anchor": "end", class: "ax" }, v));
  }
  const tiap = Math.ceil(n / 8);
  seri.forEach((b, i) => {
    const x = P.l + i * bw;
    if (FBUCKET === b.t) g.append(sv("rect", { x, y: P.t - 6, width: bw, height: H - P.t - P.b + 6, fill: "rgba(127,196,214,.14)" }));
    let acc = 0;
    keys.forEach((k, j) => {
      const v = b.n[k] || 0; if (!v) return;
      g.append(sv("rect", { x: x + 1, y: y(acc + v), width: Math.max(1, bw - 2), height: y(acc) - y(acc + v), rx: 2, fill: warnaK(k, j) },
        sv("title", {}, jam(b.t) + " · " + k + ": " + v)));
      acc += v;
    });
    if (tot[i] && (bw >= 16 || tot[i] === Math.max(...tot))) g.append(sv("text", { x: x + bw / 2, y: y(tot[i]) - 5, "text-anchor": "middle", class: "vl" }, tot[i]));
    if (i % tiap === 0) g.append(sv("text", { x: x + bw / 2, y: H - 8, "text-anchor": "middle", class: "ax" }, jam(b.t)));
  });
  if (onPilih) seri.forEach((b, i) => { if (!tot[i]) return;
    const hit = sv("rect", { x: P.l + i * bw, y: P.t, width: bw, height: H - P.t - P.b, fill: "transparent", class: "hit" },
      sv("title", {}, jam(b.t) + "–" + jam(b.t + langkah) + ": " + tot[i] + " aktivitas · klik untuk rincian"));
    hit.addEventListener("click", () => onPilih(b.t)); g.append(hit); });
  const ma = tot.map((_, i) => { const w = tot.slice(Math.max(0, i - 4), i + 1); return w.reduce((a, x) => a + x, 0) / w.length; });
  if (tot.some((v) => v)) g.append(sv("polyline", { points: ma.map((v, i) => `${P.l + i * bw + bw / 2},${y(v)}`).join(" "),
    fill: "none", stroke: aksen, "stroke-width": 2, "stroke-dasharray": "5 4", "stroke-linejoin": "round" }));
  if (!tot.some((v) => v)) g.append(sv("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "vl" }, "Tidak ada aktivitas"));
  return g;
}

function lineChart(rows, f, d, batas, unit) {
  const W = 720, H = 210, P = { l: 38, r: 70, t: 14, b: 24 };
  const t0 = Date.now() / 1000 - d.menit * 60, t1 = Date.now() / 1000;
  const vals = rows.map((r) => r[f]).filter((v) => v != null);
  const lo = Math.min(...vals, ...batas.map((b) => b[0])) - 3, hi = Math.max(...vals, ...batas.map((b) => b[0])) + 3;
  const x = (t) => P.l + (t - t0) / (t1 - t0) * (W - P.l - P.r), y = (v) => H - P.b - (v - lo) / (hi - lo) * (H - P.t - P.b);
  const g = sv("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": "Grafik " + f });
  if (!vals.length) { g.append(sv("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "vl" }, "Belum ada data sensor")); return g; }
  batas.forEach(([v, lv]) => g.append(sv("line", { x1: P.l, x2: W - P.r, y1: y(v), y2: y(v), stroke: LVL[lv], "stroke-dasharray": "4 4", "stroke-width": 1 }),
    sv("text", { x: P.l - 6, y: y(v) + 4, "text-anchor": "end", class: "ax", fill: LVL[lv] }, v)));
  for (let i = 0; i <= 6; i++) { const t = t0 + (t1 - t0) * i / 6; g.append(sv("text", { x: x(t), y: H - 6, "text-anchor": "middle", class: "ax" }, jam(t))); }
  const nama = [...new Set(rows.map((r) => r.nama))];
  const ujung = [];
  nama.forEach((n, i) => {
    const pts = rows.filter((r) => r.nama === n && r[f] != null);
    if (!pts.length) return;
    g.append(sv("polyline", { points: pts.map((r) => `${x(r.ts)},${y(r[f])}`).join(" "), fill: "none", stroke: PALET[i % PALET.length], "stroke-width": 2.2, "stroke-linejoin": "round" }));
    const e = pts[pts.length - 1];
    g.append(sv("circle", { cx: x(e.ts), cy: y(e[f]), r: 4, fill: PALET[i % PALET.length] }));
    ujung.push({ x: x(e.ts) + 7, y: y(e[f]) + 4, t: e[f] + " " + unit, c: PALET[i % PALET.length] });
  });
  ujung.sort((a, b) => a.y - b.y).forEach((u, i, arr) => { if (i && u.y - arr[i - 1].y < 13) u.y = arr[i - 1].y + 13; });
  ujung.forEach((u) => g.append(sv("text", { x: u.x, y: u.y, class: "vl", fill: u.c }, u.t)));
  return g;
}

// ---------- Komandan ----------
async function loadKomandan() {
  const [sat, inc] = await Promise.all([getJ("/api/satuan"), getJ("/api/insiden")]);
  const depth = {}; sat.forEach((s) => (depth[s.id] = s.parent_id ? (depth[s.parent_id] || 0) + 1 : 0));
  $("#tree").replaceChildren(h("div", { class: "tree" }, sat.map((s) =>
    h("div", { class: "node lvl" + depth[s.id] }, h("span", { class: "st " + s.status }), h("b", {}, s.nama),
      h("span", { class: "muted small" }, s.tingkat + (s.insiden_terbuka ? " · " + s.insiden_terbuka + " insiden terbuka" : ""))))));
  const open = inc.filter((i) => i.status !== "selesai" && (i.severity === "kritis" || i.status === "eskalasi"));
  renderIncidents($("#cmdInc"), open, false);
}

// ---------- Gerbang / Aset / Audit ----------
async function loadGate() {
  const rows = await getJ("/api/gerbang?q=" + encodeURIComponent($("#platQ").value));
  $("#gateBody").replaceChildren(...rows.map(gateRow));
}
const gateRow = (g) => h("tr", {}, h("td", {}, fmt(g.ts)), h("td", {}, h("b", {}, g.plat)), h("td", {}, g.arah),
  h("td", { class: g.terdaftar ? "ok" : "bad" }, g.terdaftar ? "Terdaftar" : "TAK TERDAFTAR"), h("td", {}, g.pemilik || "-"),
  h("td", {}, g.kamera), h("td", {}, Math.round(g.confidence * 100) + "%"));
$("#platQ").addEventListener("input", () => loadGate());
// ---------- Aset + peta ----------
let PETA = null, PETA_LAYER = null, PETA_FIT = false, ASET = [], PILIH_PIN = null, ASET_PILIH = null, FOTO_URL = [];
const SUDUT = ["Tampak depan", "Tampak samping", "Tampak belakang", "Lingkungan sekitar"];

// Dipanggil dari tautan aset di kartu insiden: pindah ke tab Aset, zoom ke pin, tampilkan fotonya.
function bukaAset(id) { ASET_PILIH = id; show("aset"); }
const WARNA_LV = { 1: "#e2504a", 2: "#ef8a3c", 3: "#e0b23a", 4: "#3fb06f" };
const gmaps = (a) => "https://www.google.com/maps?q=" + a.lat + "," + a.lon;

async function initPeta() {
  if (PETA || typeof L === "undefined") return;
  const cfg = await getJ("/api/config").catch(() => ({}));
  PETA = L.map("peta", { zoomControl: true }).setView([-6.3, 106.85], 10);
  if (cfg.tile_url) {
    const tl = L.tileLayer(cfg.tile_url, { maxZoom: 19, attribution: cfg.tile_attr || "" }).addTo(PETA);
    let gagal = 0;
    tl.on("tileerror", () => { if (++gagal === 3) $("#petaKet").textContent =
      "Peta dasar tidak bisa dimuat (offline?). Pin aset tetap tampil; atur NETRA_TILE_URL ke server tile lokal untuk markas tanpa internet."; });
  }
  PETA_LAYER = L.layerGroup().addTo(PETA);
  PETA.on("click", (e) => {
    if ($("#asetForm").classList.contains("hidden")) return;
    const f = $("#asetForm");
    f.lat.value = e.latlng.lat.toFixed(6); f.lon.value = e.latlng.lng.toFixed(6);
    tandaPilih(e.latlng);
  });
}
function tandaPilih(ll) {
  if (PILIH_PIN) PILIH_PIN.remove();
  PILIH_PIN = L.marker(ll, { icon: L.divIcon({ className: "pin-baru", iconSize: [18, 18] }) }).addTo(PETA);
}

async function loadAset() {
  const rows = ASET = await getJ("/api/aset");
  const ops = ME.peran === "operator";
  $("#asetBaru").classList.toggle("hidden", !ops);
  $("#asetBody").replaceChildren(...rows.map((a) => h("tr", { "data-id": a.id, class: a.id === ASET_PILIH ? "sel" : "" }, h("td", {}, a.satuan_nama),
    h("td", {}, h("a", { href: "#aset-" + a.id, onclick: (ev) => { ev.preventDefault(); pilihAset(a, true); } }, h("b", {}, a.nama))),
    h("td", {}, a.jenis), h("td", {}, a.kategori), h("td", {}, a.ip), h("td", {}, "●".repeat(a.kritis)), h("td", {}, a.event_24j),
    h("td", {}, a.lat != null ? [h("button", { type: "button", class: "sm ghost", onclick: () => pilihAset(a, true) }, a.lat.toFixed(5) + ", " + a.lon.toFixed(5)),
      " ", h("a", { href: gmaps(a), target: "_blank", rel: "noopener" }, "Google Maps ↗")] : h("span", { class: "muted" }, "belum ada")),
    h("td", {}, ops ? h("button", { type: "button", class: "sm ghost", onclick: () => bukaForm(a) }, "Edit") : ""))));
  await initPeta();
  if (!PETA) { $("#petaKet").textContent = "Pustaka peta tidak termuat."; return; }
  setTimeout(() => PETA.invalidateSize(), 50);
  PETA_LAYER.clearLayers();
  // Pin terburuk digambar paling akhir agar tidak tertutup pin hijau di sekitarnya.
  const ada = rows.filter((a) => a.lat != null && a.lon != null).sort((x, y) => (y.level || 4) - (x.level || 4));
  ada.forEach((a) => {
    const lv = a.level || 4;
    const m = L.circleMarker([a.lat, a.lon], { radius: 6 + a.kritis * 2, color: "#0b1113", weight: 2, fillColor: WARNA_LV[lv], fillOpacity: .95 });
    const pop = h("div", { class: "pop" }, h("b", {}, a.nama), h("div", {}, a.satuan_nama + " · " + a.jenis + " · " + a.kategori),
      h("div", {}, "IP " + a.ip + " · event 24 jam: " + a.event_24j),
      h("div", { class: "t" + lv }, lv < 4 ? "Ada insiden terbuka (level " + lv + ")" : "Normal"),
      h("div", {}, a.lat.toFixed(6) + ", " + a.lon.toFixed(6)),
      h("a", { href: gmaps(a), target: "_blank", rel: "noopener" }, "Buka di Google Maps ↗"));
    m.bindPopup(pop).bindTooltip(a.nama); m.asetId = a.id; m.addTo(PETA_LAYER);
    m.on("click", () => pilihAset(a, false));
  });
  if (!PETA_FIT && ada.length) { PETA.fitBounds(L.latLngBounds(ada.map((a) => [a.lat, a.lon])).pad(0.15)); PETA_FIT = true; }
  const target = ASET_PILIH && rows.find((a) => a.id === ASET_PILIH);
  if (target) pilihAset(target, true); else if (!ASET_PILIH) renderGaleri(null);
  const tanpa = rows.length - ada.length;
  if (!$("#petaKet").textContent.startsWith("Peta dasar")) $("#petaKet").textContent = ada.length + " aset di peta" +
    (tanpa ? ", " + tanpa + " belum punya koordinat" : "") + ". Warna pin = status insiden aset, ukuran = kekritisan. Data aset tersimpan di data/aset.json (bisa diedit langsung).";
}
function pilihAset(a, zoom) {
  const ganti = ASET_PILIH !== a.id || !$("#galeriIsi").children.length;
  ASET_PILIH = a.id;
  document.querySelectorAll("#asetBody tr").forEach((tr) => tr.classList.toggle("sel", +tr.dataset.id === a.id));
  if (zoom) { if (a.lat != null) fokusAset(a); else $("#galeri").scrollIntoView({ behavior: "smooth", block: "center" }); }
  if (ganti) renderGaleri(a);
}
async function renderGaleri(a) {
  FOTO_URL.forEach((u) => URL.revokeObjectURL(u)); FOTO_URL = [];
  if (!a) {
    $("#galeriJudul").textContent = "Foto aset";
    $("#galeriKet").textContent = "Klik pin di peta, koordinat di tabel, atau nama aset di kartu insiden untuk melihat 4 foto aset.";
    $("#galeriIsi").replaceChildren(...SUDUT.map((s) => h("figure", { class: "foto kosong" }, h("img", { src: "/static/foto-kosong.svg", alt: "" }), h("figcaption", {}, s))));
    return;
  }
  $("#galeriJudul").textContent = "Foto aset: " + a.nama;
  $("#galeriKet").textContent = a.satuan_nama + " · " + a.kategori + " · IP " + a.ip;
  let fs; try { fs = await getJ("/api/aset/" + a.id + "/foto"); } catch (_) { return; }
  if (ASET_PILIH !== a.id) return;
  const ops = ME.peran === "operator";
  const kartu = await Promise.all(fs.map(async (f) => {
    let src = "/static/foto-kosong.svg";
    if (f.nama) { try { const r = await api("/api/foto/" + f.nama.split("/").map(encodeURIComponent).join("/")); src = URL.createObjectURL(await r.blob()); FOTO_URL.push(src); } catch (_) {} }
    const label = { asli: "Foto asli", contoh: "Ilustrasi", kosong: "Belum ada foto" }[f.sumber];
    const input = h("input", { type: "file", accept: "image/jpeg,image/png,image/webp", class: "hidden" });
    input.addEventListener("change", async () => {
      const file = input.files[0]; if (!file) return;
      try { await api("/api/aset/" + a.id + "/foto/" + f.slot, { method: "PUT", body: file, headers: { "Content-Type": file.type } }); renderGaleri(a); }
      catch (err) { alert("Gagal mengunggah: " + err.message); }
    });
    return h("figure", { class: "foto " + f.sumber },
      h("img", { src, alt: SUDUT[f.slot - 1] + " " + a.nama, loading: "lazy" }),
      h("figcaption", {}, h("b", {}, SUDUT[f.slot - 1]), h("span", { class: "badge-" + f.sumber }, label),
        f.kredit ? h("a", { href: f.kredit.link, target: "_blank", rel: "noopener", class: "kredit" }, f.kredit.teks) : null,
        ops ? h("span", { class: "foto-act" }, input,
          h("button", { type: "button", class: "sm ghost", onclick: () => input.click() }, f.sumber === "asli" ? "Ganti" : "Unggah foto asli"),
          f.sumber === "asli" ? h("button", { type: "button", class: "sm ghost", onclick: async () => {
            if (!confirm("Kosongkan foto ini? Slot kembali ke foto ilustrasi; file lama tetap tersimpan di data/foto.")) return;
            await api("/api/aset/" + a.id + "/foto/" + f.slot, { method: "DELETE" }); renderGaleri(a); } }, "Kosongkan") : null) : null));
  }));
  if (ASET_PILIH === a.id) $("#galeriIsi").replaceChildren(...kartu);
}
function fokusAset(a) {
  PETA.setView([a.lat, a.lon], 18);
  PETA_LAYER.eachLayer((m) => { if (m.asetId === a.id) m.openPopup(); });
  $("#peta").scrollIntoView({ behavior: "smooth", block: "center" });
}
async function bukaForm(a) {
  const f = $("#asetForm");
  const sat = await getJ("/api/satuan-daftar");
  f.satuan_id.replaceChildren(...sat.map((s) => h("option", { value: s.id }, s.nama)));
  f.reset();
  $("#asetErr").textContent = "";
  $("#asetFormJudul").textContent = a ? "Edit aset: " + a.nama : "Tambah aset (klik peta untuk koordinat)";
  for (const k of ["id", "nama", "satuan_id", "jenis", "kategori", "ip", "mac", "kritis", "lat", "lon"]) if (a && a[k] != null) f[k].value = a[k];
  if (!a) f.id.value = "";
  f.classList.remove("hidden");
  if (a && a.lat != null) { tandaPilih([a.lat, a.lon]); PETA.setView([a.lat, a.lon], 17); }
  f.nama.focus();
}
function tutupForm() { $("#asetForm").classList.add("hidden"); if (PILIH_PIN) { PILIH_PIN.remove(); PILIH_PIN = null; } }
$("#asetBaru").addEventListener("click", () => bukaForm(null));
$("#asetBatal").addEventListener("click", tutupForm);
$("#asetForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target, num = (v) => (v === "" ? null : +v);
  const body = { nama: f.nama.value, satuan_id: +f.satuan_id.value, jenis: f.jenis.value, kategori: f.kategori.value, ip: f.ip.value,
    mac: f.mac.value || null, kritis: +f.kritis.value, lat: num(f.lat.value), lon: num(f.lon.value) };
  try {
    await api(f.id.value ? "/api/aset/" + f.id.value : "/api/aset", { method: f.id.value ? "PUT" : "POST", body: JSON.stringify(body) });
    tutupForm(); loadAset();
  } catch (err) { $("#asetErr").textContent = err.message; }
});

// ---------- Distribusi sitrep ----------
let DIST_FOKUS = null;
async function loadDistribusi() {
  const d = await getJ("/api/distribusi");
  const b = d.batas_menit || {};
  $("#distKet").textContent = "Eskalasi otomatis ke jenjang berikutnya bila belum ada penerima yang mengakui dalam: kritis " +
    (b.kritis ?? "-") + " menit, tinggi " + (b.tinggi ?? "-") + " menit. Penerima dan batas waktu diatur di " + d.file + ".";
  const kom = ME.peran === "komandan";
  const rows = DIST_FOKUS ? d.daftar.filter((r) => r.insiden_id === DIST_FOKUS) : d.daftar;
  $("#distCtl").replaceChildren(...(DIST_FOKUS ? [h("span", { class: "muted small" }, "Hanya insiden #" + DIST_FOKUS + " "),
    h("button", { type: "button", class: "sm ghost", onclick: () => { DIST_FOKUS = null; loadDistribusi(); } }, "Tampilkan semua")] : []));
  const menunggu = d.daftar.filter((r) => !r.diakui_ts && r.insiden_status !== "selesai").length;
  $("#distJudul").textContent = "Distribusi sitrep (" + d.daftar.length + " kiriman, " + menunggu + " menunggu pengakuan)";
  $("#distBody").replaceChildren(...(rows.length ? rows.map((r) => h("tr", { class: r.diakui_ts ? "" : "tunggu" },
    h("td", {}, fmt(r.ts)),
    h("td", {}, sev(r.severity), " #" + r.insiden_id + " " + r.judul),
    h("td", {}, "J" + r.jenjang + " · " + r.satuan_nama),
    h("td", {}, h("b", {}, r.penerima)),
    h("td", {}, r.cara === "otomatis" ? h("span", { class: "tag" }, "otomatis") : r.pengirim),
    h("td", {}, h("a", { href: "#", onclick: (ev) => { ev.preventDefault(); unduhArsip("sitrep", r.sitrep); } }, "PDF")),
    h("td", {}, r.diakui_ts ? h("span", { class: "t4" }, "Diakui " + fmt(r.diakui_ts).split(" ")[1] + " oleh " + r.diakui_oleh + (r.catatan ? " · " + r.catatan : ""))
      : h("span", { class: "t2" }, "Menunggu " + Math.floor((Date.now() / 1000 - r.ts) / 60) + " menit")),
    h("td", {}, kom && !r.diakui_ts ? h("button", { type: "button", class: "sm", onclick: async () => {
      const c = prompt("Catatan pengakuan (opsional), mis. 'diterima, tindak lanjut regu jaga':", "") ?? null;
      if (c === null) return;
      try { await api("/api/distribusi/" + r.id + "/akui", { method: "POST", body: JSON.stringify({ catatan: c }) }); } catch (e) { alert(e.message); }
      loadDistribusi(); } }, "Akui") : ""))) : [h("tr", {}, h("td", { colspan: 8, class: "muted" }, "Belum ada sitrep yang didistribusikan."))]));
}

// ---------- Arsip ----------
async function unduhArsip(jenis, nama) {
  const r = await api("/api/arsip/" + jenis + "/" + encodeURIComponent(nama));
  const url = URL.createObjectURL(await r.blob());
  const a = h("a", { href: url, download: nama }); document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
const kb = (n) => (n < 1024 ? n + " B" : (n / 1024).toFixed(1) + " KB");
async function loadArsip() {
  const d = await getJ("/api/arsip");
  $("#arsipFolder").textContent = "Folder: " + d.folder + "  ·  Data aset: " + d.aset_file;
  const dl = (j, n) => h("button", { type: "button", class: "sm ghost", onclick: () => unduhArsip(j, n) }, "Unduh");
  $("#arsipInsTitle").textContent = "Insiden (" + d.insiden.length + " file)";
  $("#arsipIns").replaceChildren(...(d.insiden.length ? d.insiden.map((i) => h("tr", {}, h("td", {}, h("code", {}, i.nama)),
    h("td", {}, "#" + i.id + " " + (i.judul || "")), h("td", {}, i.severity ? sev(i.severity) : "-"), h("td", {}, (i.status || "-").toUpperCase()),
    h("td", {}, i.satuan_nama || "-"), h("td", {}, i.ts ? fmt(i.ts) : "-"), h("td", {}, dl("insiden", i.nama))))
    : [h("tr", {}, h("td", { colspan: 7, class: "muted" }, "Belum ada insiden diarsipkan."))]));
  const daftar = (el, j, items, ket) => $(el).replaceChildren(...(items.length ? items.map((x) => h("div", { class: "fd-row arsip-row" },
    h("code", {}, x.nama), h("span", { class: "muted small" }, ket(x)), dl(j, x.nama))) : [h("p", { class: "muted" }, "Belum ada file.")]));
  $("#arsipAuditTitle").textContent = "Jejak audit harian (" + d.audit.length + " file)";
  daftar("#arsipAudit", "audit", d.audit, (x) => x.baris + " aksi · " + kb(x.ukuran));
  $("#arsipSitrepTitle").textContent = "Sitrep PDF (" + d.sitrep.length + " file)";
  daftar("#arsipSitrep", "sitrep", d.sitrep, (x) => fmt(x.diubah) + " · " + kb(x.ukuran));
}
async function loadAudit() {
  const rows = await getJ("/api/audit");
  $("#auditBody").replaceChildren(...rows.map((a) => h("tr", {}, h("td", {}, fmt(a.ts)), h("td", {}, a.pengguna), h("td", {}, a.aksi), h("td", {}, a.detail))));
}

// ---------- Live ----------
let refreshT = null;
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(proto + "://" + location.host + "/ws?token=" + encodeURIComponent(TOKEN));
  ws.onopen = () => $("#live").className = "dot on";
  ws.onclose = () => { $("#live").className = "dot off"; setTimeout(connectWs, 2000); };
  ws.onmessage = (m) => {
    const { kind, data } = JSON.parse(m.data);
    if (kind === "event") { const f = $("#feed"); f.prepend(feedRow(data, true)); while (f.children.length > 200) f.lastChild.remove(); }
    if (kind === "gerbang" && !$("#view-gerbang").classList.contains("hidden")) $("#gateBody").prepend(gateRow(data));
    clearTimeout(refreshT);
    refreshT = setTimeout(() => {
      const v = document.querySelector("#tabs button.active").dataset.view;
      if (v === "operator") { getJ("/api/ringkasan").then(renderKpi); if (kind !== "event") getJ("/api/insiden").then((l) => renderIncidents($("#incList"), l, ME.peran === "operator")); }
      if (v === "komandan" && kind !== "event") loadKomandan();
      if (v === "distribusi" && kind !== "event") loadDistribusi();
      if (v === "aset" && (kind === "insiden" || kind === "status") && $("#asetForm").classList.contains("hidden")) loadAset();
      if (FITUR) loadFitur();
      loadLampu();
    }, 400);
  };
}

function start() {
  $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
  $("#who").textContent = ME.username + " (" + ME.peran + ")";
  show(ME.peran === "komandan" ? "komandan" : "operator");
  loadLampu(); setInterval(() => { loadLampu(); if (FITUR) loadFitur(); }, 15000);  // level berbasis waktu (SLA, sensor senyap) berubah tanpa event
  connectWs();
}
try { const s = JSON.parse(sessionStorage.getItem("netra")); if (s) { TOKEN = s.token; ME = s; start(); } } catch (_) {}
