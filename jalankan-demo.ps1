# Menjalankan NetraGatra di Windows tanpa Docker, dengan kredensial dan kunci ingest TETAP
# (tidak berubah tiap restart, jadi ANPR/simulator tidak perlu dijalankan ulang kalau server restart).
#
# Pakai (dari folder proyek, venv sudah aktif):
#   powershell -ExecutionPolicy Bypass -File .\jalankan-demo.ps1
#   powershell -ExecutionPolicy Bypass -File .\jalankan-demo.ps1 -Reset    # mulai dari database kosong
#   powershell -ExecutionPolicy Bypass -File .\jalankan-demo.ps1 -Lan      # bisa diakses ESP32/HP lewat Wi-Fi
param([switch]$Reset, [switch]$Lan)

$root = $PSScriptRoot
# Kredensial dan kunci ingest dibaca dari file .env (tidak ikut ke git, lihat .env.example).
# Bila .env belum ada, dibuat sekali dengan nilai acak lalu dipakai terus.
$envFile = Join-Path $root ".env"
if (-not (Test-Path $envFile)) {
    function Acak([int]$n) { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count $n | ForEach-Object { [char]$_ }) }
    @(
        "NETRA_USERS=operator:$(Acak 14):operator,komandan:$(Acak 14):komandan",
        "NETRA_INGEST_KEY=$(Acak 32)"
    ) | Set-Content -Encoding ASCII $envFile
    Write-Host "File .env dibuat dengan password acak. Lihat isinya: Get-Content .env"
}
Get-Content $envFile | Where-Object { $_ -match '^\s*[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {
    $k, $v = $_ -split '=', 2
    Set-Item -Path ("Env:" + $k.Trim()) -Value $v.Trim()
}
$env:NETRA_DB           = Join-Path $root "data\netragatra.db"
$env:NETRA_WAZUH_ALERTS = Join-Path $root "sensor-logs\wazuh\alerts.json"
$env:NETRA_SURICATA_EVE = Join-Path $root "sensor-logs\suricata\eve.json"

if ($Reset) {
    Remove-Item -ErrorAction SilentlyContinue $env:NETRA_DB, $env:NETRA_WAZUH_ALERTS
    # Arsip insiden/audit/sitrep tidak dihapus, dipindah ke data\arsip-lama\<waktu>. data\aset.json tetap dipakai.
    $arsip = Join-Path $root "data\arsip"
    if (Test-Path $arsip) {
        $lama = Join-Path $root ("data\arsip-lama\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
        New-Item -ItemType Directory -Force -Path (Split-Path $lama) | Out-Null
        Move-Item $arsip $lama
        Write-Host "Arsip lama dipindah ke $lama"
    }
    Write-Host "Database dan alerts.json dihapus, mulai bersih (aset.json tetap)."
}
Set-Location (Join-Path $root "backend")
Write-Host "NetraGatra: http://localhost:8000  (Ctrl+C untuk berhenti)"
# -Lan: buka server ke jaringan (ESP32 mode Wi-Fi / HP). Izinkan port 8000 di Windows Firewall bila diminta.
$hostIp = if ($Lan) { "0.0.0.0" } else { "127.0.0.1" }
if ($Lan) { Write-Host "Mode LAN: perangkat lain bisa mengakses http://<IP-laptop>:8000" }
python -m uvicorn app.main:app --host $hostIp --port 8000
