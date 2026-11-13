/*
  NetraGatra - sensor suhu & kelembapan ESP32 + DHT22

  Kabel DHT22 (modul 3 pin):  VCC -> 3V3,  GND -> GND,  DATA -> GPIO 4
  (DHT22 4 pin tanpa modul: tambahkan resistor 10k antara DATA dan VCC)

  Library (Arduino IDE > Library Manager): "DHT sensor library" (Adafruit) + "Adafruit Unified Sensor"
  Board: ESP32 Dev Module (paket "esp32" oleh Espressif)

  Mode 1 (disarankan untuk demo): USB SERIAL
    ESP32 mencetak satu baris JSON setiap 5 detik ke USB serial 115200.
    Di laptop jalankan:  python tools\jembatan_serial.py --aset-ip 10.10.3.51
  Mode 2 (opsional): WI-FI
    Isi WIFI_SSID, WIFI_PASS, NETRA_URL, NETRA_KEY di bawah. ESP32 POST langsung ke NetraGatra.
    Server harus dijalankan dengan:  jalankan-demo.ps1 -Lan   (dan izinkan port 8000 di Windows Firewall)

  Data tidak dikirim ke cloud mana pun.
*/
#include <DHT.h>
#include <WiFi.h>
#include <HTTPClient.h>

#define DHT_PIN 4
#define DHT_TYPE DHT22
#define INTERVAL_MS 5000

// ---- Mode Wi-Fi (kosongkan WIFI_SSID untuk mode USB serial saja) ----
const char* WIFI_SSID = "";
const char* WIFI_PASS = "";
const char* NETRA_URL = "http://192.168.43.100:8000/api/ingest/telemetri";  // IP laptop server
const char* NETRA_KEY = "ISI_DARI_data_ingest.key";                      // isi data\ingest.key (NETRA_INGEST_KEY di .env)
const char* ASET_IP   = "10.10.3.51";  // aset di NetraGatra yang diwakili sensor ini (lihat tab Aset / aset.json)

DHT dht(DHT_PIN, DHT_TYPE);
unsigned long terakhir = 0;

void setup() {
  Serial.begin(115200);
  dht.begin();
  if (strlen(WIFI_SSID)) {
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
  }
  Serial.println("{\"info\":\"NetraGatra DHT22 siap\"}");
}

void kirimWifi(float t, float h) {
  if (!strlen(WIFI_SSID) || WiFi.status() != WL_CONNECTED) return;
  HTTPClient http;
  http.begin(NETRA_URL);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Netra-Key", NETRA_KEY);
  String body = String("{\"ip\":\"") + ASET_IP + "\",\"suhu\":" + String(t, 1) + ",\"kelembapan\":" + String(h, 1) + "}";
  int kode = http.POST(body);
  if (kode != 200) Serial.printf("{\"info\":\"POST gagal %d\"}\n", kode);
  http.end();
}

void loop() {
  if (millis() - terakhir < INTERVAL_MS) return;
  terakhir = millis();
  float h = dht.readHumidity();
  float t = dht.readTemperature();
  if (isnan(h) || isnan(t)) {
    Serial.println("{\"info\":\"gagal baca DHT22, cek kabel\"}");
    return;
  }
  // Satu baris JSON per bacaan: dibaca tools/jembatan_serial.py
  Serial.printf("{\"suhu\":%.1f,\"kelembapan\":%.1f}\n", t, h);
  kirimWifi(t, h);
}
