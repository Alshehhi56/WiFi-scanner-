
#include <Arduino.h>
#include <WiFi.h>

void setup() {
  Serial.begin(115200);
  delay(2000);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  Serial.println("ESP32-S3 WiFi Scanner Ready");
}

void loop() {
  Serial.println("\nScanning WiFi networks...");

  int n = WiFi.scanNetworks();

  if (n < 0) {
    Serial.println("Scan failed");
  } else {
    Serial.printf("Found %d networks\n", n);

    for (int i = 0; i < n; i++) {
      Serial.printf(
        "%d | SSID: %s | RSSI: %d dBm | CH: %d | Security: %s\n",
        i + 1,
        WiFi.SSID(i).c_str(),
        WiFi.RSSI(i),
        WiFi.channel(i),
        WiFi.encryptionType(i) == WIFI_AUTH_OPEN
          ? "Open" : "Protected"
      );
    }
  }

  WiFi.scanDelete();
  delay(5000);
}
