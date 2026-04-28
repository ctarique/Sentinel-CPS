#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_bt.h"

#define LED_PIN 4   // ESP32-CAM flash LED (often GPIO4)

void disableWireless() {
  WiFi.mode(WIFI_OFF);
  esp_wifi_stop();

  esp_bt_controller_disable();
  esp_bt_controller_deinit();
}

void setup() {
  Serial.begin(115200);
  delay(500);

  disableWireless();

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  Serial.println("READY");
}

void loop() {
  if (!Serial.available()) return;

  String cmd = Serial.readStringUntil('\n');
  cmd.trim();
  cmd.toUpperCase();

  if (cmd == "ON") {
    digitalWrite(LED_PIN, HIGH);
    Serial.println("LED_ON_OK");
  } else if (cmd == "OFF") {
    digitalWrite(LED_PIN, LOW);
    Serial.println("LED_OFF_OK");
  } else {
    Serial.println("UNKNOWN_COMMAND");
  }
}