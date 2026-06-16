#include <Arduino.h>
#include <esp_now.h>
#include <WiFi.h>
#include "../telemetry_schema.h" // Import the strict data contract

// ==========================================
// THESIS CONSTRAINT: APPROVED PEER RESTRICTION
// ==========================================
// Replace this with the actual physical MAC address of your ESP32 Vehicle.
// Any packet originating from a MAC not on this list is dropped at the hardware layer.
uint8_t vehicle_mac[] = {0x24, 0x6F, 0x28, 0xAB, 0xCD, 0xEF}; 

esp_now_peer_info_t peerInfo;
struct_telemetry incoming_telemetry;
struct_command outgoing_command;

// ==========================================
// UPSTREAM: EDGE -> HUB -> GATEWAY
// ==========================================
// Callback when telemetry is received from the vehicle over the air
void OnDataRecv(const uint8_t * mac, const uint8_t *incomingData, int len) {
    // 1. Copy the encrypted bytes into our schema
    memcpy(&incoming_telemetry, incomingData, sizeof(incoming_telemetry));
    
    // 2. Translate to flat ASCII for the Pi's Python serial listener
    // Format: TELEMETRY,ID,ADC_L,ADC_R,PID_ERR,STATUS
    Serial.print("TELEMETRY,");
    Serial.print(incoming_telemetry.vehicle_id); Serial.print(",");
    Serial.print(incoming_telemetry.adc_left); Serial.print(",");
    Serial.print(incoming_telemetry.adc_right); Serial.print(",");
    Serial.print(incoming_telemetry.pid_error, 4); Serial.print(",");
    Serial.println(incoming_telemetry.status_flag);
}

void setup() {
    // Initialize the Serial Chokepoint to the Pi
    Serial.begin(115200);
    
    // Set device as a Wi-Fi Station
    WiFi.mode(WIFI_STA);
    
    // Initialize ESP-NOW
    if (esp_now_init() != ESP_OK) {
        Serial.println("ERROR: ESP-NOW Initialization Failed.");
        return;
    }
    
    // Register the receive callback
    esp_now_register_recv_cb(OnDataRecv);
    
    // ==========================================
    // THESIS CONSTRAINT: ESP-NOW CRYPTOGRAPHY
    // ==========================================
    // Register the authorized edge vehicle as a peer
    memcpy(peerInfo.peer_addr, vehicle_mac, 6);
    peerInfo.channel = 0;  
    peerInfo.encrypt = true; // ENFORCE CCMP ENCRYPTION
    memcpy(peerInfo.lmk, LMK, 16); // Apply the 16-byte Local Master Key
    
    if (esp_now_add_peer(&peerInfo) != ESP_OK){
        Serial.println("ERROR: Failed to add authorized peer.");
        return;
    }
    
    Serial.println("HUB_READY");
}

// ==========================================
// DOWNSTREAM: GATEWAY -> HUB -> EDGE
// ==========================================
void loop() {
    // Check if the Raspberry Pi is sending a command down the serial line
    if (Serial.available() > 0) {
        String gateway_instruction = Serial.readStringUntil('\n');
        gateway_instruction.trim();
        
        if (gateway_instruction == "EMERGENCY_STOP") {
            outgoing_command.command_code = 0xFF;
            outgoing_command.parameter = 0.0;
            
            // Broadcast the encrypted STOP command to the vehicle
            esp_err_t result = esp_now_send(vehicle_mac, (uint8_t *) &outgoing_command, sizeof(outgoing_command));
            
            if (result == ESP_OK) {
                Serial.println("ACTION_LOG: STOP Command dispatched securely.");
            } else {
                Serial.println("ERROR: Failed to dispatch STOP Command.");
            }
        }
    }
}
