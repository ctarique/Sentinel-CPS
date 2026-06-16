#ifndef TELEMETRY_SCHEMA_H
#define TELEMETRY_SCHEMA_H

#include <stdint.h>

// ==========================================
// THESIS CONSTRAINT: WIRELESS CRYPTOGRAPHY
// ==========================================
// ESP-NOW traffic must use CCMP encryption with a hardcoded 
// 16-byte Local Master Key (LMK). This prevents spoofing 
// and injection from untrusted physical MAC addresses.
const uint8_t LMK[16] = {0x53, 0x65, 0x6E, 0x74, 0x69, 0x6E, 0x65, 0x6C, 
                         0x43, 0x50, 0x53, 0x5F, 0x4B, 0x65, 0x79, 0x31}; // "SentinelCPS_Key1" in hex

// ==========================================
// TELEMETRY PAYLOAD (Edge Vehicle -> Hub)
// ==========================================
typedef struct struct_telemetry {
    uint8_t vehicle_id;     // Explicit identity tracking for the Digital Twin
    uint16_t adc_left;      // 12-bit downward analog sensor (left phototransistor)
    uint16_t adc_right;     // 12-bit downward analog sensor (right phototransistor)
    float pid_error;        // Local closed-loop steering error for baseline modeling
    uint8_t status_flag;    // 0 = NEUTRAL/STOP, 1 = ACTIVE, 2 = COMMS_LOSS
} struct_telemetry;

// ==========================================
// COMMAND PAYLOAD (Hub -> Edge Vehicle)
// ==========================================
typedef struct struct_command {
    uint8_t command_code;   // 0x01 = GO, 0xFF = EMERGENCY_STOP
    float parameter;        // Optional tuning parameter (e.g., speed limits)
} struct_command;

#endif
