#pragma once

#include <stdint.h>

// Copy this file to sentinel_radio_config.h, then replace every placeholder
// locally. The local filename is ignored by Git. Keeping configured=false or
// any all-zero placeholder makes ESP-NOW unavailable by design.
static const bool SENTINEL_RADIO_CONFIGURED = false;

// Hub Wi-Fi station MAC address (placeholder only).
static const uint8_t SENTINEL_RADIO_PEER_MAC[6] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// ESP-NOW primary master key: exactly 16 bytes (placeholder only).
static const uint8_t SENTINEL_RADIO_PMK[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Shared peer local master key: exactly 16 bytes (placeholder only).
static const uint8_t SENTINEL_RADIO_LMK[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Both devices must use the same locally selected channel from 1 through 11.
static const uint8_t SENTINEL_RADIO_WIFI_CHANNEL = 0;
