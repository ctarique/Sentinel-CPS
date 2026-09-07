Browser (via SEMO VPN & Bastion Host)
   |
   | HTTP / Web Interface
   |
Bare-Metal Flask Gateway (Raspberry Pi)
   |                                  |
   | Serial (USB /dev/ttyUSB0)        | Private Wi-Fi AP (<PRIVATE_DISPLAY_AP_SSID>)
   |                                  |
ESP32 Hub Bridge                      | HTTP Video Stream
   |                                  |
   +-------- (Encrypted ESP-NOW) -----+
                      |
          Autonomous ESP32 Vehicles
                      |
               Sensors + Camera
