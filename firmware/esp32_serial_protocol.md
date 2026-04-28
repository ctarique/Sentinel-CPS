# ESP32 Serial Control Protocol

The Raspberry Pi gateway communicates with the ESP32 microcontroller using a serial connection.

Communication occurs over USB using a simple text-based protocol.

Commands

ON
Turns the LED on.

OFF
Turns the LED off.

Example Transmission

Gateway sends:

ON\n

ESP32 receives command and sets GPIO output HIGH.

Note
When communicating with ESP32 over serial from Linux, the baud rate must be explicitly set using stty before sending data. Otherwise, the ESP32 will not correctly interpret incoming messages.

Future extensions

MOVE_FORWARD
TURN_LEFT
TURN_RIGHT
STOP