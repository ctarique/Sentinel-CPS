/*
  Sentinel-CPS Vehicle Firmware Phase 3B
  Target: ESP32 development board
  Purpose: Authoritative transaction state machine shared by direct USB and
           encrypted, authorized-peer ESP-NOW command transport.

  MOTORS_ENABLED remains false. Radio callbacks only validate/copy bounded
  data and set flags; parsing, motor safety, and response routing run in loop().
*/

#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>

#define BAUD_RATE 115200

// Physical motor actuation remains compile-time disabled in Phase 3B.
static const bool MOTORS_ENABLED = false;
static const bool COMMAND_TIMEOUT_ENABLED = true;

static const size_t MAX_LINE_LENGTH = 128;
static const size_t MAX_TXID_LENGTH = 64;
static const size_t MAX_VERB_LENGTH = 16;
static const size_t RADIO_QUEUE_CAPACITY = 4;
static const size_t RADIO_TRANSMIT_QUEUE_CAPACITY = 8;

#if __has_include("sentinel_radio_config.h")
#include "sentinel_radio_config.h"
#define SENTINEL_HAS_LOCAL_RADIO_CONFIG 1
#else
#define SENTINEL_HAS_LOCAL_RADIO_CONFIG 0
static const bool SENTINEL_RADIO_CONFIGURED = false;
static const uint8_t SENTINEL_RADIO_PEER_MAC[ESP_NOW_ETH_ALEN] = {0};
static const uint8_t SENTINEL_RADIO_PMK[ESP_NOW_KEY_LEN] = {0};
static const uint8_t SENTINEL_RADIO_LMK[ESP_NOW_KEY_LEN] = {0};
static const uint8_t SENTINEL_RADIO_WIFI_CHANNEL = 0;
#endif

static_assert(
  sizeof(SENTINEL_RADIO_PEER_MAC) == ESP_NOW_ETH_ALEN,
  "SENTINEL_RADIO_PEER_MAC must contain exactly 6 bytes"
);
static_assert(
  sizeof(SENTINEL_RADIO_PMK) == ESP_NOW_KEY_LEN,
  "SENTINEL_RADIO_PMK must contain exactly 16 bytes"
);
static_assert(
  sizeof(SENTINEL_RADIO_LMK) == ESP_NOW_KEY_LEN,
  "SENTINEL_RADIO_LMK must contain exactly 16 bytes"
);

// GPIO34/GPIO35 are input-only ADC pins.
const int PIN_ADC_LEFT = 34;
const int PIN_ADC_RIGHT = 35;

// Motor driver placeholders. Confirm wiring before any future motor-enabled build.
const int PIN_MOTOR_L_FWD = 25;
const int PIN_MOTOR_L_REV = 26;
const int PIN_MOTOR_L_PWM = 27;
const int PIN_MOTOR_R_FWD = 14;
const int PIN_MOTOR_R_REV = 33;
const int PIN_MOTOR_R_PWM = 32;

const int PWM_FREQ = 1000;
const int PWM_RESOLUTION = 8;

enum VehicleState {
  STATE_IDLE,
  STATE_RUNNING,
  STATE_LOCKED
};

enum CommandOrigin {
  ORIGIN_USB,
  ORIGIN_ESP_NOW
};

struct RadioMessage {
  size_t length;
  char data[MAX_LINE_LENGTH + 1];
};

struct OutboundRadioMessage {
  size_t length;
  bool transactionResponse;
  char data[MAX_LINE_LENGTH + 1];
};

VehicleState currentState = STATE_LOCKED;
const String VEHICLE_ID = "vehicle_01";
volatile bool radioReady = false;

float Kp = 0.030;
float Ki = 0.001;
float Kd = 0.150;

int lastError = 0;
float integral = 0.0;
const float INTEGRAL_MAX = 1000.0;
float currentSteer = 0.0;

int adcL = 0;
int adcR = 0;
int lastLeftPwm = 0;
int lastRightPwm = 0;

unsigned long lastTelemetryTime = 0;
const unsigned long TELEMETRY_INTERVAL_MS = 1000;

unsigned long lastDryRunPrintTime = 0;
const unsigned long DRY_RUN_PRINT_INTERVAL_MS = 1000;

unsigned long lastCommandTime = 0;
const unsigned long COMMAND_TIMEOUT_MS = 10000;

char serialLineBuffer[MAX_LINE_LENGTH + 1];
size_t serialLineLength = 0;
bool pendingCarriageReturn = false;
bool discardingOverflowLine = false;

RadioMessage radioQueue[RADIO_QUEUE_CAPACITY];
volatile size_t radioQueueHead = 0;
volatile size_t radioQueueTail = 0;
volatile size_t radioQueueCount = 0;
volatile bool radioQueueOverflowObserved = false;
volatile bool unauthorizedPeerObserved = false;
volatile bool invalidRadioPayloadObserved = false;
volatile bool radioLinkSendFailureObserved = false;
volatile bool radioSendInFlight = false;
portMUX_TYPE radioQueueMux = portMUX_INITIALIZER_UNLOCKED;

OutboundRadioMessage radioTransmitQueue[RADIO_TRANSMIT_QUEUE_CAPACITY];
size_t radioTransmitQueueHead = 0;
size_t radioTransmitQueueTail = 0;
size_t radioTransmitQueueCount = 0;

void readSerialCommands();
bool appendSerialByte(char value);
void finishSerialLine();
void processCommandFrame(
  const char *frame,
  size_t length,
  CommandOrigin origin
);
bool isAsciiLetter(char value);
bool bytesEqual(const char *value, size_t length, const char *expected);
String stringFromBytes(const char *value, size_t length);
void executeCommand(const String &txid, String verb, CommandOrigin origin);
void handleReset(const String &txid, CommandOrigin origin);
void handleStart(const String &txid, CommandOrigin origin);
void handleStop(const String &txid, CommandOrigin origin);
bool emitAck(
  const String &txid,
  const String &verb,
  CommandOrigin origin
);
bool emitNack(
  const String &txid,
  const String &verb,
  const char *reason,
  CommandOrigin origin
);
bool routeTransactionResponse(const String &frame, CommandOrigin origin);
void emitParserDiagnostic(const char *line, CommandOrigin origin);
void clearControlState();
void checkCommunicationTimeout(unsigned long nowMs);
void readSensors();
void updatePidAndMotors();
void setMotorOutputs(float steer);
void forceMotorsOff();
int clampInt(int value, int minValue, int maxValue);
String stateToString();
void emitTelemetry(bool transmitToHub = true);
void emitAsynchronousFrame(const String &frame, bool transmitToHub = true);
bool containsNonzeroByte(const uint8_t *value, size_t length);
bool isValidUnicastPeerMac(const uint8_t *value);
bool validateRadioConfiguration();
bool initializeRadio();
void onEspNowReceive(
  const esp_now_recv_info_t *info,
  const uint8_t *data,
  int dataLength
);
void onEspNowSend(
  const esp_now_send_info_t *txInfo,
  esp_now_send_status_t status
);
bool popRadioMessage(RadioMessage &message);
void clearRadioReceiveQueue();
void processRadioQueue();
bool copyValidatedRadioPayload(const RadioMessage &message, char *destination);
bool queueRadioFrame(const String &frame, bool transactionResponse);
void processRadioTransmitQueue();
void clearRadioTransmitQueue();
void reportRadioCallbackDiagnostics();
void enterRadioFailureSafeState(const char *reason);

void setup() {
  Serial.begin(BAUD_RATE);
  delay(500);

  currentState = STATE_LOCKED;

  pinMode(PIN_ADC_LEFT, INPUT);
  pinMode(PIN_ADC_RIGHT, INPUT);

  pinMode(PIN_MOTOR_L_FWD, OUTPUT);
  pinMode(PIN_MOTOR_L_REV, OUTPUT);
  pinMode(PIN_MOTOR_R_FWD, OUTPUT);
  pinMode(PIN_MOTOR_R_REV, OUTPUT);

  ledcAttach(PIN_MOTOR_L_PWM, PWM_FREQ, PWM_RESOLUTION);
  ledcAttach(PIN_MOTOR_R_PWM, PWM_FREQ, PWM_RESOLUTION);

  // Safety ordering: configure outputs and force them off before radio setup.
  forceMotorsOff();
  clearControlState();
  readSensors();

  radioReady = initializeRadio();
  if (radioReady) {
    Serial.println("BOOT,VEHICLE,LOCKED,ESP_NOW_READY");
  }
  else {
    currentState = STATE_LOCKED;
    forceMotorsOff();
    clearControlState();
    Serial.println("BOOT,VEHICLE,LOCKED,ESP_NOW_UNAVAILABLE");
  }
  Serial.println("DIAG,VEHICLE,MOTORS_DISABLED");
  emitTelemetry();
}

void loop() {
  readSensors();
  readSerialCommands();
  reportRadioCallbackDiagnostics();
  processRadioQueue();
  processRadioTransmitQueue();

  unsigned long nowMs = millis();
  checkCommunicationTimeout(nowMs);

  if (currentState == STATE_RUNNING) {
    updatePidAndMotors();
  }
  else {
    clearControlState();
    forceMotorsOff();
  }

  if (nowMs - lastTelemetryTime >= TELEMETRY_INTERVAL_MS) {
    lastTelemetryTime = nowMs;
    emitTelemetry();
  }
  processRadioTransmitQueue();
}

void readSerialCommands() {
  while (Serial.available() > 0) {
    char value = (char)Serial.read();

    if (discardingOverflowLine) {
      if (value == '\n') {
        discardingOverflowLine = false;
        pendingCarriageReturn = false;
        serialLineLength = 0;
      }
      continue;
    }

    if (pendingCarriageReturn) {
      pendingCarriageReturn = false;
      if (value == '\n') {
        finishSerialLine();
        continue;
      }

      if (!appendSerialByte('\r')) {
        continue;
      }
    }

    if (value == '\r') {
      pendingCarriageReturn = true;
    }
    else if (value == '\n') {
      finishSerialLine();
    }
    else {
      appendSerialByte(value);
    }
  }
}

bool appendSerialByte(char value) {
  if (serialLineLength >= MAX_LINE_LENGTH) {
    serialLineLength = 0;
    pendingCarriageReturn = false;
    discardingOverflowLine = true;
    Serial.println("ERR,CMD_TOO_LONG");
    return false;
  }

  serialLineBuffer[serialLineLength++] = value;
  return true;
}

void finishSerialLine() {
  size_t frameLength = serialLineLength;
  serialLineLength = 0;
  pendingCarriageReturn = false;
  processCommandFrame(serialLineBuffer, frameLength, ORIGIN_USB);
}

void processCommandFrame(
  const char *frame,
  size_t length,
  CommandOrigin origin
) {
  if (frame == NULL || length == 0 || length > MAX_LINE_LENGTH) {
    emitParserDiagnostic("ERR,MALFORMED_FRAME", origin);
    return;
  }

  size_t commaPositions[2] = {0, 0};
  size_t commaCount = 0;

  for (size_t index = 0; index < length; ++index) {
    unsigned char value = (unsigned char)frame[index];
    if (value <= 0x1F || value == 0x7F) {
      emitParserDiagnostic("ERR,MALFORMED_FRAME", origin);
      return;
    }
    if (value == ',') {
      if (commaCount >= 2) {
        emitParserDiagnostic("ERR,MALFORMED_FRAME", origin);
        return;
      }
      commaPositions[commaCount++] = index;
    }
  }

  if (commaCount != 2) {
    emitParserDiagnostic("ERR,MALFORMED_FRAME", origin);
    return;
  }

  size_t discriminatorLength = commaPositions[0];
  size_t txidStart = commaPositions[0] + 1;
  size_t txidLength = commaPositions[1] - txidStart;
  size_t verbStart = commaPositions[1] + 1;
  size_t verbLength = length - verbStart;

  if (!bytesEqual(frame, discriminatorLength, "CMD") ||
      txidLength == 0 || txidLength > MAX_TXID_LENGTH ||
      verbLength == 0 || verbLength > MAX_VERB_LENGTH) {
    emitParserDiagnostic("ERR,MALFORMED_FRAME", origin);
    return;
  }

  for (size_t index = 0; index < verbLength; ++index) {
    if (!isAsciiLetter(frame[verbStart + index])) {
      emitParserDiagnostic("ERR,MALFORMED_FRAME", origin);
      return;
    }
  }

  String txid = stringFromBytes(frame + txidStart, txidLength);
  String verb = stringFromBytes(frame + verbStart, verbLength);
  verb.toUpperCase();
  executeCommand(txid, verb, origin);
}

bool isAsciiLetter(char value) {
  return (value >= 'A' && value <= 'Z') ||
         (value >= 'a' && value <= 'z');
}

bool bytesEqual(const char *value, size_t length, const char *expected) {
  size_t expectedLength = strlen(expected);
  if (length != expectedLength) {
    return false;
  }

  for (size_t index = 0; index < length; ++index) {
    if (value[index] != expected[index]) {
      return false;
    }
  }
  return true;
}

String stringFromBytes(const char *value, size_t length) {
  String result;
  result.reserve(length);
  for (size_t index = 0; index < length; ++index) {
    result += value[index];
  }
  return result;
}

void executeCommand(const String &txid, String verb, CommandOrigin origin) {
  if (verb == "RESET") {
    handleReset(txid, origin);
  }
  else if (verb == "START") {
    handleStart(txid, origin);
  }
  else if (verb == "STOP") {
    handleStop(txid, origin);
  }
  else if (verb == "STATUS") {
    emitAck(txid, verb, origin);
  }
  else if (verb == "PING") {
    if (currentState == STATE_RUNNING) {
      lastCommandTime = millis();
    }
    emitAck(txid, verb, origin);
  }
  else {
    emitNack(txid, verb, "UNSUPPORTED_VERB", origin);
  }
}

void handleReset(const String &txid, CommandOrigin origin) {
  // Motor and control safety actions must complete before the ACK is generated.
  forceMotorsOff();
  clearControlState();
  currentState = STATE_IDLE;
  emitAck(txid, "RESET", origin);
  emitTelemetry();
}

void handleStart(const String &txid, CommandOrigin origin) {
  if (currentState == STATE_LOCKED) {
    forceMotorsOff();
    emitNack(txid, "START", "LOCKED_REQUIRE_RESET", origin);
    return;
  }

  if (currentState == STATE_IDLE) {
    clearControlState();
    currentState = STATE_RUNNING;
  }

  // START while already RUNNING is idempotent and refreshes the timeout.
  lastCommandTime = millis();
  emitAck(txid, "START", origin);
  emitTelemetry();
}

void handleStop(const String &txid, CommandOrigin origin) {
  // Motor and control safety actions must complete before the ACK is generated.
  forceMotorsOff();
  clearControlState();
  currentState = STATE_LOCKED;
  emitAck(txid, "STOP", origin);
  emitTelemetry();
}

bool emitAck(
  const String &txid,
  const String &verb,
  CommandOrigin origin
) {
  String frame = "ACK," + txid + "," + verb + "," +
    stateToString() + ",VEHICLE";
  return routeTransactionResponse(frame, origin);
}

bool emitNack(
  const String &txid,
  const String &verb,
  const char *reason,
  CommandOrigin origin
) {
  String frame = "NACK," + txid + "," + verb + "," + String(reason) +
    "," + stateToString() + ",VEHICLE";
  return routeTransactionResponse(frame, origin);
}

bool routeTransactionResponse(const String &frame, CommandOrigin origin) {
  if (origin == ORIGIN_USB) {
    Serial.println(frame);
    return true;
  }

  if (queueRadioFrame(frame, true)) {
    return true;
  }

  // No ACK was transmitted. Lock immediately rather than leaving a failed
  // radio transaction in RUNNING or IDLE.
  enterRadioFailureSafeState("ESP_NOW_RESPONSE_SEND_FAILED");
  return false;
}

void emitParserDiagnostic(const char *line, CommandOrigin origin) {
  Serial.println(line);
  if (origin == ORIGIN_ESP_NOW && radioReady) {
    String diagnostic = "DIAG,VEHICLE,MALFORMED_COMMAND_IGNORED";
    if (!queueRadioFrame(diagnostic, false)) {
      enterRadioFailureSafeState("ESP_NOW_DIAGNOSTIC_SEND_FAILED");
    }
  }
}

void clearControlState() {
  lastError = 0;
  integral = 0.0;
  currentSteer = 0.0;
}

void checkCommunicationTimeout(unsigned long nowMs) {
  if (currentState != STATE_RUNNING || !COMMAND_TIMEOUT_ENABLED) {
    return;
  }

  if (nowMs - lastCommandTime <= COMMAND_TIMEOUT_MS) {
    return;
  }

  // Safety ordering: outputs off and state cleared before any outward message.
  forceMotorsOff();
  clearControlState();
  currentState = STATE_LOCKED;
  emitAsynchronousFrame("EVENT,VEHICLE,COMMUNICATION_TIMEOUT,LOCKED");
  emitTelemetry();
}

void readSensors() {
  adcL = analogRead(PIN_ADC_LEFT);
  adcR = analogRead(PIN_ADC_RIGHT);
}

void updatePidAndMotors() {
  int error = adcL - adcR;
  float proportional = error * Kp;

  integral += error;
  if (integral > INTEGRAL_MAX) integral = INTEGRAL_MAX;
  if (integral < -INTEGRAL_MAX) integral = -INTEGRAL_MAX;
  float integralTerm = integral * Ki;

  float derivative = (error - lastError) * Kd;
  currentSteer = (proportional + integralTerm + derivative) * 0.01;
  lastError = error;

  setMotorOutputs(currentSteer);
}

void setMotorOutputs(float steer) {
  float basePwm = 120.0;
  float steerScale = 100.0;
  int intendedLeftPwm = clampInt((int)(basePwm + (steer * steerScale)), 0, 255);
  int intendedRightPwm = clampInt((int)(basePwm - (steer * steerScale)), 0, 255);

  if (currentState != STATE_RUNNING) {
    forceMotorsOff();
    return;
  }

  if (MOTORS_ENABLED) {
    lastLeftPwm = intendedLeftPwm;
    lastRightPwm = intendedRightPwm;
    digitalWrite(PIN_MOTOR_L_FWD, HIGH);
    digitalWrite(PIN_MOTOR_L_REV, LOW);
    digitalWrite(PIN_MOTOR_R_FWD, HIGH);
    digitalWrite(PIN_MOTOR_R_REV, LOW);
    ledcWrite(PIN_MOTOR_L_PWM, lastLeftPwm);
    ledcWrite(PIN_MOTOR_R_PWM, lastRightPwm);
  }
  else {
    // Phase 3B dry-run: continuously retain the physical motor-off invariant.
    forceMotorsOff();
    unsigned long nowMs = millis();
    if (nowMs - lastDryRunPrintTime >= DRY_RUN_PRINT_INTERVAL_MS) {
      lastDryRunPrintTime = nowMs;
      String diagnostic = "DIAG,VEHICLE,DRY_RUN_PWM," +
        String(intendedLeftPwm) + "," + String(intendedRightPwm) + "," +
        String(currentSteer, 3);
      emitAsynchronousFrame(diagnostic);
    }
  }
}

void forceMotorsOff() {
  lastLeftPwm = 0;
  lastRightPwm = 0;

  digitalWrite(PIN_MOTOR_L_FWD, LOW);
  digitalWrite(PIN_MOTOR_L_REV, LOW);
  digitalWrite(PIN_MOTOR_R_FWD, LOW);
  digitalWrite(PIN_MOTOR_R_REV, LOW);
  ledcWrite(PIN_MOTOR_L_PWM, 0);
  ledcWrite(PIN_MOTOR_R_PWM, 0);
}

int clampInt(int value, int minValue, int maxValue) {
  if (value < minValue) return minValue;
  if (value > maxValue) return maxValue;
  return value;
}

String stateToString() {
  if (currentState == STATE_IDLE) return "IDLE";
  if (currentState == STATE_RUNNING) return "RUNNING";
  if (currentState == STATE_LOCKED) return "LOCKED";
  return "UNKNOWN";
}

void emitTelemetry(bool transmitToHub) {
  String frame = "TEL," + VEHICLE_ID + "," + String(adcL) + "," +
    String(adcR) + "," + String(currentSteer, 3) + "," + stateToString();
  emitAsynchronousFrame(frame, transmitToHub);
}

void emitAsynchronousFrame(const String &frame, bool transmitToHub) {
  Serial.println(frame);
  if (transmitToHub && radioReady && !queueRadioFrame(frame, false)) {
    Serial.println("DIAG,VEHICLE,RADIO_TRANSMIT_QUEUE_ASYNC_DROP");
  }
}

bool containsNonzeroByte(const uint8_t *value, size_t length) {
  if (value == NULL || length == 0) {
    return false;
  }
  for (size_t index = 0; index < length; ++index) {
    if (value[index] != 0) {
      return true;
    }
  }
  return false;
}

bool isValidUnicastPeerMac(const uint8_t *value) {
  if (!containsNonzeroByte(value, ESP_NOW_ETH_ALEN) || (value[0] & 0x01) != 0) {
    return false;
  }
  return true;
}

bool validateRadioConfiguration() {
  if (!SENTINEL_HAS_LOCAL_RADIO_CONFIG || !SENTINEL_RADIO_CONFIGURED) {
    return false;
  }
  if (SENTINEL_RADIO_WIFI_CHANNEL < 1 || SENTINEL_RADIO_WIFI_CHANNEL > 11) {
    return false;
  }
  if (!isValidUnicastPeerMac(SENTINEL_RADIO_PEER_MAC)) {
    return false;
  }
  if (!containsNonzeroByte(SENTINEL_RADIO_PMK, ESP_NOW_KEY_LEN) ||
      !containsNonzeroByte(SENTINEL_RADIO_LMK, ESP_NOW_KEY_LEN)) {
    return false;
  }
  return true;
}

bool initializeRadio() {
  if (!validateRadioConfiguration()) {
    return false;
  }
  if (!WiFi.mode(WIFI_STA)) {
    return false;
  }
  if (esp_wifi_set_channel(
        SENTINEL_RADIO_WIFI_CHANNEL,
        WIFI_SECOND_CHAN_NONE
      ) != ESP_OK) {
    return false;
  }
  if (esp_now_init() != ESP_OK) {
    return false;
  }

  if (esp_now_set_pmk(SENTINEL_RADIO_PMK) != ESP_OK ||
      esp_now_register_recv_cb(onEspNowReceive) != ESP_OK ||
      esp_now_register_send_cb(onEspNowSend) != ESP_OK) {
    esp_now_deinit();
    return false;
  }

  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, SENTINEL_RADIO_PEER_MAC, ESP_NOW_ETH_ALEN);
  memcpy(peer.lmk, SENTINEL_RADIO_LMK, ESP_NOW_KEY_LEN);
  peer.channel = SENTINEL_RADIO_WIFI_CHANNEL;
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = true;

  if (esp_now_add_peer(&peer) != ESP_OK) {
    esp_now_deinit();
    return false;
  }

  esp_now_peer_num_t peerCount = {};
  esp_now_peer_info_t confirmedPeer = {};
  if (esp_now_get_peer_num(&peerCount) != ESP_OK ||
      peerCount.total_num != 1 ||
      peerCount.encrypt_num != 1 ||
      esp_now_get_peer(SENTINEL_RADIO_PEER_MAC, &confirmedPeer) != ESP_OK ||
      !confirmedPeer.encrypt ||
      confirmedPeer.ifidx != WIFI_IF_STA ||
      confirmedPeer.channel != SENTINEL_RADIO_WIFI_CHANNEL) {
    esp_now_deinit();
    return false;
  }
  return true;
}

void onEspNowReceive(
  const esp_now_recv_info_t *info,
  const uint8_t *data,
  int dataLength
) {
  if (info == NULL || info->src_addr == NULL ||
      memcmp(info->src_addr, SENTINEL_RADIO_PEER_MAC, ESP_NOW_ETH_ALEN) != 0) {
    portENTER_CRITICAL(&radioQueueMux);
    unauthorizedPeerObserved = true;
    portEXIT_CRITICAL(&radioQueueMux);
    return;
  }

  if (!radioReady || data == NULL || dataLength <= 0 ||
      dataLength > (int)MAX_LINE_LENGTH) {
    portENTER_CRITICAL(&radioQueueMux);
    invalidRadioPayloadObserved = true;
    portEXIT_CRITICAL(&radioQueueMux);
    return;
  }

  portENTER_CRITICAL(&radioQueueMux);
  if (radioQueueCount >= RADIO_QUEUE_CAPACITY) {
    radioQueueOverflowObserved = true;
    portEXIT_CRITICAL(&radioQueueMux);
    return;
  }

  RadioMessage &slot = radioQueue[radioQueueTail];
  slot.length = (size_t)dataLength;
  memcpy(slot.data, data, slot.length);
  slot.data[slot.length] = '\0';
  radioQueueTail = (radioQueueTail + 1) % RADIO_QUEUE_CAPACITY;
  ++radioQueueCount;
  portEXIT_CRITICAL(&radioQueueMux);
}

void onEspNowSend(
  const esp_now_send_info_t *txInfo,
  esp_now_send_status_t status
) {
  bool expectedPeer = txInfo != NULL && txInfo->des_addr != NULL &&
    memcmp(txInfo->des_addr, SENTINEL_RADIO_PEER_MAC, ESP_NOW_ETH_ALEN) == 0;
  if (!expectedPeer || status != ESP_NOW_SEND_SUCCESS) {
    portENTER_CRITICAL(&radioQueueMux);
    radioLinkSendFailureObserved = true;
    radioSendInFlight = false;
    portEXIT_CRITICAL(&radioQueueMux);
  }
  else {
    portENTER_CRITICAL(&radioQueueMux);
    radioSendInFlight = false;
    portEXIT_CRITICAL(&radioQueueMux);
  }
  // Link delivery is never interpreted as vehicle command execution.
}

bool popRadioMessage(RadioMessage &message) {
  portENTER_CRITICAL(&radioQueueMux);
  if (radioQueueCount == 0) {
    portEXIT_CRITICAL(&radioQueueMux);
    return false;
  }
  message = radioQueue[radioQueueHead];
  radioQueueHead = (radioQueueHead + 1) % RADIO_QUEUE_CAPACITY;
  --radioQueueCount;
  portEXIT_CRITICAL(&radioQueueMux);
  return true;
}

void clearRadioReceiveQueue() {
  portENTER_CRITICAL(&radioQueueMux);
  radioQueueHead = 0;
  radioQueueTail = 0;
  radioQueueCount = 0;
  portEXIT_CRITICAL(&radioQueueMux);
}

void processRadioQueue() {
  if (!radioReady) {
    clearRadioReceiveQueue();
    return;
  }

  RadioMessage message;
  char safeFrame[MAX_LINE_LENGTH + 1];
  while (popRadioMessage(message)) {
    if (!copyValidatedRadioPayload(message, safeFrame)) {
      Serial.println("DIAG,VEHICLE,MALFORMED_RADIO_PAYLOAD_IGNORED");
      continue;
    }
    processCommandFrame(safeFrame, message.length, ORIGIN_ESP_NOW);
  }
}

bool copyValidatedRadioPayload(
  const RadioMessage &message,
  char *destination
) {
  if (destination == NULL || message.length == 0 ||
      message.length > MAX_LINE_LENGTH ||
      message.data[message.length] != '\0') {
    return false;
  }
  for (size_t index = 0; index < message.length; ++index) {
    unsigned char value = (unsigned char)message.data[index];
    if (value <= 0x1F || value == 0x7F) {
      return false;
    }
    destination[index] = message.data[index];
  }
  destination[message.length] = '\0';
  return true;
}

bool queueRadioFrame(const String &frame, bool transactionResponse) {
  if (!radioReady || frame.length() == 0 ||
      frame.length() > MAX_LINE_LENGTH) {
    return false;
  }

  if (radioTransmitQueueCount >= RADIO_TRANSMIT_QUEUE_CAPACITY) {
    return false;
  }

  size_t slotIndex = radioTransmitQueueTail;
  if (transactionResponse) {
    radioTransmitQueueHead =
      (radioTransmitQueueHead + RADIO_TRANSMIT_QUEUE_CAPACITY - 1) %
      RADIO_TRANSMIT_QUEUE_CAPACITY;
    slotIndex = radioTransmitQueueHead;
  }
  else {
    radioTransmitQueueTail =
      (radioTransmitQueueTail + 1) % RADIO_TRANSMIT_QUEUE_CAPACITY;
  }

  OutboundRadioMessage &slot = radioTransmitQueue[slotIndex];
  slot.length = frame.length();
  slot.transactionResponse = transactionResponse;
  memcpy(slot.data, frame.c_str(), slot.length);
  slot.data[slot.length] = '\0';
  ++radioTransmitQueueCount;
  return true;
}

void processRadioTransmitQueue() {
  if (!radioReady || radioTransmitQueueCount == 0) {
    return;
  }

  portENTER_CRITICAL(&radioQueueMux);
  if (radioSendInFlight) {
    portEXIT_CRITICAL(&radioQueueMux);
    return;
  }
  radioSendInFlight = true;
  portEXIT_CRITICAL(&radioQueueMux);

  OutboundRadioMessage message = radioTransmitQueue[radioTransmitQueueHead];
  radioTransmitQueueHead =
    (radioTransmitQueueHead + 1) % RADIO_TRANSMIT_QUEUE_CAPACITY;
  --radioTransmitQueueCount;

  esp_err_t result = esp_now_send(
    SENTINEL_RADIO_PEER_MAC,
    reinterpret_cast<const uint8_t *>(message.data),
    message.length
  );
  if (result != ESP_OK) {
    portENTER_CRITICAL(&radioQueueMux);
    radioSendInFlight = false;
    portEXIT_CRITICAL(&radioQueueMux);
    enterRadioFailureSafeState(
      message.transactionResponse
        ? "ESP_NOW_RESPONSE_SEND_FAILED"
        : "ESP_NOW_ASYNC_SEND_FAILED"
    );
  }
}

void clearRadioTransmitQueue() {
  radioTransmitQueueHead = 0;
  radioTransmitQueueTail = 0;
  radioTransmitQueueCount = 0;
}

void reportRadioCallbackDiagnostics() {
  bool overflow = false;
  bool unauthorized = false;
  bool invalid = false;
  bool sendFailure = false;

  portENTER_CRITICAL(&radioQueueMux);
  overflow = radioQueueOverflowObserved;
  unauthorized = unauthorizedPeerObserved;
  invalid = invalidRadioPayloadObserved;
  sendFailure = radioLinkSendFailureObserved;
  radioQueueOverflowObserved = false;
  unauthorizedPeerObserved = false;
  invalidRadioPayloadObserved = false;
  radioLinkSendFailureObserved = false;
  portEXIT_CRITICAL(&radioQueueMux);

  if (overflow) Serial.println("DIAG,VEHICLE,RADIO_QUEUE_OVERFLOW_COMMAND_DROPPED");
  if (unauthorized) Serial.println("DIAG,VEHICLE,UNAUTHORIZED_PEER_IGNORED");
  if (invalid) Serial.println("DIAG,VEHICLE,INVALID_RADIO_PAYLOAD_IGNORED");
  if (sendFailure) {
    enterRadioFailureSafeState("ESP_NOW_LINK_SEND_FAILED");
  }
}

void enterRadioFailureSafeState(const char *reason) {
  radioReady = false;
  clearRadioReceiveQueue();
  clearRadioTransmitQueue();
  forceMotorsOff();
  clearControlState();
  currentState = STATE_LOCKED;
  String event = "EVENT,VEHICLE," + String(reason) + ",LOCKED";
  Serial.println(event);
  emitTelemetry(false);
}
