/*
  Sentinel-CPS Hub Firmware Phase 3B
  Target: ESP32-D0WDQ6 or compatible ESP32 development board
  Purpose: Transaction-aware Gateway USB serial to encrypted ESP-NOW bridge.

  Execution authority remains on the vehicle. ESP-NOW API acceptance and its
  link-layer send callback are never converted into command ACKs.
*/

#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>

#define BAUD_RATE 115200

static const size_t MAX_LINE_LENGTH = 128;
static const size_t MAX_TXID_LENGTH = 64;
static const size_t MAX_VERB_LENGTH = 16;
static const size_t RADIO_QUEUE_CAPACITY = 8;

// This is intentionally below the Gateway's repository-default 1000 ms ACK
// timeout. Phase 3B performs no automatic radio retry.
static const unsigned long DOWNSTREAM_RESPONSE_TIMEOUT_MS = 750;

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

enum SystemState {
  STATE_LOCKED
};

struct RadioMessage {
  size_t length;
  unsigned long receivedAtMs;
  char data[MAX_LINE_LENGTH + 1];
};

struct PendingTransaction {
  bool active;
  String txid;
  String verb;
  unsigned long sentAtMs;
};

SystemState currentState = STATE_LOCKED;
String inputBuffer = "";
bool pendingCarriageReturn = false;
bool discardingOverflowLine = false;
bool radioReady = false;

PendingTransaction pendingTransaction = {false, "", "", 0};

RadioMessage radioQueue[RADIO_QUEUE_CAPACITY];
volatile size_t radioQueueHead = 0;
volatile size_t radioQueueTail = 0;
volatile size_t radioQueueCount = 0;
volatile bool radioQueueOverflowObserved = false;
volatile bool unauthorizedPeerObserved = false;
volatile bool invalidRadioPayloadObserved = false;
volatile bool radioLinkSendFailureObserved = false;
portMUX_TYPE radioQueueMux = portMUX_INITIALIZER_UNLOCKED;

void readGatewayFrames();
bool appendInputByte(char value);
void finishInputLine();
void handleGatewayFrame(const String &frame);
bool isValidTransactionId(const String &txid);
bool isValidVerbToken(const String &verb);
bool isSupportedVerb(const String &verb);
bool isValidState(const String &state);
bool isValidReasonToken(const String &reason);
bool isValidUnsignedInteger(const String &value);
bool isValidFloatToken(const String &value);
size_t splitCsv(const String &frame, String *fields, size_t capacity);
bool fieldsAreNonempty(const String *fields, size_t fieldCount);
void emitNack(const String &txid, const String &verb, const char *reason);
void emitHubDiagnostic(const char *code);
bool validateRadioConfiguration();
bool containsNonzeroByte(const uint8_t *value, size_t length);
bool isValidUnicastPeerMac(const uint8_t *value);
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
void processRadioQueue();
bool copyValidatedRadioText(const RadioMessage &message, String &frame);
void handleRadioFrame(const String &frame, unsigned long receivedAtMs);
bool isValidTransactionResponse(
  const String *fields,
  size_t fieldCount
);
bool isValidTelemetry(const String *fields, size_t fieldCount);
void handleTransactionResponse(
  const String &frame,
  const String *fields,
  unsigned long receivedAtMs
);
void checkDownstreamTimeout(unsigned long nowMs);
void clearPendingTransaction();
void reportCallbackDiagnostics();

void setup() {
  Serial.begin(BAUD_RATE);
  delay(500);

  inputBuffer.reserve(MAX_LINE_LENGTH);
  pendingTransaction.txid.reserve(MAX_TXID_LENGTH);
  pendingTransaction.verb.reserve(MAX_VERB_LENGTH);
  currentState = STATE_LOCKED;

  radioReady = initializeRadio();
  if (radioReady) {
    Serial.println("BOOT,HUB,LOCKED,ESP_NOW_READY");
  }
  else {
    currentState = STATE_LOCKED;
    Serial.println("BOOT,HUB,LOCKED,ESP_NOW_UNAVAILABLE");
  }
}

void loop() {
  readGatewayFrames();
  processRadioQueue();
  checkDownstreamTimeout(millis());
  reportCallbackDiagnostics();
}

void readGatewayFrames() {
  while (Serial.available() > 0) {
    char value = (char)Serial.read();

    if (discardingOverflowLine) {
      if (value == '\n') {
        discardingOverflowLine = false;
        pendingCarriageReturn = false;
        inputBuffer = "";
      }
      continue;
    }

    if (pendingCarriageReturn) {
      pendingCarriageReturn = false;
      if (value == '\n') {
        finishInputLine();
        continue;
      }

      if (!appendInputByte('\r')) {
        continue;
      }
    }

    if (value == '\r') {
      pendingCarriageReturn = true;
    }
    else if (value == '\n') {
      finishInputLine();
    }
    else {
      appendInputByte(value);
    }
  }
}

bool appendInputByte(char value) {
  if (inputBuffer.length() >= MAX_LINE_LENGTH) {
    inputBuffer = "";
    pendingCarriageReturn = false;
    discardingOverflowLine = true;
    Serial.println("ERR,CMD_TOO_LONG");
    return false;
  }

  inputBuffer += value;
  return true;
}

void finishInputLine() {
  String frame = inputBuffer;
  inputBuffer = "";
  pendingCarriageReturn = false;
  handleGatewayFrame(frame);
}

void handleGatewayFrame(const String &frame) {
  int firstComma = frame.indexOf(',');
  int secondComma = firstComma < 0 ? -1 : frame.indexOf(',', firstComma + 1);
  int thirdComma = secondComma < 0 ? -1 : frame.indexOf(',', secondComma + 1);

  if (firstComma < 0 || secondComma < 0 || thirdComma >= 0) {
    Serial.println("ERR,MALFORMED_FRAME");
    return;
  }

  String discriminator = frame.substring(0, firstComma);
  String txid = frame.substring(firstComma + 1, secondComma);
  String verb = frame.substring(secondComma + 1);

  if (discriminator != "CMD" ||
      !isValidTransactionId(txid) ||
      !isValidVerbToken(verb)) {
    Serial.println("ERR,MALFORMED_FRAME");
    return;
  }

  // Preserve txid byte-for-byte; normalize only the protocol verb.
  verb.toUpperCase();

  if (!isSupportedVerb(verb)) {
    emitNack(txid, verb, "UNSUPPORTED_VERB");
    return;
  }

  if (verb == "STOP") {
    // This is only the Hub's local safety state. Vehicle STOP is not proven
    // until the matching vehicle response is received and forwarded.
    currentState = STATE_LOCKED;
  }

  if (!radioReady) {
    emitNack(txid, verb, "NO_DOWNSTREAM_TRANSPORT");
    return;
  }

  if (pendingTransaction.active) {
    emitNack(txid, verb, "DOWNSTREAM_BUSY");
    return;
  }

  String downstreamFrame = "CMD," + txid + "," + verb;
  if (downstreamFrame.length() == 0 ||
      downstreamFrame.length() > MAX_LINE_LENGTH) {
    Serial.println("ERR,MALFORMED_FRAME");
    return;
  }

  pendingTransaction.active = true;
  pendingTransaction.txid = txid;
  pendingTransaction.verb = verb;
  pendingTransaction.sentAtMs = millis();

  esp_err_t result = esp_now_send(
    SENTINEL_RADIO_PEER_MAC,
    reinterpret_cast<const uint8_t *>(downstreamFrame.c_str()),
    downstreamFrame.length()
  );
  if (result != ESP_OK) {
    clearPendingTransaction();
    emitNack(txid, verb, "DOWNSTREAM_SEND_FAILED");
  }
}

bool isValidTransactionId(const String &txid) {
  if (txid.length() == 0 || txid.length() > MAX_TXID_LENGTH) {
    return false;
  }

  for (size_t index = 0; index < txid.length(); ++index) {
    unsigned char value = (unsigned char)txid[index];
    if (value == ',' || value <= 0x1F || value == 0x7F) {
      return false;
    }
  }
  return true;
}

bool isValidVerbToken(const String &verb) {
  if (verb.length() == 0 || verb.length() > MAX_VERB_LENGTH) {
    return false;
  }

  for (size_t index = 0; index < verb.length(); ++index) {
    char value = verb[index];
    bool isUppercase = value >= 'A' && value <= 'Z';
    bool isLowercase = value >= 'a' && value <= 'z';
    if (!isUppercase && !isLowercase) {
      return false;
    }
  }
  return true;
}

bool isSupportedVerb(const String &verb) {
  return verb == "START" ||
         verb == "STOP" ||
         verb == "RESET" ||
         verb == "STATUS" ||
         verb == "PING";
}

bool isValidState(const String &state) {
  return state == "IDLE" || state == "RUNNING" || state == "LOCKED";
}

bool isValidReasonToken(const String &reason) {
  if (reason.length() == 0 || reason.length() > 64) {
    return false;
  }
  for (size_t index = 0; index < reason.length(); ++index) {
    char value = reason[index];
    bool valid = (value >= 'A' && value <= 'Z') ||
                 (value >= '0' && value <= '9') ||
                 value == '_';
    if (!valid) {
      return false;
    }
  }
  return true;
}

bool isValidUnsignedInteger(const String &value) {
  if (value.length() == 0) {
    return false;
  }
  for (size_t index = 0; index < value.length(); ++index) {
    if (value[index] < '0' || value[index] > '9') {
      return false;
    }
  }
  return true;
}

bool isValidFloatToken(const String &value) {
  if (value.length() == 0) {
    return false;
  }
  char *end = NULL;
  strtof(value.c_str(), &end);
  return end != value.c_str() && *end == '\0';
}

size_t splitCsv(const String &frame, String *fields, size_t capacity) {
  if (capacity == 0) {
    return 0;
  }

  size_t fieldCount = 0;
  size_t fieldStart = 0;
  for (size_t index = 0; index <= frame.length(); ++index) {
    if (index == frame.length() || frame[index] == ',') {
      if (fieldCount >= capacity) {
        return 0;
      }
      fields[fieldCount++] = frame.substring(fieldStart, index);
      fieldStart = index + 1;
    }
  }
  return fieldCount;
}

bool fieldsAreNonempty(const String *fields, size_t fieldCount) {
  for (size_t index = 0; index < fieldCount; ++index) {
    if (fields[index].length() == 0) {
      return false;
    }
  }
  return true;
}

void emitNack(const String &txid, const String &verb, const char *reason) {
  Serial.print("NACK,");
  Serial.print(txid);
  Serial.print(",");
  Serial.print(verb);
  Serial.print(",");
  Serial.print(reason);
  Serial.println(",LOCKED,HUB");
}

void emitHubDiagnostic(const char *code) {
  Serial.print("DIAG,HUB,");
  Serial.println(code);
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

  if (data == NULL || dataLength <= 0 ||
      dataLength > (int)MAX_LINE_LENGTH) {
    portENTER_CRITICAL(&radioQueueMux);
    invalidRadioPayloadObserved = true;
    portEXIT_CRITICAL(&radioQueueMux);
    return;
  }

  unsigned long receivedAtMs = millis();
  portENTER_CRITICAL(&radioQueueMux);
  if (radioQueueCount >= RADIO_QUEUE_CAPACITY) {
    radioQueueOverflowObserved = true;
    portEXIT_CRITICAL(&radioQueueMux);
    return;
  }

  RadioMessage &slot = radioQueue[radioQueueTail];
  slot.length = (size_t)dataLength;
  slot.receivedAtMs = receivedAtMs;
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
    portEXIT_CRITICAL(&radioQueueMux);
  }
  // Link-layer success is deliberately not a transaction completion.
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

void processRadioQueue() {
  RadioMessage message;
  while (popRadioMessage(message)) {
    String frame;
    frame.reserve(message.length);
    if (!copyValidatedRadioText(message, frame)) {
      emitHubDiagnostic("MALFORMED_RADIO_PAYLOAD");
      continue;
    }
    handleRadioFrame(frame, message.receivedAtMs);
  }
}

bool copyValidatedRadioText(const RadioMessage &message, String &frame) {
  if (message.length == 0 || message.length > MAX_LINE_LENGTH ||
      message.data[message.length] != '\0') {
    return false;
  }
  for (size_t index = 0; index < message.length; ++index) {
    unsigned char value = (unsigned char)message.data[index];
    if (value <= 0x1F || value == 0x7F) {
      return false;
    }
    frame += message.data[index];
  }
  return frame.length() == message.length;
}

void handleRadioFrame(const String &frame, unsigned long receivedAtMs) {
  String fields[8];
  size_t fieldCount = splitCsv(frame, fields, 8);
  if (fieldCount == 0) {
    emitHubDiagnostic("MALFORMED_RADIO_FRAME");
    return;
  }

  if (fields[0] == "ACK" || fields[0] == "NACK") {
    if (!isValidTransactionResponse(fields, fieldCount)) {
      emitHubDiagnostic("MALFORMED_VEHICLE_RESPONSE");
      return;
    }
    handleTransactionResponse(frame, fields, receivedAtMs);
    return;
  }

  if (fields[0] == "TEL") {
    if (isValidTelemetry(fields, fieldCount)) {
      Serial.println(frame);
    }
    else {
      emitHubDiagnostic("MALFORMED_VEHICLE_TELEMETRY");
    }
    return;
  }

  if ((fields[0] == "EVENT" || fields[0] == "DIAG") &&
      fieldCount >= 3 && fieldsAreNonempty(fields, fieldCount)) {
    Serial.println(frame);
    return;
  }

  emitHubDiagnostic("UNRECOGNIZED_RADIO_FRAME");
}

bool isValidTransactionResponse(
  const String *fields,
  size_t fieldCount
) {
  String uppercaseVerb = fields[2];
  uppercaseVerb.toUpperCase();
  if (fields[0] == "ACK") {
    return fieldCount == 5 &&
           isValidTransactionId(fields[1]) &&
           isValidVerbToken(fields[2]) &&
           fields[2] == uppercaseVerb &&
           isValidState(fields[3]) &&
           fields[4] == "VEHICLE";
  }
  if (fields[0] == "NACK") {
    return fieldCount == 6 &&
           isValidTransactionId(fields[1]) &&
           isValidVerbToken(fields[2]) &&
           fields[2] == uppercaseVerb &&
           isValidReasonToken(fields[3]) &&
           isValidState(fields[4]) &&
           fields[5] == "VEHICLE";
  }
  return false;
}

bool isValidTelemetry(const String *fields, size_t fieldCount) {
  return fieldCount == 6 &&
         fields[1].length() > 0 &&
         isValidUnsignedInteger(fields[2]) &&
         isValidUnsignedInteger(fields[3]) &&
         isValidFloatToken(fields[4]) &&
         isValidState(fields[5]);
}

void handleTransactionResponse(
  const String &frame,
  const String *fields,
  unsigned long receivedAtMs
) {
  if (!pendingTransaction.active) {
    emitHubDiagnostic("LATE_OR_DUPLICATE_RESPONSE_IGNORED");
    return;
  }

  if (receivedAtMs - pendingTransaction.sentAtMs >
      DOWNSTREAM_RESPONSE_TIMEOUT_MS) {
    emitHubDiagnostic("LATE_RESPONSE_IGNORED");
    return;
  }

  if (fields[1] != pendingTransaction.txid ||
      fields[2] != pendingTransaction.verb) {
    emitHubDiagnostic("MISMATCHED_RESPONSE_IGNORED");
    return;
  }

  clearPendingTransaction();
  Serial.println(frame);
}

void checkDownstreamTimeout(unsigned long nowMs) {
  if (!pendingTransaction.active ||
      nowMs - pendingTransaction.sentAtMs <=
        DOWNSTREAM_RESPONSE_TIMEOUT_MS) {
    return;
  }

  String timedOutTxid = pendingTransaction.txid;
  String timedOutVerb = pendingTransaction.verb;
  clearPendingTransaction();
  currentState = STATE_LOCKED;
  emitNack(timedOutTxid, timedOutVerb, "DOWNSTREAM_TIMEOUT");
}

void clearPendingTransaction() {
  pendingTransaction.active = false;
  pendingTransaction.txid = "";
  pendingTransaction.verb = "";
  pendingTransaction.sentAtMs = 0;
}

void reportCallbackDiagnostics() {
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

  if (overflow) emitHubDiagnostic("RADIO_QUEUE_OVERFLOW_DROP");
  if (unauthorized) emitHubDiagnostic("UNAUTHORIZED_PEER_IGNORED");
  if (invalid) emitHubDiagnostic("INVALID_RADIO_PAYLOAD_IGNORED");
  if (sendFailure) emitHubDiagnostic("ESP_NOW_LINK_SEND_FAILED");
}
