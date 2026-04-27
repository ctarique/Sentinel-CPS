from flask import Flask, render_template, request, jsonify
from datetime import datetime, timezone
import csv
import os
import socket
import uuid
import time
import re
import fcntl
import serial 

app = Flask(__name__)

# --- Configuration ---
BASE_DIR = os.path.expanduser("~/GitHub_Projects/sentinel-zero-trust-gateway/gateway")
LOG_PATH = os.path.join(BASE_DIR, "logs", "actions.csv")
DEVICE_ID = "esp32-D0WDQ6" 
SOURCE_HOST = socket.gethostname()

# --- Hardware Serial Setup ---
SERIAL_PORT = "/dev/ttyUSB0"
BAUD_RATE = 115200

try:
    # Open the port with a 1-second timeout
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

    # THE FIX: Explicitly disable the auto-reset signals
    ser.dtr = False
    ser.rts = False

    # Allow the hardware a moment to stabilize after the handshake
    time.sleep(2)

    # Clear any "boot junk" from the buffer so we start with a clean slate
    ser.reset_input_buffer()
    print(f"SUCCESS: Connected to ESP32 on {SERIAL_PORT}")
except Exception as e:
    print(f"CRITICAL: Hardware connection failed: {e}")
    ser = None

# Leave the HEADER and everything else below as it was
HEADER = ["timestamp_utc", "event_id", "session_id", "username", "source_host", "device_id", "action", "target", "value", "result", "latency_ms", "error"]

def init_log():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w", newline="") as f:
            csv.writer(f).writerow(HEADER)

def sanitize_input(text):
    if not text: return ""
    return re.sub(r'[^a-zA-Z0-9_\-]', '', str(text))[:50]

def log_event(session_id, username, action, target, value, result, latency_ms, error=""):
    init_log()
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    clean_session = sanitize_input(session_id)
    clean_user = sanitize_input(username)
    clean_value = sanitize_input(value)
    
    with open(LOG_PATH, "a", newline="") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            csv.writer(f).writerow([ts, uuid.uuid4().hex[:8], clean_session, clean_user, SOURCE_HOST, DEVICE_ID, action, target, clean_value, result, latency_ms, error])
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)

def send_command(cmd: str):
    if not ser:
        return "DISCONNECTED", 0, False, "Serial port not available"
    start = time.time()
    try:
        ser.reset_input_buffer()
        ser.write(f"{cmd}\n".encode('utf-8'))
        response = ser.readline().decode('utf-8').strip()
        latency = int((time.time() - start) * 1000)
        return (response, latency, True, "") if response else ("TIMEOUT", latency, False, "No response")
    except Exception as e:
        return ("ERROR", int((time.time() - start) * 1000), False, str(e))

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/control", methods=["POST"])
def control():
    data = request.json
    
    # We pull the 'target' from the request (e.g., "LED" or "CAR_01")
    # If the request doesn't specify, we default to "GATEWAY"
    target = data.get("target", "GATEWAY")
    
    # Execute the REAL hardware command
    response, latency, success, error_msg = send_command(data.get("value", ""))
    result = "SUCCESS" if success else "FAILED"

    # Log the interaction with the dynamic target
    log_event(
        data.get("session_id"), 
        data.get("username"), 
        data.get("action"), 
        target, 
        data.get("value"), 
        result, 
        latency, 
        error_msg
    )

    return jsonify({
        "status": result, 
        "latency_ms": latency, 
        "response": response, 
        "error": error_msg
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)