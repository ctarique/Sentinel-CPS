from flask import Flask, render_template, jsonify
import threading
import time
import csv
import fcntl
import os

app = Flask(__name__)

# ==========================================
# THESIS CONSTRAINT: CONCURRENCY PROTECTION
# ==========================================
serial_lock = threading.Lock()

# Simulated in-memory Digital Twin state
vehicle_state = {
    "status": "AWAITING_TELEMETRY",
    "adc_left": 0,
    "adc_right": 0,
    "pid_error": 0.0
}

# THESIS CONSTRAINT: HIGH-IOPS LOGGING
# In the lab, this file will be written to the mounted USB 3.0 drive
TELEMETRY_LOG_PATH = "telemetry.csv"

def background_telemetry_listener():
    """
    Asynchronous listener reading from the tethered Hub via /dev/ttyUSB0.
    Updates the Digital Twin state and performs thread-safe logging.
    """
    try:
        import serial
        # 115200 baud matches the Hub's C++ Serial.begin()
        ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=1)
        print("[OVERWATCH] Serial bridge connected successfully.")
    except Exception as e:
        print(f"[WARNING] Hardware not found. Bypassing serial for local dev: {e}")
        ser = None

    while True:
        if ser and ser.in_waiting > 0:
            try:
                # 1. Read the raw ASCII string from the Hub
                raw_data = ser.readline().decode('utf-8').strip()
                
                # Format expected: TELEMETRY,ID,ADC_L,ADC_R,PID_ERR,STATUS
                if raw_data.startswith("TELEMETRY"):
                    parts = raw_data.split(',')
                    if len(parts) == 6:
                        
                        # 2. Concurrency Protection: Update Shared State
                        with serial_lock:
                            vehicle_state["status"] = parts[5]
                            vehicle_state["adc_left"] = int(parts[2])
                            vehicle_state["adc_right"] = int(parts[3])
                            vehicle_state["pid_error"] = float(parts[4])
                        
                        # 3. High-IOPS Thread-Safe Logging (eBPF/AI Dataset Prep)
                        with open(TELEMETRY_LOG_PATH, 'a', newline='') as f:
                            # Apply an exclusive lock to the file before writing
                            fcntl.flock(f, fcntl.LOCK_EX)
                            
                            csv_writer = csv.writer(f)
                            # Prepend a timestamp to the telemetry array
                            csv_writer.writerow([time.time()] + parts[1:])
                            
                            # Release the lock immediately after writing
                            fcntl.flock(f, fcntl.LOCK_UN)
                            
            except Exception as e:
                print(f"[ERROR] Serial parsing failed: {e}")
        
        # Micro-sleep to prevent the while-loop from pegging the CPU to 100%
        time.sleep(0.01)

@app.route('/')
def dashboard():
    """Serves the Digital Twin telemetry overlay."""
    return "<h1>Sentinel-CPS Dashboard</h1><p>Telemetry overlay will render here.</p>"

@app.route('/lane-builder')
def lane_builder():
    """Serves the dynamic physical track for the Smart TV."""
    return render_template('lane_builder.html')

@app.route('/api/telemetry', methods=['GET'])
def get_telemetry():
    """JSON endpoint for the web UI to fetch real-time edge vehicle states."""
    # The serial_lock ensures we don't read the dictionary while the listener is writing to it
    with serial_lock:
        return jsonify(vehicle_state)

if __name__ == '__main__':
    # Start the background listener thread as a daemon BEFORE starting Flask
    listener_thread = threading.Thread(target=background_telemetry_listener, daemon=True)
    listener_thread.start()
    
    # Binds exclusively to Port 8080 as defined by the HLAC firewall rules
    app.run(host='0.0.0.0', port=8080, debug=True)