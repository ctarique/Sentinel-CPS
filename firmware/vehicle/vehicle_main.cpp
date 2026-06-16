#include <Arduino.h>
#include "../telemetry_schema.h" // Import our strict data contract

// ==========================================
// HARDWARE PIN DEFINITIONS
// ==========================================
const int ADC_LEFT_PIN = 34;  // Downward left phototransistor
const int ADC_RIGHT_PIN = 35; // Downward right phototransistor

// Motor A (Left) and Motor B (Right) PWM pins
const int MOTOR_A_FWD = 25;
const int MOTOR_B_FWD = 26;

// ==========================================
// THESIS CONSTRAINT: ONBOARD PID CONTROL
// ==========================================
// PID Constants (To be tuned on the physical Smart TV glass)
float Kp = 0.5; // Proportional: Reacts to current error
float Ki = 0.0; // Integral: Reacts to accumulated past error
float Kd = 0.1; // Derivative: Reacts to the rate of error change

float previous_error = 0.0;
float integral = 0.0;

// Global state instance from our schema
struct_telemetry current_state;

void setup() {
    Serial.begin(115200);
    
    // Initialize ADC pins for analog luminance reading
    pinMode(ADC_LEFT_PIN, INPUT);
    pinMode(ADC_RIGHT_PIN, INPUT);
    
    // Initialize motor driver pins
    pinMode(MOTOR_A_FWD, OUTPUT);
    pinMode(MOTOR_B_FWD, OUTPUT);

    current_state.vehicle_id = 0x01; // Assigning Vehicle 1
    current_state.status_flag = 1;   // ACTIVE
}

// ==========================================
// THESIS CONSTRAINT: SAFE PHYSICAL FAILURE STATE
// ==========================================
void emergency_stop() {
    analogWrite(MOTOR_A_FWD, 0);
    analogWrite(MOTOR_B_FWD, 0);
    current_state.status_flag = 0; // NEUTRAL/STOP
    Serial.println("CRITICAL: EMERGENCY STOP EXECUTED.");
}

void loop() {
    // 1. Read Analog Luminance (The TV pixels)
    current_state.adc_left = analogRead(ADC_LEFT_PIN);
    current_state.adc_right = analogRead(ADC_RIGHT_PIN);

    // 2. Calculate the Error, e(t)
    // If left > right, error is positive (drifting right).
    // If right > left, error is negative (drifting left).
    float error = (float)current_state.adc_left - (float)current_state.adc_right;
    current_state.pid_error = error;

    // 3. The PID Mathematics
    integral += error;
    float derivative = error - previous_error;
    
    // u(t) = Kp*e(t) + Ki*integral + Kd*derivative
    float steering_adjustment = (Kp * error) + (Ki * integral) + (Kd * derivative);
    
    previous_error = error;

    // 4. Apply to Motor PWM (Base speed +/- adjustment)
    int base_speed = 150; // out of 255
    int left_motor_speed = constrain(base_speed - steering_adjustment, 0, 255);
    int right_motor_speed = constrain(base_speed + steering_adjustment, 0, 255);

    if (current_state.status_flag == 1) {
        analogWrite(MOTOR_A_FWD, left_motor_speed);
        analogWrite(MOTOR_B_FWD, right_motor_speed);
    } else {
        emergency_stop();
    }

    // Delay to stabilize the control loop sample rate
    delay(20); 
}
