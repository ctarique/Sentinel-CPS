# Sentinel Gateway: Connectivity Guide

## Connection Strings

### MacOS (Mobile Workstation)
To initiate a management session from the MacBook Pro:
```bash
ssh -i ~/.ssh/sentinel_mac_admin iotadmin@iot-pi.local
```

### Windows (Lab Terminal / Bastion Host)
To initiate a management session from the fixed terminal:
```bash
ssh -i "C:\Users\<LOCAL_USER>\.ssh\sentinel_admin" iotadmin@iot-pi.local
```