# Sentinel Gateway: Connectivity Guide

## Connection Strings

### MacOS (Mobile Workstation)
To initiate a management session from the MacBook Pro:
```bash
ssh -i ~/.ssh/<ADMIN_PRIVATE_KEY> <ADMIN_USER>@<GATEWAY_HOSTNAME>
```

### Windows (Lab Terminal / Bastion Host)
To initiate a management session from the fixed terminal:
```bash
ssh -i "C:\Users\<LOCAL_USER>\.ssh\<ADMIN_PRIVATE_KEY>" <ADMIN_USER>@<GATEWAY_HOSTNAME>
```
