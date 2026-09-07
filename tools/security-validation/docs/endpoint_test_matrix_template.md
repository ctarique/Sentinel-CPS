# Sentinel-CPS Endpoint Test Matrix Template

**Validation date:** YYYY-MM-DD  
**Gateway host/IP:** [PRIVATE / REDACTED IN PUBLIC COPY]  
**Tester:** [PRIVATE / REDACTED IN PUBLIC COPY]

| Endpoint Role | Source Device Label | Expected Port 22 (SSH) | Expected Port 8080 (Gateway UI/API) | Actual Port 22 | Actual Port 8080 | Evidence Filename | Notes / Limitations |
|---|---|---:|---:|---:|---:|---|---|
| Admin Laptop / MacBook | | PASS | PASS | | | | |
| Windows Bastion Host | | PASS or N/A | PASS | | | | |
| Smart TV Display Node | | N/A or FAIL | PASS | | | | |
| Unapproved Client | | FAIL | FAIL or limited | | | | |
| Raspberry Pi Localhost | | PASS | PASS | | | | |

## Result labels

Use these labels consistently:

- `PASS`: observed behavior matched expectation.
- `FAIL`: observed behavior did not match expectation.
- `INCONCLUSIVE`: test could not determine behavior.
- `N/A`: endpoint cannot perform the test or test is not applicable.
