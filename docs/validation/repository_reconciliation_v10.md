# Sentinel-CPS v10.0 Repository Reconciliation

## Scope

This reconciliation organized the existing GitHub repository and reviewed
selected material from the ignored `_import_onedrive_v10/` staging folder.
The staging folder was treated as untrusted raw source material and remains
ignored by git. No new Gateway, ESP32, eBPF, or AI functionality was
implemented.

## Created Folders and Placeholders

The following implementation and evidence folders were created with
`.gitkeep` placeholders where they would otherwise be empty:

* `gateway/templates/`
* `gateway/static/`
* `gateway/sentinel/`
* `gateway/tests/`
* `firmware/hub/`
* `firmware/vehicle/`
* `host/systemd/`
* `host/nftables/`
* `host/udev/`
* `overwatch/ebpf/`
* `overwatch/inference/`
* `docs/evidence/lab_screenshots/`

The following populated organizational folders were also created:

* `docs/formal/`
* `docs/architecture/`
* `docs/network/`
* `docs/validation/`
* `docs/research_logs/`
* `lane-subsystem/`

## Safely Imported From Staging

The following current v10.0 PDFs were inspected for obvious credentials,
addresses, hostnames, local paths, and operational network inventory, then
copied into `docs/formal/`:

* `Sentinel-CPS_Functional_Requirements_Document_v10.0.pdf`
* `Sentinel-CPS_Thesis_Scope_Statement_v10.0.pdf`
* `Sentinel-CPS_Thesis_Synopsis_v10.0.pdf`

The formal PDFs contain ordinary thesis author/advisor and document-generation
metadata. No credentials, private keys, live IP addresses, MAC addresses, or
access secrets were found during the available inspection. Two other current
v10.0 formal PDFs were not imported because the corresponding source document
text includes the operational hostname `iot-pi.local`; those are listed for
manual review.

`Lane Subsystem/Light Sensor Test Lane.pptx` was copied to
`lane-subsystem/Light Sensor Test Lane.pptx`. It is a one-slide lane artifact
with no notes, hidden slides, hyperlinks, network details, or embedded media.
It contains ordinary author and PowerPoint application metadata.

## Existing Repository Material Organized

Existing tracked files were preserved and moved into the v10.0 documentation
layout:

* `docs/Unified_Zero-Trust_CPS_Blueprint_v9.0.png` moved to
  `docs/architecture/`
* `docs/system_architecture.md` moved to
  `docs/architecture/system_architecture_v9.md`
* `docs/CONNECTIVITY_GUIDE.md` moved to `docs/network/`
* `docs/firewall_setup_sanitized.md` moved to `docs/network/`
* `docs/network_architecture.md` moved to
  `docs/network/network_architecture_v9.md`
* `docs/RESEARCH_JOURNAL.md` moved to `docs/research_logs/`

The existing `firmware/esp32_serial_protocol.md`, `gateway/data/.gitkeep`, and
`logs/.gitkeep` were retained.

## Intentionally Not Imported

The following staging material was intentionally left only in
`_import_onedrive_v10/`:

* All `.DS_Store` files
* All DOCX files, because they may contain hidden metadata, comments, or
  revision history and equivalent shareable PDFs are available where needed
* All archived formal documents, because the current v10.0 PDFs supersede them
* `Architecture and Diagrams/Archive/Unified_Zero-Trust_CPS_Blueprint_v9.0.png`,
  because it is byte-for-byte identical to the existing repository copy
* `Architecture and Diagrams/Archive/CPS_Simulation_Operational_Flow.jpeg`,
  because it contains iPhone and GPS EXIF metadata
* `Code/Archive/esp32_serial_protocol.md`, because the existing repository
  protocol note is more complete
* `Formal Thesis Documents/Sentinel-CPS_Security_Requirements_Document_v10.0.pdf`,
  because the corresponding source text includes `iot-pi.local`
* `Formal Thesis Documents/Sentinel-CPS_System_Architecture_Document_v10.0.pdf`,
  because the corresponding source text includes `iot-pi.local`
* All staged Research Logs material, including `RESEARCH_JOURNAL.md`, the
  current development update PDF/DOCX, and older development-update DOCX files
* The intentionally absent `Lab Screenshots` and `Security and Network`
  high-risk source folders

## Manual Sanitization Review Required

The following staged files may be useful later but were not imported:

* `Code/app.py`: contains a hard-coded local repository path, records the
  runtime hostname, writes operational log fields, and runs on legacy port
  `5000` rather than the v10.0 port `8080`
* `Code/dashboard.html`: references a local log path and legacy port `5000`,
  and it does not match the staged JSON `/control` route
* `Architecture and Diagrams/network_architecture.md`: otherwise useful v10.0
  content, but it names the operational mDNS hostname `iot-pi.local`
* `Architecture and Diagrams/sentinel_cps_blueprint_v10.svg`
* `Architecture and Diagrams/sentinel_cps_blueprint_v10.png`
* `Architecture and Diagrams/sentinel_cps_blueprint_v10.html`
* `Formal Thesis Documents/Sentinel-CPS_Security_Requirements_Document_v10.0.pdf`
* `Formal Thesis Documents/Sentinel-CPS_System_Architecture_Document_v10.0.pdf`

The three v10.0 blueprint formats visually or textually include
`iot-pi.local`. They should be regenerated with a placeholder hostname before
public import. The two held formal PDFs should also be regenerated or redacted
with placeholder hostnames before import.

The preserved existing files below should also receive a later content review
because they describe legacy operational history, institution-specific access
concepts, or port `5000`:

* `docs/research_logs/RESEARCH_JOURNAL.md`
* `docs/network/CONNECTIVITY_GUIDE.md`
* `docs/network/firewall_setup_sanitized.md`
* `docs/network/network_architecture_v9.md`
* `docs/architecture/system_architecture_v9.md`

They were retained to avoid removing useful existing repository history.

## Duplicates and Conflicts

* The staged archived v9.0 blueprint PNG is identical to the existing tracked
  v9.0 blueprint PNG.
* The existing serial protocol note is more complete than the staged archived
  copy because it includes an additional baud-rate note.
* The staged Gateway prototype and dashboard use port `5000`, while the v10.0
  architecture requires TCP port `8080`.
* The staged dashboard submits a traditional HTML form, while the staged
  Gateway prototype expects JSON at `/control`; they are not a directly
  compatible pair.
* Existing legacy network and system architecture notes describe earlier
  design decisions and were renamed or categorized as v9/history rather than
  treated as current v10.0 guidance.

## Assumptions

* Author and advisor names in formal thesis PDFs are intended public academic
  metadata.
* The lane-subsystem PowerPoint is a shareable project artifact despite
  containing ordinary author metadata.
* Existing tracked history should be preserved and organized, even when a
  later sanitization review is recommended.
* Empty implementation folders should contain placeholders only; no fake
  implementation or dependency files were created.

## Recommended Next Codex Task

Perform **Gateway MVP refinement**:

1. Review and sanitize the staged Flask prototype without copying local paths,
   runtime host identifiers, or operational defaults.
2. Define configuration through safe environment variables and repository-local
   paths.
3. Align the application and template contract with TCP port `8080`.
4. Add focused tests for input validation, command handling, logging behavior,
   and disconnected serial operation before hardware integration.
