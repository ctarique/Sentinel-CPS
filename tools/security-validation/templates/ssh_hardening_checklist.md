# SSH Hardening Checklist

Use this checklist with the collected `sshd_config_effective.txt`, `ssh_status.txt`, and endpoint probe evidence.

## Configuration review

- [ ] `PasswordAuthentication no` is actively enforced in the effective SSH configuration.
- [ ] `PubkeyAuthentication yes` is enabled.
- [ ] Root login is disabled or restricted, such as `PermitRootLogin no` or `prohibit-password`.
- [ ] Only expected admin keys are present in `authorized_keys` metadata.
- [ ] No private keys such as `id_ed25519`, `id_rsa`, `.pem`, or `.key` are stored in the project repository.
- [ ] SSH service is running only where expected.
- [ ] SSH service status was captured with `systemctl status ssh` or `systemctl status sshd`.

## Endpoint behavior review

- [ ] Approved admin endpoint can reach Port 22 when expected.
- [ ] Approved admin endpoint can authenticate using an Ed25519 key when expected.
- [ ] Unapproved endpoint cannot authenticate.
- [ ] Port 22 exposure is limited by network/firewall posture where applicable.
- [ ] Smart TV/display endpoint does not require SSH/admin access.

## Notes

Document any exception honestly. For example, if Port 22 is visible from a broader network segment during early testing, record it as a limitation and do not claim VAL-01 is complete until the configuration is corrected or bounded in the thesis.
